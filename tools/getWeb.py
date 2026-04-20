from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient


# ============================================================================
# HTTP Utility
# ============================================================================


def _http_get_with_retry(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
    max_retries: int = 3,
) -> requests.Response:
    proxies = {
        k: v
        for k, v in {
            "http": os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY"),
            "https": os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"),
        }.items()
        if v
    } or None

    if headers is None:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }

    last_exc: Optional[Exception] = None
    last_status: Optional[int] = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, proxies=proxies)
            last_status = resp.status_code
            if resp.status_code >= 500 or resp.status_code == 429:
                last_exc = RuntimeError(f"status={resp.status_code}")
                time.sleep(1 + attempt)
                continue
            return resp
        except Exception as exc:
            last_exc = exc
            time.sleep(1 + attempt)
            continue

    raise RuntimeError(
        f"GET {url} failed after {max_retries} attempts, "
        f"last_status={last_status}, error={last_exc}"
    )


# ============================================================================
# Text Processing Utilities
# ============================================================================


def _strip_code_fence(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"```(?:\w+)?\s*([\s\S]*?)\s*```", text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _extract_json_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    s = _strip_code_fence(text)
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[start : i + 1]
    return None


# ============================================================================
# NVD Parsers
# ============================================================================


def _classify_reference_type(url: str) -> str:
    domain = urllib.parse.urlparse(url).netloc.lower()
    if "github.com" in domain:
        return "github"
    elif any(site in domain for site in ["securityfocus.com", "seclists.org", "packetstormsecurity.com"]):
        return "security_advisory"
    elif any(site in domain for site in [".com", ".org", ".net"]):
        return "vendor"
    else:
        return "other"


def _extract_nvd_description(soup) -> str:
    desc_elements = soup.find_all(["p", "div"], attrs={
        "data-testid": lambda x: x and "vuln-description" in x.lower()
    })
    for element in desc_elements:
        text = element.get_text(strip=True)
        if text and len(text) > 10:
            return text
    for element in soup.find_all(["p", "div"]):
        text = element.get_text(strip=True)
        if text and len(text) > 100:
            if any(keyword in text.lower() for keyword in ["vulnerability", "allows", "could", "attack"]):
                return text
    return "未找到描述信息"


def _extract_nvd_references(soup) -> List[Dict[str, str]]:
    references = []
    ref_tables = soup.find_all("table", {"data-testid": lambda x: x and "hyperlink" in x.lower()})
    for table in ref_tables:
        rows = table.find_all("tr")
        for row in rows[1:]:
            link_element = row.find("a")
            if link_element and link_element.get("href"):
                link_text = link_element.get_text(strip=True)
                link_url = link_element.get("href")
                references.append({
                    "text": link_text,
                    "url": link_url,
                    "type": _classify_reference_type(link_url),
                })
    if not references:
        for link in soup.find_all("a", href=True):
            url = link.get("href")
            text = link.get_text(strip=True)
            if url and not url.startswith("#") and "nvd.nist.gov" not in url:
                if any(ext in url.lower() for ext in [".com", ".org", ".net", "http", "https"]):
                    references.append({
                        "text": text,
                        "url": url,
                        "type": _classify_reference_type(url),
                    })
    unique_refs = []
    seen_urls = set()
    for ref in references:
        if ref["url"] not in seen_urls:
            seen_urls.add(ref["url"])
            unique_refs.append(ref)
    return unique_refs[:20]


def _extract_reference_description(soup, url: str) -> str:
    description_parts = []
    domain = urllib.parse.urlparse(url).netloc.lower()
    if any(site in domain for site in ["securityfocus.com", "seclists.org", "packetstormsecurity.com"]):
        for elem in soup.find_all(["pre", "div", "article"]):
            text = elem.get_text(strip=True)
            if text and len(text) > 200 and "vulnerability" in text.lower():
                description_parts.append(text[:1000])
                break
    elif any(site in domain for site in [".com", ".org", ".net"]):
        for tag in ["article", "main", "div.content", "div.post-content", "div.entry-content"]:
            elements = soup.find_all(tag)
            for elem in elements:
                text = elem.get_text(strip=True)
                if text and len(text) > 300:
                    description_parts.append(text)
                    break
            if description_parts:
                break
    if not description_parts:
        paragraphs = soup.find_all("p")
        for p in paragraphs[:6]:
            text = p.get_text(strip=True)
            if text and len(text) > 30:
                description_parts.append(text)
    if not description_parts:
        all_text = soup.get_text()
        cleaned_text = re.sub(r"\s+", " ", all_text)
        if len(cleaned_text) > 200:
            description_parts.append(cleaned_text[:1000])
    return "\n\n".join(description_parts) if description_parts else "未能提取到描述信息"


def _extract_reference_code_blocks(soup) -> List[str]:
    code_blocks = []
    for pre in soup.find_all("pre"):
        code_text = pre.get_text(strip=False)
        if code_text and len(code_text) > 10:
            code_blocks.append(code_text)
    for code in soup.find_all("code"):
        code_text = code.get_text(strip=False)
        if code_text and len(code_text) > 50:
            code_blocks.append(code_text)
    return code_blocks


# ============================================================================
# GitHub Parsers
# ============================================================================


def _parse_github_markdown_content(md_content: str, url: str) -> Dict[str, Any]:
    content_info: Dict[str, Any] = {"description": "", "code_blocks": []}
    lines = md_content.split("\n")
    in_code_block = False
    current_code_block: List[str] = []
    for line in lines:
        line = line.rstrip()
        if line.strip().startswith("```"):
            if in_code_block:
                if current_code_block:
                    content_info["code_blocks"].append("\n".join(current_code_block))
                    current_code_block = []
                in_code_block = False
            else:
                in_code_block = True
            continue
        if in_code_block:
            current_code_block.append(line)
            continue
        if line.strip() and not line.startswith("#"):
            if len(content_info["description"]) < 1000:
                content_info["description"] += line + "\n"
    if current_code_block:
        content_info["code_blocks"].append("\n".join(current_code_block))
    content_info["description"] = content_info["description"].strip()
    return content_info


def _extract_from_github_page(github_url: str) -> Dict[str, Any]:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        resp = _http_get_with_retry(github_url, headers=headers, timeout=10, max_retries=3)
        if resp.status_code != 200:
            return {"description": f"访问GitHub页面失败，状态码: {resp.status_code}", "code_blocks": []}
        soup = BeautifulSoup(resp.content, "html.parser")
        content_info: Dict[str, Any] = {"description": "", "code_blocks": []}
        md_content_div = soup.find("div", {"class": "markdown-body"})
        if md_content_div:
            for pre in md_content_div.find_all("pre"):
                code_text = pre.get_text(strip=False)
                if code_text:
                    content_info["code_blocks"].append(code_text)
            for element in md_content_div.find_all(["p", "div"]):
                if element.find_parent("pre"):
                    continue
                text = element.get_text(strip=True)
                if text and len(text) > 20:
                    content_info["description"] += text + "\n"
        if not content_info["description"]:
            article = soup.find("article")
            if article:
                for pre in article.find_all("pre"):
                    code_text = pre.get_text(strip=False)
                    if code_text:
                        content_info["code_blocks"].append(code_text)
                for element in article.find_all(["p", "div"]):
                    if element.find_parent("pre"):
                        continue
                    text = element.get_text(strip=True)
                    if text and len(text) > 20:
                        content_info["description"] += text + "\n"
        content_info["description"] = content_info["description"].strip()[:1000]
        return content_info
    except Exception as e:
        return {"description": f"解析GitHub页面失败: {e}", "code_blocks": []}


# ============================================================================
# Public CVE Collection Functions
# ============================================================================


def get_cve_info(cve_id: str) -> str:
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id, re.IGNORECASE):
        return json.dumps({
            "error": f"CVE编号格式不正确: {cve_id}",
            "correct_format": "CVE-YYYY-NNNNN",
        }, ensure_ascii=False)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}".strip()
    api_url = f"https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}".strip()

    try:
        try:
            api_resp = _http_get_with_retry(api_url, headers=headers, timeout=20, max_retries=3)
            data = api_resp.json()
            vulns = data.get("vulnerabilities") or []
            if vulns:
                cve_obj = vulns[0].get("cve", {})
                descriptions = cve_obj.get("descriptions") or []
                description = ""
                for d in descriptions:
                    if d.get("lang") == "en" and d.get("value"):
                        description = d["value"]
                        break
                if not description and descriptions:
                    description = descriptions[0].get("value", "")
                references = []
                for ref in cve_obj.get("references") or []:
                    ref_url = ref.get("url")
                    if not ref_url:
                        continue
                    ref_text = ref.get("source") or ref_url
                    references.append({
                        "text": ref_text,
                        "url": ref_url,
                        "type": _classify_reference_type(ref_url),
                    })
                if description or references:
                    return json.dumps({
                        "cve_id": cve_id,
                        "description": description or "",
                        "references": references,
                        "success": True,
                        "source": "nvd_api",
                    }, ensure_ascii=False)
        except Exception:
            pass

        page_resp = _http_get_with_retry(detail_url, headers=headers, timeout=20, max_retries=3)
        if page_resp.status_code == 404:
            return json.dumps({"error": f"CVE {cve_id} 不存在或在NVD库中未找到"})
        if page_resp.status_code != 200:
            return json.dumps({"error": f"NVD库请求失败，状态码: {page_resp.status_code}"})

        soup = BeautifulSoup(page_resp.content, "html.parser")
        description = _extract_nvd_description(soup)
        references = _extract_nvd_references(soup)
        return json.dumps({
            "cve_id": cve_id,
            "description": description,
            "references": references,
            "success": True,
            "source": "nvd_html",
        }, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"error": f"请求错误: {e}"}, ensure_ascii=False)


def crawl_reference(reference_url: str) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    }
    try:
        if "github.com" in reference_url:
            return crawl_github(reference_url)
        time.sleep(1)
        resp = _http_get_with_retry(reference_url, headers=headers, timeout=15, max_retries=3)
        if resp.status_code != 200:
            return json.dumps({
                "success": False,
                "error": f"HTTP请求失败，状态码: {resp.status_code}",
                "url": reference_url,
            }, ensure_ascii=False)

        soup = BeautifulSoup(resp.content, "html.parser")
        title_tag = soup.find("title")
        page_title = title_tag.get_text(strip=True) if title_tag else "无标题"
        description = _extract_reference_description(soup, reference_url)
        code_blocks = _extract_reference_code_blocks(soup)
        return json.dumps({
            "success": True,
            "url": reference_url,
            "title": page_title,
            "description": description,
            "code_blocks": code_blocks,
            "content_type": "web_page",
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"爬取参考链接时出错: {e}",
            "url": reference_url,
        }, ensure_ascii=False)


def crawl_github(github_url: str) -> str:
    if not github_url or "github.com" not in github_url:
        return json.dumps({"success": False, "error": "不是有效的GitHub链接"}, ensure_ascii=False)

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        raw_url = github_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = None
        try:
            response = _http_get_with_retry(raw_url, headers=headers, timeout=10, max_retries=3)
        except Exception:
            response = None

        if response is not None and response.status_code == 200:
            result = _parse_github_markdown_content(response.text, github_url)
        else:
            result = _extract_from_github_page(github_url)

        result["success"] = True
        result["url"] = github_url
        result["content_type"] = "github"
        return json.dumps(result, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"爬取GitHub链接时出错: {e}",
            "url": github_url,
        }, ensure_ascii=False)


# ============================================================================
# Main Entry Point
# ============================================================================


def get_web_infomation(cve_str: str) -> None:
    """Collect CVE information from NVD and references, then consolidate with LLM.

    1. Query NVD API (fallback to HTML) for description + references
    2. Crawl up to 5 reference links for additional details
    3. Use LLM to consolidate into {info, reason, webpoc} JSON
    4. Save to output/searchResult/
    """
    collected: Dict[str, Any] = {"descriptions": [], "code_blocks": []}

    # Step 1: NVD data
    try:
        resp = get_cve_info(cve_str)
        data = {}
        try:
            data = json.loads(resp)
        except Exception:
            data = {}

        if isinstance(data, dict):
            desc = data.get("description") or ""
            if desc:
                collected["descriptions"].append(desc)
            refs = data.get("references") or []
        else:
            refs = []

        # Step 2: Crawl references (limit to 5 to avoid excessive requests)
        for r in refs[:5]:
            try:
                url = r.get("url") if isinstance(r, dict) else r
                if not url:
                    continue
                if "github.com" in url:
                    out = crawl_github(url)
                else:
                    out = crawl_reference(url)
                try:
                    j = json.loads(out)
                except Exception:
                    j = {}
                if isinstance(j, dict) and j.get("success"):
                    d = j.get("description") or ""
                    if d:
                        collected["descriptions"].append(d)
                    for cb in j.get("code_blocks") or []:
                        if cb and isinstance(cb, str):
                            collected["code_blocks"].append(cb)
            except Exception:
                continue
    except Exception:
        pass

    # Step 3: LLM consolidation
    consolidated: Dict[str, Any] = {"info": "", "reason": "", "webpoc": ""}
    try:
        client = LLMClient()
        try:
            prompt_parts = [
                "You are given collected vulnerability information fragments. Consolidate them into a JSON object with exactly three keys: info, reason, webpoc.",
                "Return ONLY the JSON object, no explanation. If a field is empty, use an empty string.",
            ]
            descs = collected.get("descriptions") or []
            if descs:
                prompt_parts.append("Collected descriptions:\n" + "\n\n---\n\n".join(descs[:8]))
            cbs = collected.get("code_blocks") or []
            if cbs:
                brief_cbs = [cb[:4000] if len(cb) > 4000 else cb for cb in cbs[:6]]
                prompt_parts.append("Collected code blocks:\n" + "\n\n---\n\n".join(brief_cbs))
            prompt = "\n\n".join(prompt_parts)
            reply = client.chat([ChatMessage(role="user", content=prompt)], temperature=0, max_tokens=800)
            json_candidate = _extract_json_from_text(reply)
            if json_candidate:
                parsed = json.loads(json_candidate)
                if isinstance(parsed, dict):
                    consolidated = {
                        "info": parsed.get("info") or "",
                        "reason": parsed.get("reason") or "",
                        "webpoc": parsed.get("webpoc") or "",
                    }
        finally:
            client.close()
    except Exception:
        pass

    # Fallback: if LLM consolidation failed, build from raw collected data
    if not consolidated["info"] and (collected.get("descriptions") or []):
        consolidated["info"] = "\n\n".join(collected.get("descriptions")[:10])[:4000]
    if not consolidated["webpoc"] and (collected.get("code_blocks") or []):
        found = ""
        for cb in collected.get("code_blocks"):
            if re.search(r"^(GET|POST)\s+.*HTTP/\d\.\d", cb, flags=re.I | re.M):
                found = cb
                break
        if not found and collected.get("code_blocks"):
            found = collected.get("code_blocks")[0]
        consolidated["webpoc"] = (found or "").strip()

    # Step 4: Save
    ts = time.strftime("%Y%m%d_%H%M")
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output", "searchResult"))
    os.makedirs(out_dir, exist_ok=True)
    fname = f"{ts}_{cve_str}_info.json"
    fpath = os.path.join(out_dir, fname)
    with open(fpath, "w", encoding="utf-8") as fh:
        json.dump(consolidated, fh, ensure_ascii=False, indent=2)
    print(f"Saved CVE info to: {fpath}")
