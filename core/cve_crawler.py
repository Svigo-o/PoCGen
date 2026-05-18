from __future__ import annotations

import json
import os
import re
import time

from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

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
# Text / JSON Utilities
# ============================================================================


def _strip_code_fence(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"```(?:\w+)?\s*([\s\S]*?)\s*```", text)
    return m.group(1).strip() if m else text.strip()


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


def _dedup(lst: List[str]) -> List[str]:
    seen: set = set()
    return [x for x in lst if x not in seen and not seen.add(x)]


# ============================================================================
# fkie-cad NVD Mirror
# ============================================================================


def _build_mirror_url(cve_id: str) -> str:
    parts = cve_id.upper().split("-")
    if len(parts) != 3:
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    year, seq = parts[1], parts[2]
    group = f"{seq[:2]}xx"
    return (
        f"https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main"
        f"/CVE-{year}/CVE-{year}-{group}/CVE-{year}-{seq}.json"
    )


def _extract_best_cvss(metrics: dict) -> dict:
    """Extract the best CVSS record: prefer v3.1 Primary > v3.1 > v3.x."""
    best: Dict[str, Any] = {}
    priority = 0
    for metric_set in metrics.values():
        if not isinstance(metric_set, list):
            continue
        for m in metric_set:
            cd = m.get("cvssData") or {}
            ver = cd.get("version", "")
            is_primary = m.get("type") == "Primary"
            if ver == "3.1" and is_primary and priority < 3:
                best = {
                    "version": ver,
                    "vectorString": cd.get("vectorString", ""),
                    "baseScore": cd.get("baseScore"),
                    "baseSeverity": cd.get("baseSeverity", ""),
                }
                priority = 3
            elif ver == "3.1" and priority < 2:
                best = {
                    "version": ver,
                    "vectorString": cd.get("vectorString", ""),
                    "baseScore": cd.get("baseScore"),
                    "baseSeverity": cd.get("baseSeverity", ""),
                }
                priority = 2
            elif ver.startswith("3") and priority < 1:
                best = {
                    "version": ver,
                    "vectorString": cd.get("vectorString", ""),
                    "baseScore": cd.get("baseScore"),
                    "baseSeverity": cd.get("baseSeverity", ""),
                }
                priority = 1
    return best


def _parse_cve_data(data: dict) -> dict:
    """Extract structured info from NVD-format CVE JSON (mirror or API)."""
    cve_id = data.get("id", "")

    description = ""
    for d in data.get("descriptions") or []:
        if d.get("lang") == "en" and d.get("value"):
            description = d["value"]
            break
    if not description:
        descs = data.get("descriptions") or []
        if descs:
            description = descs[0].get("value", "")

    cwe_list = _dedup([
        desc["value"]
        for w in data.get("weaknesses") or []
        for desc in w.get("description") or []
        if desc.get("value", "").startswith("CWE-")
    ])

    references: List[Dict[str, Any]] = []
    for ref in data.get("references") or []:
        url = ref.get("url")
        if url:
            references.append({
                "url": url,
                "source": ref.get("source", ""),
                "tags": ref.get("tags", []),
            })

    affected = _dedup([
        cpe["criteria"]
        for cfg in data.get("configurations") or []
        for node in cfg.get("nodes", [])
        for cpe in node.get("cpeMatch", [])
        if cpe.get("vulnerable") and cpe.get("criteria")
    ])

    return {
        "cve_id": cve_id,
        "description": description,
        "cwe": cwe_list,
        "cvss": _extract_best_cvss(data.get("metrics", {})),
        "affected": affected,
        "references": references,
    }


# ============================================================================
# Reference Crawlers
# ============================================================================


def _extract_page_text(soup) -> tuple[str, List[str]]:
    """Extract description text and code blocks from a parsed HTML page."""
    desc_parts: List[str] = []
    code_blocks: List[str] = []

    for pre in soup.find_all("pre"):
        text = pre.get_text(strip=False)
        if text and len(text) > 10:
            code_blocks.append(text)

    for tag in ("article", "main", "div.content", "div.post-content", "div.entry-content", "div.markdown-body"):
        for elem in soup.find_all(tag):
            for child in elem.find_all(["p", "div"]):
                if child.find_parent("pre"):
                    continue
                text = child.get_text(strip=True)
                if text and len(text) > 20:
                    desc_parts.append(text)
            if desc_parts:
                break
        if desc_parts:
            break

    if not desc_parts:
        for p in soup.find_all("p")[:10]:
            text = p.get_text(strip=True)
            if text and len(text) > 30:
                desc_parts.append(text)

    description = "\n\n".join(desc_parts)[:2000] if desc_parts else ""
    return description, code_blocks


def crawl_github(github_url: str) -> Dict[str, Any]:
    if not github_url or "github.com" not in github_url:
        return {"success": False, "error": "Not a GitHub URL", "url": github_url}

    try:
        raw_url = github_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = None
        try:
            response = _http_get_with_retry(raw_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, max_retries=3)
        except Exception:
            response = None

        if response is not None and response.status_code == 200:
            text = response.text
            if text.strip().startswith("#") or "markdown" in (response.headers.get("Content-Type") or "").lower():
                result = _parse_markdown(text)
            else:
                result = {"description": text[:2000], "code_blocks": []}
        else:
            resp = _http_get_with_retry(github_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, max_retries=3)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}", "url": github_url}
            soup = BeautifulSoup(resp.content, "html.parser")
            desc, code_blocks = _extract_page_text(soup)
            result = {"description": desc, "code_blocks": code_blocks}

        result["success"] = True
        result["url"] = github_url
        return result
    except Exception as e:
        return {"success": False, "error": str(e), "url": github_url}


def _parse_markdown(md: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"description": "", "code_blocks": []}
    in_code = False
    code_buf: List[str] = []
    for line in md.split("\n"):
        line = line.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                if code_buf:
                    info["code_blocks"].append("\n".join(code_buf))
                    code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if line.strip() and not line.startswith("#") and len(info["description"]) < 2000:
            info["description"] += line + "\n"
    if code_buf:
        info["code_blocks"].append("\n".join(code_buf))
    info["description"] = info["description"].strip()
    return info


def crawl_reference(url: str) -> Dict[str, Any]:
    if "github.com" in url:
        return crawl_github(url)

    try:
        time.sleep(1)
        resp = _http_get_with_retry(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, max_retries=3)
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code}", "url": url}
        soup = BeautifulSoup(resp.content, "html.parser")
        desc, code_blocks = _extract_page_text(soup)
        return {"success": True, "url": url, "description": desc, "code_blocks": code_blocks}
    except Exception as e:
        return {"success": False, "error": str(e), "url": url}


# ============================================================================
# Main Entry Point
# ============================================================================


def get_web_infomation(cve_str: str, force: bool = False) -> Optional[dict]:
    """Collect CVE info from fkie-cad mirror + reference crawling, then consolidate.

    1. Fetch CVE JSON from fkie-cad mirror (fallback to NVD API)
    2. Crawl reference links (prioritise "Exploit" tagged)
    3. Consolidate via LLM into {info, reason, webpoc}
    4. Save to output/cve_cache/{CVE-ID}.json

    If a result already exists and force=False, return the cached result.
    """
    cve_id = cve_str.upper().strip()
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
        print(f"Invalid CVE format: {cve_str}")
        return None

    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output", "cve_cache"))
    os.makedirs(out_dir, exist_ok=True)
    result_path = os.path.join(out_dir, f"{cve_id}.json")

    # Dedup
    if not force and os.path.isfile(result_path):
        print(f"[cache] Reusing existing result: {result_path}")
        with open(result_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    # ---------------------------------------------------------------
    # Step 1: Fetch CVE data (mirror -> NVD API)
    # ---------------------------------------------------------------
    parsed: Optional[dict] = None
    try:
        resp = _http_get_with_retry(_build_mirror_url(cve_id), headers={"User-Agent": "Mozilla/5.0"}, timeout=20, max_retries=3)
        if resp.status_code == 200:
            parsed = _parse_cve_data(resp.json())
            print("[mirror] Fetched from fkie-cad mirror")
    except Exception as exc:
        print(f"[mirror] Failed: {exc}, trying NVD API")

    if parsed is None:
        try:
            resp = _http_get_with_retry(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers={"User-Agent": "Mozilla/5.0"}, timeout=20, max_retries=3,
            )
            vulns = resp.json().get("vulnerabilities") or []
            if vulns:
                parsed = _parse_cve_data(vulns[0].get("cve", {}))
                parsed["cve_id"] = cve_id
                print("[nvd-api] Fetched from NVD API")
        except Exception as exc:
            print(f"[nvd-api] Failed: {exc}")

    if parsed is None:
        print(f"Failed to fetch CVE data for {cve_id}")
        return None

    collected: Dict[str, Any] = {
        "descriptions": [parsed["description"]] if parsed.get("description") else [],
        "code_blocks": [],
        "cwe": parsed.get("cwe", []),
        "cvss": parsed.get("cvss", {}),
        "affected": parsed.get("affected", []),
    }

    # ---------------------------------------------------------------
    # Step 2: Crawl references (Exploit-tagged first)
    # ---------------------------------------------------------------
    refs = parsed.get("references") or []
    exploit_first = sorted(refs, key=lambda r: 0 if "Exploit" in (r.get("tags") or []) else 1)

    for r in exploit_first[:8]:
        url = r.get("url")
        if not url:
            continue
        print(f"[crawl] {url}  (tags: {', '.join(r.get('tags') or []) or 'none'})")
        try:
            result = crawl_reference(url)
            if result.get("success"):
                if result.get("description"):
                    collected["descriptions"].append(result["description"])
                collected["code_blocks"].extend(cb for cb in result.get("code_blocks") or [] if cb)
            else:
                print(f"[crawl] Failed: {result.get('error', 'unknown')}")
        except Exception as exc:
            print(f"[crawl] Error: {exc}")

    # ---------------------------------------------------------------
    # Step 3: LLM consolidation
    # ---------------------------------------------------------------
    consolidated: Dict[str, Any] = {"info": "", "reason": "", "webpoc": ""}
    try:
        client = LLMClient()
        try:
            prompt_parts = [
                "Consolidate the following vulnerability information into a JSON object with exactly three keys: info, reason, webpoc.",
                "- info: concise vulnerability description (product, version, vuln type, attack vector, impact). Max 3 sentences.",
                "- reason: technical root cause (which function/parameter is vulnerable, how the attack works).",
                "- webpoc: raw HTTP PoC request if available; otherwise the exploit script. Empty string if none.",
                "Return ONLY the JSON object, no explanation.",
            ]
            if collected["cwe"]:
                prompt_parts.append(f"CWE: {', '.join(collected['cwe'])}")
            if collected["cvss"]:
                prompt_parts.append(
                    f"CVSS: {collected['cvss'].get('vectorString', '')} "
                    f"(score: {collected['cvss'].get('baseScore', 'N/A')}, "
                    f"severity: {collected['cvss'].get('baseSeverity', 'N/A')})"
                )
            if collected["affected"]:
                prompt_parts.append("Affected: " + ", ".join(collected["affected"][:5]))
            if collected["descriptions"]:
                prompt_parts.append("Descriptions:\n" + "\n---\n".join(collected["descriptions"][:10]))
            if collected["code_blocks"]:
                brief = [cb[:3000] for cb in collected["code_blocks"][:6]]
                prompt_parts.append("Code / PoC blocks:\n" + "\n---\n".join(brief))

            reply = client.chat(
                [ChatMessage(role="user", content="\n\n".join(prompt_parts))],
                temperature=0, max_tokens=3000,
            )
            json_candidate = _extract_json_from_text(reply)
            if json_candidate:
                parsed_llm = json.loads(json_candidate)
                if isinstance(parsed_llm, dict):
                    consolidated = {
                        "info": parsed_llm.get("info") or "",
                        "reason": parsed_llm.get("reason") or "",
                        "webpoc": parsed_llm.get("webpoc") or "",
                    }
        finally:
            client.close()
    except Exception as exc:
        print(f"[llm] LLM consolidation failed: {exc}")

    # Fallback: build from raw data if LLM didn't fill fields
    if not consolidated["info"] and collected["descriptions"]:
        consolidated["info"] = collected["descriptions"][0][:1000]

    if not consolidated["reason"]:
        parts = []
        if collected["cwe"]:
            parts.append(f"Weakness: {', '.join(collected['cwe'])}")
        if collected["cvss"]:
            parts.append(f"CVSS {collected['cvss'].get('baseScore', 'N/A')} ({collected['cvss'].get('baseSeverity', '')})")
        consolidated["reason"] = "; ".join(parts)

    if not consolidated["webpoc"] and collected["code_blocks"]:
        for cb in collected["code_blocks"]:
            if re.search(r"^(GET|POST)\s+.*HTTP/\d\.\d", cb, flags=re.I | re.M):
                consolidated["webpoc"] = cb.strip()
                break
        if not consolidated["webpoc"]:
            for cb in collected["code_blocks"]:
                if "requests." in cb or "curl" in cb:
                    consolidated["webpoc"] = cb[:3000].strip()
                    break

    # ---------------------------------------------------------------
    # Step 4: Save
    # ---------------------------------------------------------------
    with open(result_path, "w", encoding="utf-8") as fh:
        json.dump(consolidated, fh, ensure_ascii=False, indent=2)
    print(f"Saved CVE info to: {result_path}")
    return consolidated


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CVE 情报爬取（NVD 镜像 + 参考链接爬虫）")
    parser.add_argument("cve_id", help="CVE 编号，如 CVE-2025-9149")
    parser.add_argument("--force", action="store_true", help="强制重新爬取，忽略缓存")
    args = parser.parse_args()

    result = get_web_infomation(args.cve_id, force=args.force)
    if result:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Failed to fetch CVE info")
        exit(1)
