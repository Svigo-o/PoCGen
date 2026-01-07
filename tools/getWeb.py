from langchain.tools import tool
from langchain_classic.agents import AgentExecutor,create_react_agent
from langchain_classic import hub
from langchain_openai import ChatOpenAI
import requests
from bs4 import BeautifulSoup
import re
import os
import sys
import time
from datetime import datetime
import urllib.parse
from typing import Dict, List, Optional, Any
import json

# 辅助函数 - 必须先定义
def _extract_nvd_description(soup) -> str:
    """提取NVD漏洞描述"""
    desc_elements = soup.find_all(['p', 'div'], attrs={
        'data-testid': lambda x: x and 'vuln-description' in x.lower()
    })
    
    for element in desc_elements:
        text = element.get_text(strip=True)
        if text and len(text) > 10:
            return text
    
    # 备用方法
    for element in soup.find_all(['p', 'div']):
        text = element.get_text(strip=True)
        if text and len(text) > 100:
            if any(keyword in text.lower() for keyword in ['vulnerability', 'allows', 'could', 'attack']):
                return text
    
    return "未找到描述信息"

def _classify_reference_type(url: str) -> str:
    """分类参考链接类型"""
    domain = urllib.parse.urlparse(url).netloc.lower()
    
    if 'github.com' in domain:
        return "github"
    elif any(site in domain for site in ['securityfocus.com', 'seclists.org', 'packetstormsecurity.com']):
        return "security_advisory"
    elif any(site in domain for site in ['.com', '.org', '.net']):
        return "vendor"
    else:
        return "other"

def _extract_nvd_references(soup) -> List[Dict[str, str]]:
    """提取NVD参考链接"""
    references = []
    
    # 方法1: 查找参考链接表格
    ref_tables = soup.find_all('table', {'data-testid': lambda x: x and 'hyperlink' in x.lower()})
    
    for table in ref_tables:
        rows = table.find_all('tr')
        for row in rows[1:]:
            link_element = row.find('a')
            if link_element and link_element.get('href'):
                link_text = link_element.get_text(strip=True)
                link_url = link_element.get('href')
                references.append({
                    "text": link_text,
                    "url": link_url,
                    "type": _classify_reference_type(link_url)
                })
    
    # 方法2: 查找所有外部链接
    if not references:
        for link in soup.find_all('a', href=True):
            url = link.get('href')
            text = link.get_text(strip=True)
            
            if url and not url.startswith('#') and 'nvd.nist.gov' not in url:
                if any(ext in url.lower() for ext in ['.com', '.org', '.net', 'http', 'https']):
                    references.append({
                        "text": text,
                        "url": url,
                        "type": _classify_reference_type(url)
                    })
    
    # 去重
    unique_refs = []
    seen_urls = set()
    for ref in references:
        if ref["url"] not in seen_urls:
            seen_urls.add(ref["url"])
            unique_refs.append(ref)
    
    return unique_refs[:20]

def _extract_reference_description(soup, url: str) -> str:
    """提取参考链接页面描述信息"""
    description_parts = []
    
    domain = urllib.parse.urlparse(url).netloc.lower()
    
    # 安全公告网站处理
    if any(site in domain for site in ['securityfocus.com', 'seclists.org', 'packetstormsecurity.com']):
        for elem in soup.find_all(['pre', 'div', 'article']):
            text = elem.get_text(strip=True)
            if text and len(text) > 200 and 'vulnerability' in text.lower():
                description_parts.append(text[:1000])
                break
    
    # 厂商网站处理
    elif any(site in domain for site in ['.com', '.org', '.net']):
        for tag in ['article', 'main', 'div.content', 'div.post-content', 'div.entry-content']:
            elements = soup.find_all(tag)
            for elem in elements:
                text = elem.get_text(strip=True)
                if text and len(text) > 300:
                    description_parts.append(text)
                    break
            if description_parts:
                break
    
    # 如果没有找到特定内容，提取页面主要文本
    if not description_parts:
        paragraphs = soup.find_all('p')
        for p in paragraphs[:6]:
            text = p.get_text(strip=True)
            if text and len(text) > 30:
                description_parts.append(text)
    
    # 如果还是没有内容，提取页面文本的前部分
    if not description_parts:
        all_text = soup.get_text()
        cleaned_text = re.sub(r'\s+', ' ', all_text)
        if len(cleaned_text) > 200:
            description_parts.append(cleaned_text[:1000])
    
    return "\n\n".join(description_parts) if description_parts else "未能提取到描述信息"

def _extract_reference_code_blocks(soup) -> List[str]:
    """提取参考链接代码块信息"""
    code_blocks = []
    
    # 查找pre标签
    pre_blocks = soup.find_all('pre')
    for pre in pre_blocks:
        code_text = pre.get_text(strip=False)
        if code_text and len(code_text) > 10:
            code_blocks.append(code_text)
    
    # 查找code标签
    code_elements = soup.find_all('code')
    for code in code_elements:
        code_text = code.get_text(strip=False)
        if code_text and len(code_text) > 50:
            code_blocks.append(code_text)
    
    return code_blocks

def _parse_github_markdown_content(md_content: str, url: str) -> Dict[str, Any]:
    """解析GitHub Markdown内容"""
    content_info = {
        'description': "",
        'code_blocks': [],
        'tables': [],
        'headings': []
    }
    
    lines = md_content.split('\n')
    in_code_block = False
    current_code_block = []
    
    for line in lines:
        line = line.rstrip()
        
        # 检测代码块开始/结束
        if line.strip().startswith('```'):
            if in_code_block:
                # 代码块结束
                if current_code_block:
                    content_info['code_blocks'].append('\n'.join(current_code_block))
                    current_code_block = []
                in_code_block = False
            else:
                # 代码块开始
                in_code_block = True
            continue
        
        # 如果在代码块中
        if in_code_block:
            current_code_block.append(line)
            continue
        
        # 非代码块内容作为描述的一部分
        if line.strip() and not line.startswith('#'):
            if len(content_info['description']) < 1000:
                content_info['description'] += line + "\n"
    
    # 处理最后一个代码块
    if current_code_block:
        content_info['code_blocks'].append('\n'.join(current_code_block))
    
    # 清理描述文本
    content_info['description'] = content_info['description'].strip()
    
    return content_info

def _extract_from_github_page(github_url: str) -> Dict[str, Any]:
    """从GitHub页面提取内容"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        
        response = requests.get(github_url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return {
                "description": f"访问GitHub页面失败，状态码: {response.status_code}",
                "code_blocks": []
            }
        
        soup = BeautifulSoup(response.content, 'html.parser')
        content_info = {
            'description': "",
            'code_blocks': []
        }
        
        # 查找Markdown内容区域
        md_content_div = soup.find('div', {'class': 'markdown-body'})
        if md_content_div:
            # 提取代码块
            pre_blocks = md_content_div.find_all('pre')
            for pre in pre_blocks:
                code_text = pre.get_text(strip=False)
                if code_text:
                    content_info['code_blocks'].append(code_text)
            
            # 提取描述文本
            for element in md_content_div.find_all(['p', 'div']):
                if element.find_parent('pre'):
                    continue
                text = element.get_text(strip=True)
                if text and len(text) > 20:
                    content_info['description'] += text + "\n"
        
        # 如果没有找到markdown-body，尝试其他内容区域
        if not content_info['description']:
            article = soup.find('article')
            if article:
                pre_blocks = article.find_all('pre')
                for pre in pre_blocks:
                    code_text = pre.get_text(strip=False)
                    if code_text:
                        content_info['code_blocks'].append(code_text)
                
                for element in article.find_all(['p', 'div']):
                    if element.find_parent('pre'):
                        continue
                    text = element.get_text(strip=True)
                    if text and len(text) > 20:
                        content_info['description'] += text + "\n"
        
        content_info['description'] = content_info['description'].strip()[:1000]
        
        return content_info
        
    except Exception as e:
        return {
            "description": f"解析GitHub页面失败: {str(e)}",
            "code_blocks": []
        }

# 主工具函数
@tool
def get_cve_info(cve_id: str) -> str:
    """
    爬取NVD库CVE信息工具。输入CVE编号，返回描述信息和参考链接。
    
    Args:
        cve_id: CVE编号，格式如 CVE-2024-27983
        
    Returns:
        JSON格式字符串，包含描述信息和参考链接数组
    """
    # 验证CVE编号格式
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id, re.IGNORECASE):
        return json.dumps({
            "error": f"CVE编号格式不正确: {cve_id}",
            "correct_format": "CVE-YYYY-NNNN (例如: CVE-2024-27983)"
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

    # optional proxy support from env
    proxies = {
        k: v
        for k, v in {
            "http": os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY"),
            "https": os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"),
        }.items()
        if v
    } or None

    def _request(url: str, timeout: int = 15):
        last_exc: Optional[Exception] = None
        last_status: Optional[int] = None
        for _ in range(3):
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    proxies=proxies,
                )
                last_status = resp.status_code
                if resp.status_code == 200:
                    return resp
            except Exception as exc:  # noqa: PERF203
                last_exc = exc
            time.sleep(3)
        raise RuntimeError(f"request failed, status={last_status}, error={last_exc}")

    try:
        # Prefer the official JSON API; it is less likely to be blocked by WAF.
        try:
            api_resp = _request(api_url, timeout=20)
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
                # fallback to first description
                if not description and descriptions:
                    description = descriptions[0].get("value", "")

                references = []
                for ref in cve_obj.get("references") or []:
                    ref_url = ref.get("url")
                    if not ref_url:
                        continue
                    ref_text = ref.get("source") or ref_url
                    references.append(
                        {
                            "text": ref_text,
                            "url": ref_url,
                            "type": _classify_reference_type(ref_url),
                        }
                    )

                if description or references:
                    return json.dumps(
                        {
                            "cve_id": cve_id,
                            "description": description or "",
                            "references": references,
                            "success": True,
                            "source": "nvd_api",
                        },
                        ensure_ascii=False,
                    )
        except Exception:
            # API may rate-limit or block; fall back to HTML page.
            pass

        page_resp = _request(detail_url, timeout=20)

        if page_resp.status_code == 404:
            return json.dumps({"error": f"CVE {cve_id} 不存在或在NVD库中未找到"})

        if page_resp.status_code != 200:
            return json.dumps({"error": f"NVD库请求失败，状态码: {page_resp.status_code}"})

        soup = BeautifulSoup(page_resp.content, "html.parser")

        description = _extract_nvd_description(soup)
        references = _extract_nvd_references(soup)

        result = {
            "cve_id": cve_id,
            "description": description,
            "references": references,
            "success": True,
            "source": "nvd_html",
        }

        return json.dumps(result, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"error": f"请求错误: {str(e)}"}, ensure_ascii=False)


@tool
def save_to_file(input_str: str) -> str:
    """
    保存工具。将信息保存到指定文件路径，如果文件不存在，会直接创建。
    输入格式：文件路径|内容
    
    Args:
        input_str: 包含文件路径和内容的字符串，格式为"文件路径|内容"
        
    Returns:
        保存结果的JSON字符串
    """
    try:
        # 解析输入字符串
        if '|' not in input_str:
            return json.dumps({
                "success": False,
                "error": "输入格式不正确，请使用'文件路径|内容'的格式"
            }, ensure_ascii=False)
        
        # 分割文件路径和内容
        parts = input_str.split('|', 1)
        file_path = parts[0].strip()
        content = parts[1].strip()
        
        # 确保目录存在
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # 使用覆盖模式写入
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content + "\n")
        
        result = {
            "success": True,
            "file_path": file_path,
            "message": f"内容已成功保存到 {file_path}",
            "content_length": len(content)
        }
        
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"保存文件时出错: {str(e)}"
        }, ensure_ascii=False)

@tool
def crawl_reference(reference_url: str) -> str:
    """
    爬取NVD库中reference链接的工具。输入一个reference链接，输出描述信息以及代码块信息。
    
    Args:
        reference_url: 参考链接URL
        
    Returns:
        JSON格式字符串，包含描述信息和代码块信息
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    
    try:
        # 如果是GitHub链接，使用专门的GitHub爬取工具
        if 'github.com' in reference_url:
            return crawl_github(reference_url)
        
        # 添加延迟避免请求过快
        time.sleep(1)
        
        response = requests.get(reference_url, headers=headers, timeout=15)
        
        if response.status_code != 200:
            return json.dumps({
                "success": False,
                "error": f"HTTP请求失败，状态码: {response.status_code}",
                "url": reference_url
            }, ensure_ascii=False)
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # 提取页面标题
        title_tag = soup.find('title')
        page_title = title_tag.get_text(strip=True) if title_tag else "无标题"
        
        # 提取描述信息
        description = _extract_reference_description(soup, reference_url)
        
        # 提取代码块信息
        code_blocks = _extract_reference_code_blocks(soup)
        
        result = {
            "success": True,
            "url": reference_url,
            "title": page_title,
            "description": description,
            "code_blocks": code_blocks,
            "content_type": "web_page"
        }
        
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"爬取参考链接时出错: {str(e)}",
            "url": reference_url
        }, ensure_ascii=False)




@tool
def crawl_github(github_url: str) -> str:
    """
    GitHub爬取工具。如果是github链接，输入reference链接，输出代码块信息与描述信息。
    
    Args:
        github_url: GitHub链接
        
    Returns:
        JSON格式字符串，包含代码块信息和描述信息
    """
    if not github_url or 'github.com' not in github_url:
        return json.dumps({
            "success": False,
            "error": "不是有效的GitHub链接"
        }, ensure_ascii=False)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    
    try:
        # 尝试获取原始Markdown内容
        raw_url = github_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
        
        response = requests.get(raw_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            md_content = response.text
            result = _parse_github_markdown_content(md_content, github_url)
        else:
            # 如果原始内容获取失败，尝试解析GitHub页面
            result = _extract_from_github_page(github_url)
        
        result["success"] = True
        result["url"] = github_url
        result["content_type"] = "github"
        
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"爬取GitHub链接时出错: {str(e)}",
            "url": github_url
        }, ensure_ascii=False)




def get_web_infomation(cve_str:str):
    # 配置大模型
    base_url = "http://222.20.126.32:30000/v1"  # 您的大模型地址
    api_key = "DeepseekV3.1_32@C402"  # API密钥
    
    llm = ChatOpenAI(
        model="ds",
        temperature=0,
        openai_api_base=base_url,
        openai_api_key=api_key,
        timeout=60
    )
    
    # 获取工具（使用@tool装饰器会自动创建Tool对象）
    tools = [get_cve_info, save_to_file, crawl_reference, crawl_github]
    
    # 创建代理
    prompt = hub.pull("hwchase17/react")
    agent = create_react_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(
        agent=agent, 
        tools=tools, 
        verbose=True,
        handle_parsing_errors=True
    )
    
    # 测试
    questions = [
        "请选择合适的工具，在NVD数据库随便搜索"+cve_str+"的信息，若爬取失败请多次爬取中间间隔30s直到成功，不允许假设自己成功了，也不允许放弃，记住漏洞的描述信息。然后请检测NVD搜索页面的参考链接，并依次爬取参考链接，获取参考链接中的漏洞信息，最后将所有爬取下来关于漏洞的信息分为三部分①描述信息的总结，②漏洞成因漏洞类型③PoC攻击报文部分例如以POST或GET开头的部分，三部分按照json格式保存到../output/searchResult/"+cve_str+"_info.json，三个字段名分别为info、reason、webpoc注意不要存储爬取失败的信息，如果提醒他、文件不存在请自行创建"
        
    ]
    
    for question in questions:
        print(f"\n问题: {question}")
        print("-" * 40)
        
        try:
            result = agent_executor.invoke({"input": question})
            print(f"回答: {result['output']}")
        except Exception as e:
            print(f"错误: {e}")
