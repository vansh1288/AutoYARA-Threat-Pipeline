import os
import json
import time
import requests
from typing import List, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 2000
REQUEST_TIMEOUT = 30


def clean_cve_text(cve_data: Dict[str, Any]) -> str:
    descriptions = cve_data.get("descriptions", [])
    description_text = " ".join(
        d.get("value", "") for d in descriptions if d.get("lang") == "en"
    )
    metrics = cve_data.get("metrics", {})
    cvss_text = ""
    for metric_type, metric_list in metrics.items():
        for metric in metric_list:
            cvss_data = metric.get("cvssData", {})
            if cvss_data:
                cvss_text += f" CVSS:{cvss_data.get('version', '')} "
                cvss_text += f"Score:{cvss_data.get('baseScore', '')} "
                cvss_text += f"Vector:{cvss_data.get('vectorString', '')} "
    references = cve_data.get("references", [])
    ref_text = " ".join(r.get("url", "") for r in references)
    cwe_text = ""
    weaknesses = cve_data.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwe_text += f" CWE:{desc.get('value', '')}"
    combined = f"{description_text} {cvss_text} {ref_text} {cwe_text}"
    return " ".join(combined.split())


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((requests.RequestException, requests.Timeout))
)
def fetch_cves_page(start_index: int, results_per_page: int, api_key: str = None) -> Dict[str, Any]:
    headers = {"User-Agent": "ThreatIntelPipeline/1.0"}
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    if api_key:
        headers["apiKey"] = api_key
    response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()


def fetch_latest_cves(days_back: int = 1, max_cves: int = 1000) -> List[Dict[str, Any]]:
    api_key = os.getenv("NVD_API_KEY")
    all_cves = []
    start_index = 0
    results_per_page = min(DEFAULT_RESULTS_PER_PAGE, max_cves)
    total_results = None
    while len(all_cves) < max_cves:
        try:
            data = fetch_cves_page(start_index, results_per_page, api_key)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                if cve:
                    cleaned_text = clean_cve_text(cve)
                    cve["cleaned_text"] = cleaned_text
                    all_cves.append(cve)
                    if len(all_cves) >= max_cves:
                        break
            if total_results is None:
                total_results = data.get("totalResults", 0)
            start_index += results_per_page
            if start_index >= total_results:
                break
            time.sleep(1.5 if not api_key else 0.6)
        except requests.RequestException:
            break
    return all_cves[:max_cves]