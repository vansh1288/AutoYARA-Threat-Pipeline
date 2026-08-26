import os
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=env_path)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL_NAME = "openai/gpt-oss-20b"
_client = None


from groq import Groq

def get_client():
    api_key = os.getenv("GROQ_API_KEY")
    return Groq(api_key=api_key)


YARA_PROMPT = """You are a threat intelligence expert. Generate a valid YARA rule for the following vulnerability.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
CWE IDs: {cwe_ids}
Description: {description}

Requirements:
- Rule name must follow format: rule_{cve_id}
- Include meta section with description, author, date, cve_id, cvss_score, cwe
- Include strings section with relevant indicators (hex strings, text strings, regex)
- Include condition section with logical detection logic
- Use only valid YARA syntax
- No comments in the rule
- Output ONLY the YARA rule, nothing else"""


SNORT_PROMPT = """You are a threat intelligence expert. Generate a valid Snort rule for the following vulnerability.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
CWE IDs: {cwe_ids}
Description: {description}

Requirements:
- Rule must follow Snort 3 format
- Include action, protocol, source/dest IP/port, direction, options
- Use msg, sid, rev, classtype, reference options
- Reference must include cve,{cve_id}
- Use only valid Snort syntax
- No comments in the rule
- Output ONLY the Snort rule, nothing else"""


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception)
)
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(Exception)
)
def generate_rule(cve: Dict[str, Any], rule_type: str = "yara") -> Optional[str]:
    client = get_client()
    cve_id = cve.get("id", "UNKNOWN")
    cvss_score = cve.get("cvss_score", "N/A")
    cwe_ids = ", ".join(cve.get("cwe_ids", ["N/A"]))
    description = cve.get("cleaned_text", "")[:3000]
    
    safe_cve_id = cve_id.replace("-", "_")
    
    prompt = YARA_PROMPT if rule_type == "yara" else SNORT_PROMPT
    prompt = prompt.format(
        cve_id=safe_cve_id,
        cvss_score=cvss_score,
        cwe_ids=cwe_ids,
        description=description
    )
    
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=2000
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"API Error for {cve_id}: {e}")
        raise e


def generate_rules_batch(cve_list: List[Dict[str, Any]], rule_type: str = "yara") -> List[Dict[str, Any]]:
    results = []
    for cve in cve_list:
        rule = generate_rule(cve, rule_type)
        results.append({
            "cve_id": cve.get("id"),
            "rule_type": rule_type,
            "rule_content": rule,
            "valid": rule is not None
        })
    return results