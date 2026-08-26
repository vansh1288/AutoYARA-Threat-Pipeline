import os
import yara
from typing import List, Dict, Any, Tuple


def validate_yara_rule(rule_content: str) -> Tuple[bool, str]:
    if not rule_content:
        return False, "Empty rule content"
    try:
        compiled = yara.compile(source=rule_content)
        return True, "Valid"
    except yara.SyntaxError as e:
        return False, f"Syntax error: {str(e)}"
    except yara.Error as e:
        return False, f"YARA error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def validate_snort_rule(rule_content: str) -> Tuple[bool, str]:
    if not rule_content:
        return False, "Empty rule content"
    required_fields = ["msg:", "sid:", "rev:"]
    missing = [field for field in required_fields if field not in rule_content]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    if not rule_content.strip().startswith(("alert", "drop", "reject", "pass", "log")):
        return False, "Invalid action keyword"
    return True, "Valid"


def validate_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    validated = []
    for rule in rules:
        rule_type = rule.get("rule_type", "yara")
        content = rule.get("rule_content", "")
        if rule_type == "yara":
            is_valid, message = validate_yara_rule(content)
        else:
            is_valid, message = validate_snort_rule(content)
        validated.append({
            "cve_id": rule.get("cve_id"),
            "rule_type": rule_type,
            "rule_content": content,
            "valid": is_valid,
            "validation_message": message
        })
    return validated