import os
import sys
from typing import Dict, Any
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=env_path)
            
import ingest
import embed
import database
import generate
import validate




def run_pipeline(max_cves: int = 100, rule_type: str = "yara") -> Dict[str, Any]:
    cves = ingest.fetch_latest_cves(max_cves=max_cves)
    if not cves:
        return {"status": "no_cves_fetched", "count": 0}
    cves_with_embeddings = embed.generate_embeddings(cves)
    inserted = database.insert_cves(cves_with_embeddings)
    rules = generate.generate_rules_batch(cves_with_embeddings, rule_type)
    validated_rules = validate.validate_rules(rules)
    valid_count = sum(1 for r in validated_rules if r.get("valid"))
    
    return {
        "status": "completed",
        "cves_fetched": len(cves),
        "cves_inserted": inserted,
        "rules_generated": len(rules),
        "rules_valid": valid_count,
        "rules_invalid": len(rules) - valid_count,
        "rule_content": validated_rules
    }

def main():
    import json
    max_cves = int(os.getenv("MAX_CVES", "2"))
    rule_type = os.getenv("RULE_TYPE", "yara")
    
    result = run_pipeline(max_cves=max_cves, rule_type=rule_type)
    
    print(json.dumps(result, indent=4))
    
    database.close_connection()
    sys.exit(0 if result.get("status") == "completed" else 1)

if __name__ == "__main__":
    main()