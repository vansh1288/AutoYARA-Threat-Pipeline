import os
from typing import List, Dict, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type


MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("MONGODB_DATABASE", "threat_intel")
COLLECTION_NAME = os.getenv("MONGODB_COLLECTION", "cves")
_client = None


from pymongo import MongoClient

def get_client():
    uri =os.getenv("MONGODB_URI")
    return MongoClient(uri)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=5),
    retry=retry_if_exception_type((ConnectionFailure, OperationFailure))
)
def insert_cves(cve_list: List[Dict[str, Any]]) -> int:
    if not cve_list:
        return 0
    client = get_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]
    documents = []
    for cve in cve_list:
        cve_id = cve.get("id")
        if not cve_id:
            continue
        doc = {
            "cve_id": cve_id,
            "cleaned_text": cve.get("cleaned_text", ""),
            "embedding": cve.get("embedding", []),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "cvss_score": extract_cvss_score(cve),
            "cwe_ids": extract_cwe_ids(cve)
        }
        documents.append(doc)
    if not documents:
        return 0
    result = collection.insert_many(documents, ordered=False)
    return len(result.inserted_ids)


def extract_cvss_score(cve: Dict[str, Any]) -> Optional[float]:
    metrics = cve.get("metrics", {})
    for metric_type, metric_list in metrics.items():
        for metric in metric_list:
            cvss_data = metric.get("cvssData", {})
            if cvss_data.get("baseScore") is not None:
                return float(cvss_data["baseScore"])
    return None


def extract_cwe_ids(cve: Dict[str, Any]) -> List[str]:
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)
    return cwe_ids


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=5),
    retry=retry_if_exception_type((ConnectionFailure, OperationFailure))
)
def vector_similarity_search(query_embedding: List[float], limit: int = 5) -> List[Dict[str, Any]]:
    client = get_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]
    pipeline = [
        {
            "$vectorSearch": {
                "index": "vector_index",
                "path": "embedding",
                "queryVector": query_embedding,
                "numCandidates": 100,
                "limit": limit
            }
        },
        {
            "$project": {
                "cve_id": 1,
                "cleaned_text": 1,
                "cvss_score": 1,
                "cwe_ids": 1,
                "score": {"$meta": "vectorSearchScore"}
            }
        }
    ]
    return list(collection.aggregate(pipeline))


def close_connection():
    global _client
    if _client:
        _client.close()
        _client = None