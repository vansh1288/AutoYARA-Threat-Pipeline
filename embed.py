import os
from typing import List, Dict, Any
from sentence_transformers import SentenceTransformer


MODEL_NAME = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
_model = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def generate_embeddings(cve_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    model = get_model()
    texts = [cve.get("cleaned_text", "") for cve in cve_list]
    embeddings = model.encode(texts, show_progress_bar=False, convert_to_numpy=True)
    for cve, embedding in zip(cve_list, embeddings):
        cve["embedding"] = embedding.tolist()
    return cve_list