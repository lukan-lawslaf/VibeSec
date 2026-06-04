"""
rag.py — Retrieval-Augmented Generation utilities for VibeSec.

Uses:
  - ChromaDB  (local persistent vector store)
  - sentence-transformers  (local embedding model, no API key required)

Public API
----------
index_code(code: str) -> None
    Chunk and embed *code* into the Chroma collection.

retrieve_context(query: str, n_results: int = 5) -> str
    Return the top-n most relevant code chunks as a single string.
"""

import hashlib
import os
from typing import Any

# ---------------------------------------------------------------------------
# Lazy initialisation — heavy imports deferred so the module can be loaded
# even when the optional dependencies are not yet installed.
# ---------------------------------------------------------------------------

_chroma_client: Any = None
_collection: Any    = None
_embedding_fn: Any  = None

_COLLECTION_NAME  = "vibesec_code"
_PERSIST_DIR      = os.path.join(os.path.dirname(__file__), "..", ".chromadb")
_EMBEDDING_MODEL  = "all-MiniLM-L6-v2"   # runs on GPU (device='cuda')
_CHUNK_SIZE       = 30   # lines per chunk
_CHUNK_OVERLAP    = 5    # lines of overlap between consecutive chunks


def _ensure_initialised() -> None:
    """Lazily create the ChromaDB client, embedding function, and collection."""
    global _chroma_client, _collection, _embedding_fn

    if _collection is not None:
        return  # already ready

    # -- Chroma ---------------------------------------------------------------
    import chromadb
    from chromadb.utils import embedding_functions

    _chroma_client = chromadb.PersistentClient(path=_PERSIST_DIR)

    # -- Embeddings -----------------------------------------------------------
    _embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=_EMBEDDING_MODEL,
        device="cuda",
    )

    # -- Collection -----------------------------------------------------------
    _collection = _chroma_client.get_or_create_collection(
        name=_COLLECTION_NAME,
        embedding_function=_embedding_fn,
    )


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

async def index_code(code: str) -> None:
    """
    Chunk *code* into overlapping windows and upsert each chunk into Chroma.

    Parameters
    ----------
    code:
        Raw Python (or other) source code as a string.
    """
    _ensure_initialised()

    chunks = _chunk_code(code)
    if not chunks:
        return

    ids       = [_chunk_id(chunk) for chunk in chunks]
    documents = chunks

    # Upsert so re-indexing the same code is idempotent.
    _collection.upsert(ids=ids, documents=documents)


async def retrieve_context(query: str, n_results: int = 5) -> str:
    """
    Query the vector store and return the top-n relevant code chunks
    joined into a single string.

    Parameters
    ----------
    query:
        Natural-language or code-snippet query.
    n_results:
        Number of chunks to retrieve (default 5).

    Returns
    -------
    str
        Newline-separated relevant code chunks, or an empty string if the
        collection is empty.
    """
    _ensure_initialised()

    count = _collection.count()
    if count == 0:
        return ""

    n_results = min(n_results, count)

    results = _collection.query(
        query_texts=[query],
        n_results=n_results,
    )

    documents: list[str] = results.get("documents", [[]])[0]
    return "\n\n---\n\n".join(documents)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _chunk_code(code: str) -> list[str]:
    """Split *code* into overlapping line-based chunks."""
    lines  = code.splitlines()
    chunks: list[str] = []
    start  = 0

    while start < len(lines):
        end   = min(start + _CHUNK_SIZE, len(lines))
        chunk = "\n".join(lines[start:end])
        chunks.append(chunk)
        if end == len(lines):
            break
        start += _CHUNK_SIZE - _CHUNK_OVERLAP

    return chunks


def _chunk_id(chunk: str) -> str:
    """Deterministic, collision-resistant ID for a code chunk."""
    return hashlib.sha256(chunk.encode()).hexdigest()[:32]
