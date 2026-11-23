"""Per-client and per-service Chroma persistence with explicit metadata filters."""

import os
from pathlib import Path
import shutil
from typing import Any

os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY", "0")

import chromadb
from chromadb.config import Settings


class ChromaVectorStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self._clients: dict[Path, Any] = {}

    def directory_for(self, client_id: int, service_line: str) -> Path:
        if service_line not in {"audit", "accounting", "cosec"}:
            raise ValueError("Unknown service line")
        return self.root / str(int(client_id)) / service_line

    def delete_client(self, client_id: int) -> bool:
        target = (self.root / str(int(client_id))).resolve()
        root = self.root.resolve()
        if target.parent != root:
            raise ValueError("Unsafe vector-store deletion path")
        # Chroma may share internal resources across persistent collections; release all handles first.
        self.close()
        existed = target.exists()
        if existed:
            shutil.rmtree(target)
        return existed

    def close(self) -> None:
        """Release persistent client file handles before a process-level restore."""
        clients = list(self._clients.values())
        self._clients.clear()
        for client in clients:
            close = getattr(client, "close", None)
            if callable(close):
                close()

    def _collection(self, client_id: int, service_line: str):
        directory = self.directory_for(client_id, service_line)
        directory.mkdir(parents=True, exist_ok=True)
        client = self._clients.get(directory)
        if client is None:
            client = chromadb.PersistentClient(
                path=str(directory), settings=Settings(anonymized_telemetry=False)
            )
            self._clients[directory] = client
        return client.get_or_create_collection(
            name="saps_document_chunks", metadata={"hnsw:space": "cosine"}
        )

    def document_hash_matches(self, client_id: int, service_line: str, document_id: int, content_hash: str) -> bool:
        collection = self._collection(client_id, service_line)
        stored = collection.get(where={"document_id": int(document_id)}, include=["metadatas"])
        metadatas = stored.get("metadatas") or []
        return bool(metadatas) and all(meta.get("content_hash") == content_hash for meta in metadatas)

    def remove_document(self, client_id: int, service_line: str, document_id: int) -> None:
        collection = self._collection(client_id, service_line)
        collection.delete(where={"document_id": int(document_id)})

    def upsert_chunks(
        self,
        client_id: int,
        service_line: str,
        document_id: int,
        content_hash: str,
        filename: str,
        classification: str,
        chunks: list[str],
        embeddings: list[list[float]],
    ) -> None:
        if len(chunks) != len(embeddings):
            raise ValueError("Each document chunk must have one embedding")
        collection = self._collection(client_id, service_line)
        collection.upsert(
            ids=[f"doc-{document_id}-chunk-{index}" for index in range(len(chunks))],
            documents=chunks,
            embeddings=embeddings,
            metadatas=[{
                "client_id": int(client_id),
                "service_line": service_line,
                "document_id": int(document_id),
                "chunk_index": index,
                "content_hash": content_hash,
                "filename": filename,
                "classification": classification,
            } for index in range(len(chunks))],
        )

    def search(
        self,
        client_id: int,
        service_line: str,
        embedding: list[float],
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        collection = self._collection(client_id, service_line)
        count = collection.count()
        if not count:
            return []
        result = collection.query(
            query_embeddings=[embedding],
            n_results=min(limit, count),
            where={"$and": [
                {"client_id": int(client_id)},
                {"service_line": service_line},
            ]},
            include=["documents", "metadatas", "distances"],
        )
        documents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        return [
            {"text": text, "metadata": metadata, "distance": distance}
            for text, metadata, distance in zip(documents, metadatas, distances)
        ]
