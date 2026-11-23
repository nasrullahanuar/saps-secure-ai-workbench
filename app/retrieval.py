"""Engagement-scoped retrieval and local-only grounded response generation."""

from dataclasses import dataclass
import json
from pathlib import Path
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Client, Document, Engagement, User
from app.prompt_security import SYSTEM_PROMPT, contains_instruction_like_text, wrap_untrusted_source
from app.scanner import scan_text

_CANARY_PATTERN = re.compile(r"\bCANARY-([A-Z])-\d+\b", re.IGNORECASE)


class AccessDenied(Exception):
    pass


class PromptBlocked(Exception):
    def __init__(self, categories: list[str]):
        self.categories = categories


class CrossScopeCanary(Exception):
    pass


@dataclass(frozen=True)
class SourceChunk:
    reference: str
    document_id: int
    filename: str
    text: str
    classification: str
    injection_detected: bool


@dataclass(frozen=True)
class ChatResult:
    answer: str
    sources: tuple[SourceChunk, ...]


def split_chunks(text: str, size: int = 700, overlap: int = 80) -> list[str]:
    clean = text.strip()
    if not clean:
        return []
    chunks = []
    start = 0
    while start < len(clean):
        end = min(len(clean), start + size)
        chunk = clean[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(clean):
            break
        start = max(start + 1, end - overlap)
    return chunks


class RetrievalService:
    def __init__(self, data_dir: Path, vectors, ollama):
        self.data_dir = Path(data_dir)
        self.vectors = vectors
        self.ollama = ollama

    @staticmethod
    def _log(session: Session, user_id: int, event_type: str, metadata: dict) -> None:
        session.add(AuditLog(
            actor_user_id=user_id,
            event_type=event_type,
            metadata_json=json.dumps(metadata, sort_keys=True),
        ))
        session.commit()

    def authorize(self, session: Session, user_id: int, client_id: int, service_line: str) -> Client:
        role = session.scalar(select(User.role).where(User.id == user_id))
        if role == "it_admin":
            self._log(session, user_id, "retrieval_denied", {
                "client_id": client_id, "service_line": service_line,
                "reason": "privileged_role_has_no_client_content_access",
            })
            raise AccessDenied
        engagement = session.scalar(
            select(Engagement.id).where(
                Engagement.user_id == user_id,
                Engagement.client_id == client_id,
                Engagement.service_line == service_line,
                Engagement.status == "active",
            )
        )
        if engagement is None:
            self._log(session, user_id, "retrieval_denied", {
                "client_id": client_id,
                "service_line": service_line,
                "reason": "no_active_engagement",
            })
            raise AccessDenied
        # Client data is read only after an exact active engagement was verified.
        return session.get(Client, client_id)

    def _reject_foreign_canary(self, session: Session, user_id: int, client: Client, service_line: str, prompt: str) -> None:
        own_code = re.search(r"SYNTH-([A-Z])$", client.synthetic_code)
        own_letter = own_code.group(1).upper() if own_code else None
        foreign = any(match.group(1).upper() != own_letter for match in _CANARY_PATTERN.finditer(prompt))
        if foreign:
            self._log(session, user_id, "retrieval_denied", {
                "client_id": client.id,
                "service_line": service_line,
                "reason": "cross_scope_canary_request",
            })
            raise CrossScopeCanary

    def _authorized_documents(
        self, session: Session, user_id: int, client_id: int, service_line: str
    ) -> list[Document]:
        # This function is called only after authorize() succeeds.
        return session.scalars(select(Document).where(
            Document.client_id == client_id,
            Document.service_line == service_line,
        ).order_by(Document.id)).all()

    def _index_documents(
        self, session: Session, user_id: int, client_id: int, service_line: str
    ) -> None:
        storage_root = (self.data_dir / "documents").resolve()
        for document in self._authorized_documents(session, user_id, client_id, service_line):
            path = (self.data_dir / document.storage_path).resolve()
            if storage_root not in path.parents:
                continue
            if self.vectors.document_hash_matches(
                client_id, service_line, document.id, document.content_hash
            ):
                continue
            self.vectors.remove_document(client_id, service_line, document.id)
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            # Re-scan before vectorization as defense in depth; vectors never receive raw matches.
            sanitized = scan_text(text).redacted_text
            chunks = split_chunks(sanitized)
            if not chunks:
                continue
            embeddings = self.ollama.embed(chunks)
            self.vectors.upsert_chunks(
                client_id,
                service_line,
                document.id,
                document.content_hash,
                document.filename,
                document.classification,
                chunks,
                embeddings,
            )

    @staticmethod
    def _source_from_result(result: dict) -> SourceChunk:
        metadata = result["metadata"]
        document_id = int(metadata["document_id"])
        chunk_index = int(metadata["chunk_index"])
        text = result["text"]
        return SourceChunk(
            reference=f"D{document_id}:C{chunk_index}",
            document_id=document_id,
            filename=str(metadata.get("filename", "Synthetic document")),
            text=text,
            classification=str(metadata.get("classification", "internal")),
            injection_detected=contains_instruction_like_text(text),
        )

    def chat(
        self,
        session: Session,
        user_id: int,
        client_id: int,
        service_line: str,
        prompt: str,
    ) -> ChatResult:
        # Authorization is deliberately the first data-access operation.
        client = self.authorize(session, user_id, client_id, service_line)
        self._reject_foreign_canary(session, user_id, client, service_line, prompt)

        prompt_scan = scan_text(prompt)
        if prompt_scan.findings:
            self._log(session, user_id, "prompt_blocked", {
                "client_id": client_id,
                "service_line": service_line,
                "finding_count": prompt_scan.finding_count,
                "categories": prompt_scan.categories,
            })
            raise PromptBlocked(prompt_scan.categories)

        self._index_documents(session, user_id, client_id, service_line)
        query_embedding = self.ollama.embed([prompt])[0]
        matches = self.vectors.search(client_id, service_line, query_embedding, limit=5)
        sources = tuple(self._source_from_result(item) for item in matches)
        if not sources:
            answer = "No indexed source chunks are available for this assigned engagement yet."
        else:
            context = "\n\n".join(wrap_untrusted_source(source.reference, source.text) for source in sources)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Question:\n{prompt}\n\nAuthorized source data follows:\n{context}"},
            ]
            answer = self.ollama.chat(messages)
            valid_refs = {source.reference for source in sources}
            cited_refs = set(re.findall(r"\[D\d+:C\d+\]", answer)).intersection(
                {f"[{reference}]" for reference in valid_refs}
            )
            if not cited_refs:
                answer = "The local model did not return a valid source citation. Review the authorized source chunks below."

        self._log(session, user_id, "retrieval_query", {
            "client_id": client_id,
            "service_line": service_line,
            "source_count": len(sources),
            "injection_like_sources": sum(source.injection_detected for source in sources),
        })
        return ChatResult(answer=answer, sources=sources)

    def document_by_id(
        self,
        session: Session,
        user_id: int,
        client_id: int,
        service_line: str,
        document_id: int,
    ) -> tuple[Document, str] | None:
        # Denial happens before the document row, path, or contents are read.
        self.authorize(session, user_id, client_id, service_line)
        document = session.scalar(select(Document).where(
            Document.id == document_id,
            Document.client_id == client_id,
            Document.service_line == service_line,
        ))
        if document is None:
            return None
        storage_root = (self.data_dir / "documents").resolve()
        path = (self.data_dir / document.storage_path).resolve()
        if storage_root not in path.parents:
            return None
        try:
            content = scan_text(path.read_text(encoding="utf-8")).redacted_text
        except OSError:
            return None
        self._log(session, user_id, "document_view", {
            "document_id": document.id,
            "client_id": client_id,
            "service_line": service_line,
        })
        return document, content
