"""Local SAPS demo: password + TOTP login and a small assignment dashboard."""

from pathlib import Path
import hashlib
import json
import re
import secrets
import time
from uuid import uuid4

import pyotp

from app.egress_guard import install_egress_guard

install_egress_guard()

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from app.auth import hash_password, verify_password, verify_totp
from app.audit_chain import verify_audit_chain
from app.config import get_settings
from app.database import initialize_database
from app.models import (
    Approval, AuditLog, Client, Document, Draft, DraftCitation, Engagement,
    IndependenceReview, User,
)
from app.models import utc_now
from app.operations import secure_delete_client
from app.ollama_client import LocalOllamaClient
from app.retrieval import AccessDenied, ChatResult, CrossScopeCanary, PromptBlocked, RetrievalService
from app.scanner import scan_text
from app.vector_store import ChromaVectorStore
from app.workflow_policy import WORKFLOWS, cited_references, valid_cited_claim_lines

TEMPLATES_DIR = Path(__file__).parent / "templates"
MAX_UPLOAD_BYTES = 1_048_576
SERVICE_LINES = {"audit", "accounting", "cosec"}


def create_app(
    database_url: str | None = None,
    session_secret: str | None = None,
    session_timeout_seconds: int | None = None,
    data_dir: Path | str | None = None,
    ollama_client=None,
    vector_store=None,
) -> FastAPI:
    settings = get_settings()
    timeout = session_timeout_seconds or settings.session_timeout_seconds
    # Random fallback is process-local; configure .env for stable sessions across restarts.
    configured_secret = session_secret or settings.session_secret
    if configured_secret == "replace-with-a-random-value-before-use":
        configured_secret = ""
    secret_key = configured_secret or secrets.token_urlsafe(48)
    storage_root = Path(data_dir) if data_dir is not None else settings.data_dir
    local_ollama = ollama_client or LocalOllamaClient(settings)
    local_vectors = vector_store or ChromaVectorStore(storage_root / "vectors")
    retrieval_service = RetrievalService(storage_root, local_vectors, local_ollama)
    factory: sessionmaker[Session] = initialize_database(database_url)
    application = FastAPI(title="SAPS Local Lab")
    application.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        max_age=timeout,
        same_site="lax",
        https_only=False,
    )
    application.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    def db_session():
        with factory() as session:
            yield session

    def current_user(request: Request, session: Session) -> User | None:
        user_id = request.session.get("user_id")
        last_activity = request.session.get("last_activity")
        if not user_id or not last_activity or time.time() - int(last_activity) > timeout:
            request.session.clear()
            return None
        user = session.get(User, int(user_id))
        if user is None or not user.is_active:
            request.session.clear()
            return None
        request.session["last_activity"] = int(time.time())
        return user

    def user_engagement_choices(session: Session, user_id: int) -> list[dict]:
        if session.scalar(select(User.role).where(User.id == user_id)) == "it_admin":
            return []
        rows = session.execute(
            select(Client.id, Client.name, Engagement.service_line)
            .join(Engagement, Engagement.client_id == Client.id)
            .where(Engagement.user_id == user_id, Engagement.status == "active")
            .order_by(Client.name, Engagement.service_line)
        ).all()
        return [
            {"client_id": client_id, "client_name": name, "service_line": service_line}
            for client_id, name, service_line in rows
        ]

    def audit_event(session: Session, user_id: int, event_type: str, metadata: dict) -> None:
        session.add(AuditLog(
            actor_user_id=user_id,
            event_type=event_type,
            metadata_json=json.dumps(metadata, sort_keys=True),
        ))
        session.commit()

    def save_ai_draft(session: Session, user: User, client_id: int, service_line: str,
                      draft_type: str, result: ChatResult) -> Draft:
        if not result.sources or not valid_cited_claim_lines(result.answer, result.sources):
            raise ValueError("The local model response did not cite every claim to an authorized source.")
        output_scan = scan_text(result.answer)
        if output_scan.findings:
            audit_event(session, user.id, "draft_output_blocked", {
                "client_id": client_id, "service_line": service_line,
                "categories": output_scan.categories,
            })
            raise ValueError("The local model response was blocked by the privacy scanner.")
        references = cited_references(result.answer)
        draft = Draft(
            client_id=client_id,
            service_line=service_line,
            draft_type=draft_type,
            content=result.answer,
            status="draft",
            prepared_by=user.id,
        )
        session.add(draft)
        session.flush()
        for source in result.sources:
            if source.reference in references:
                session.add(DraftCitation(
                    draft_id=draft.id,
                    document_id=source.document_id,
                    chunk_id=source.reference,
                    source_excerpt=source.text,
                ))
        audit_event(session, user.id, "draft_created", {
            "draft_id": draft.id, "client_id": client_id, "service_line": service_line,
            "draft_type": draft_type, "citation_count": len(references),
        })
        return draft

    def authorized_draft(session: Session, user: User, draft_id: int) -> Draft | None:
        # Read scope metadata first. Do not load draft content until engagement access is confirmed.
        if user.role == "it_admin":
            audit_event(session, user.id, "draft_access_denied", {
                "draft_id": draft_id, "reason": "privileged_role_has_no_client_content_access",
            })
            raise AccessDenied
        scope = session.execute(select(
            Draft.client_id, Draft.service_line,
        ).where(Draft.id == draft_id)).first()
        if scope is None:
            return None
        assigned = session.scalar(select(Engagement.id).where(
            Engagement.user_id == user.id,
            Engagement.client_id == scope.client_id,
            Engagement.service_line == scope.service_line,
            Engagement.status == "active",
        ))
        if assigned is None:
            audit_event(session, user.id, "draft_access_denied", {
                "draft_id": draft_id, "client_id": scope.client_id,
                "service_line": scope.service_line,
            })
            raise AccessDenied
        return session.get(Draft, draft_id)

    @application.get("/", response_class=HTMLResponse)
    def home(request: Request):
        if request.session.get("user_id"):
            return RedirectResponse("/dashboard", status_code=303)
        return RedirectResponse("/login", status_code=303)

    @application.exception_handler(404)
    async def not_found(request: Request, _exception):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"code": 404, "heading": "Page not found", "message": "That workspace page is not available."},
            status_code=404,
        )

    @application.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @application.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        totp_code: str = Form(...),
        session: Session = Depends(db_session),
    ):
        user = session.scalar(select(User).where(User.username == username, User.is_active.is_(True)))
        valid = bool(
            user
            and verify_password(user.password_hash, password)
            and verify_totp(user.totp_secret, totp_code)
        )
        session.add(AuditLog(
            actor_user_id=user.id if user and valid else None,
            event_type="login_success" if valid else "login_denied",
            metadata_json='{"method":"password_totp"}',
        ))
        session.commit()
        if not valid:
            return templates.TemplateResponse(
                request, "login.html", {"error": "Login failed. Check your credentials and one-time code."},
                status_code=401,
            )

        request.session.clear()
        request.session.update({"user_id": user.id, "last_activity": int(time.time())})
        return RedirectResponse("/dashboard", status_code=303)

    @application.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)

        rows = [] if user.role == "it_admin" else session.execute(
            select(Client.name, Client.synthetic_code, Engagement.service_line)
            .join(Engagement, Engagement.client_id == Client.id)
            .where(Engagement.user_id == user.id, Engagement.status == "active")
            .order_by(Client.name, Engagement.service_line)
        ).all()
        assignments = [
            {"client": name, "code": code, "service_line": service}
            for name, code, service in rows
        ]
        pair_join = and_(
            Engagement.client_id == Document.client_id,
            Engagement.service_line == Document.service_line,
        )
        visible_documents = select(Document).join(Engagement, pair_join).where(
            Engagement.user_id == user.id, Engagement.status == "active"
        )
        documents = [] if user.role == "it_admin" else session.scalars(
            visible_documents.order_by(Document.created_at.desc()).limit(10)
        ).all()
        document_count = 0 if user.role == "it_admin" else session.scalar(
            select(func.count(Document.id)).join(Engagement, pair_join).where(
                Engagement.user_id == user.id, Engagement.status == "active"
            )
        ) or 0
        pending_drafts = 0 if user.role == "it_admin" else session.scalar(
            select(func.count(Draft.id)).join(
                Engagement,
                and_(Engagement.client_id == Draft.client_id, Engagement.service_line == Draft.service_line),
            ).where(
                Engagement.user_id == user.id,
                Engagement.status == "active",
                Draft.status.in_(("draft", "reviewed")),
            )
        ) or 0
        blocked_uploads = session.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.actor_user_id == user.id,
                AuditLog.event_type.in_(("ingestion_blocked", "upload_denied")),
            )
        ) or 0
        recent_activity = session.scalars(
            select(AuditLog).where(AuditLog.actor_user_id == user.id)
            .order_by(AuditLog.created_at.desc()).limit(5)
        ).all()
        stats = {
            "clients": len({(item["client"], item["code"]) for item in assignments}),
            "documents": document_count,
            "pending_drafts": pending_drafts,
            "blocked_uploads": blocked_uploads,
        }
        return templates.TemplateResponse(
            request, "dashboard.html", {
                "user": user,
                "assignments": assignments,
                "documents": documents,
                "stats": stats,
                "recent_activity": recent_activity,
            }
        )

    @application.get("/documents/upload", response_class=HTMLResponse)
    def upload_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        choices = user_engagement_choices(session, user.id)
        return templates.TemplateResponse(
            request, "upload.html", {"user": user, "choices": choices, "result": None, "error": None}
        )

    @application.post("/documents/upload", response_class=HTMLResponse)
    async def upload_document(
        request: Request,
        client_service: str = Form(..., max_length=64),
        file: UploadFile = File(...),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)

        try:
            client_text, service_line = client_service.split(":", maxsplit=1)
            client_id = int(client_text)
        except (ValueError, TypeError):
            client_id, service_line = 0, ""

        # Authorize the requested pair before reading the uploaded bytes.
        allowed = user.role != "it_admin" and service_line in SERVICE_LINES and session.scalar(
            select(Engagement.id).where(
                Engagement.user_id == user.id,
                Engagement.client_id == client_id,
                Engagement.service_line == service_line,
                Engagement.status == "active",
            )
        ) is not None
        if not allowed:
            session.add(AuditLog(
                actor_user_id=user.id,
                event_type="upload_denied",
                metadata_json=json.dumps({"client_id": client_id, "service_line": service_line}),
            ))
            session.commit()
            return templates.TemplateResponse(
                request, "upload.html", {"user": user, "choices": [], "result": None,
                                          "error": "Upload denied: no active engagement for that client and service line."},
                status_code=403,
            )

        def log_rejection(reason: str) -> None:
            session.add(AuditLog(
                actor_user_id=user.id,
                event_type="ingestion_blocked",
                metadata_json=json.dumps({
                    "client_id": client_id,
                    "service_line": service_line,
                    "reason": reason,
                }, sort_keys=True),
            ))
            session.commit()

        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in {".txt", ".csv", ".md"}:
            log_rejection("unsupported_file_type")
            return templates.TemplateResponse(
                request, "upload.html", {"user": user, "choices": [], "result": None,
                                          "error": "Upload only a synthetic .txt, .csv, or .md file."},
                status_code=415,
            )
        raw_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            log_rejection("file_too_large")
            return templates.TemplateResponse(
                request, "upload.html", {"user": user, "choices": [], "result": None,
                                          "error": "File exceeds the 1 MiB upload limit."},
                status_code=413,
            )
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            log_rejection("invalid_text_encoding")
            return templates.TemplateResponse(
                request, "upload.html", {"user": user, "choices": [], "result": None,
                                          "error": "Upload must be UTF-8 text."},
                status_code=415,
            )

        scan = scan_text(raw_text)
        document_id = uuid4().hex
        stored_name = f"document_{document_id}{suffix}"
        relative_path = Path("documents") / str(client_id) / service_line / stored_name
        absolute_path = storage_root / relative_path
        absolute_path.parent.mkdir(parents=True, exist_ok=True)
        absolute_path.write_text(scan.redacted_text, encoding="utf-8")
        digest = hashlib.sha256(scan.redacted_text.encode("utf-8")).hexdigest()
        status = "redacted" if scan.findings else "accepted"
        document = Document(
            client_id=client_id,
            service_line=service_line,
            filename=stored_name,
            classification=scan.classification,
            storage_path=relative_path.as_posix(),
            content_hash=digest,
            ingestion_status=status,
            created_by=user.id,
        )
        session.add(document)
        session.flush()
        session.add(AuditLog(
            actor_user_id=user.id,
            event_type="ingestion_redacted" if scan.findings else "ingestion_accepted",
            metadata_json=json.dumps({
                "document_id": document.id,
                "client_id": client_id,
                "service_line": service_line,
                "classification": scan.classification,
                "finding_count": scan.finding_count,
                "categories": scan.categories,
            }, sort_keys=True),
        ))
        try:
            session.commit()
        except Exception:
            absolute_path.unlink(missing_ok=True)
            session.rollback()
            raise

        result = {
            "status": status,
            "classification": scan.classification,
            "categories": scan.categories,
            "finding_count": scan.finding_count,
            "document_id": document.id,
        }
        choices = user_engagement_choices(session, user.id)
        return templates.TemplateResponse(
            request, "upload.html", {"user": user, "choices": choices, "result": result, "error": None}
        )

    @application.get("/workflows", response_class=HTMLResponse)
    def workflows_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(request, "workflows.html", {
            "user": user, "choices": user_engagement_choices(session, user.id),
            "workflows": WORKFLOWS, "error": None, "saved_draft": None,
        })

    @application.post("/workflows/generate", response_class=HTMLResponse)
    def generate_workflow(
        request: Request,
        client_service: str = Form(..., max_length=64),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        try:
            client_text, service_line = client_service.split(":", maxsplit=1)
            client_id = int(client_text)
        except (ValueError, TypeError):
            client_id, service_line = 0, ""
        workflow = WORKFLOWS.get(service_line)
        saved_draft = None
        error = None
        status_code = 200
        try:
            if workflow is None:
                raise AccessDenied
            result = retrieval_service.chat(
                session, user.id, client_id, service_line, workflow["prompt"]
            )
            draft = save_ai_draft(
                session, user, client_id, service_line, workflow["type"], result
            )
            saved_draft = {"id": draft.id, "title": workflow["title"], "content": draft.content}
        except AccessDenied:
            error, status_code = "Access denied: you are not assigned to that client and service line.", 403
        except CrossScopeCanary:
            error, status_code = "Access denied: a cross-client canary request was blocked.", 403
        except PromptBlocked as blocked:
            error, status_code = "Workflow prompt blocked by privacy scanner: " + ", ".join(blocked.categories), 400
        except ValueError as exc:
            error, status_code = str(exc), 422
        except Exception as exc:
            audit_event(session, user.id, "local_generation_failed", {
                "client_id": client_id, "service_line": service_line,
                "error_type": type(exc).__name__,
            })
            error, status_code = "Local retrieval or generation is unavailable. Check Ollama and configured models.", 503
        return templates.TemplateResponse(request, "workflows.html", {
            "user": user, "choices": user_engagement_choices(session, user.id),
            "workflows": WORKFLOWS, "error": error, "saved_draft": saved_draft,
            "selected_client_service": client_service,
        }, status_code=status_code)

    @application.get("/drafts", response_class=HTMLResponse)
    def drafts_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        drafts = [] if user.role == "it_admin" else session.scalars(
            select(Draft).join(Engagement, and_(
                Engagement.client_id == Draft.client_id,
                Engagement.service_line == Draft.service_line,
            )).where(Engagement.user_id == user.id, Engagement.status == "active")
            .order_by(Draft.created_at.desc())
        ).unique().all()
        citation_map = {}
        for draft in drafts:
            citation_map[draft.id] = session.scalars(
                select(DraftCitation).where(DraftCitation.draft_id == draft.id)
            ).all()
        return templates.TemplateResponse(request, "drafts.html", {
            "user": user, "drafts": drafts, "citation_map": citation_map,
            "error": None, "notice": request.query_params.get("notice"),
        })

    @application.get("/approvals", response_class=HTMLResponse)
    def approvals_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        drafts = [] if user.role == "it_admin" else session.scalars(
            select(Draft).join(Engagement, and_(
                Engagement.client_id == Draft.client_id,
                Engagement.service_line == Draft.service_line,
            )).where(
                Engagement.user_id == user.id, Engagement.status == "active",
                Draft.prepared_by != user.id, Draft.status.in_(("draft", "reviewed")),
            ).order_by(Draft.created_at)
        ).unique().all()
        return templates.TemplateResponse(request, "approvals.html", {
            "user": user, "drafts": drafts, "error": None,
        })

    @application.post("/drafts/{draft_id}/review")
    def review_draft(
        draft_id: int, request: Request, comments: str = Form("", max_length=2000),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        try:
            draft = authorized_draft(session, user, draft_id)
        except AccessDenied:
            return PlainTextResponse("Access denied", status_code=403)
        if draft is None:
            return PlainTextResponse("Draft not found", status_code=404)
        if draft.prepared_by == user.id:
            audit_event(session, user.id, "draft_review_denied", {"draft_id": draft.id, "reason": "self_review"})
            return PlainTextResponse("The preparer cannot review their own draft.", status_code=403)
        if draft.status != "draft":
            return PlainTextResponse("Only Draft items can move to Reviewed.", status_code=409)
        draft.status = "reviewed"
        safe_comments = scan_text(comments).redacted_text
        session.add(Approval(draft_id=draft.id, reviewer_id=user.id, decision="reviewed", comments=safe_comments))
        audit_event(session, user.id, "draft_reviewed", {"draft_id": draft.id})
        return RedirectResponse("/drafts?notice=Draft%20marked%20Reviewed", status_code=303)

    @application.post("/drafts/{draft_id}/approve")
    def approve_draft(
        draft_id: int, request: Request, comments: str = Form("", max_length=2000),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        try:
            draft = authorized_draft(session, user, draft_id)
        except AccessDenied:
            return PlainTextResponse("Access denied", status_code=403)
        if draft is None:
            return PlainTextResponse("Draft not found", status_code=404)
        if draft.prepared_by == user.id:
            audit_event(session, user.id, "draft_approval_denied", {"draft_id": draft.id, "reason": "self_approval"})
            return PlainTextResponse("The preparer cannot approve their own draft.", status_code=403)
        if draft.status != "reviewed":
            return PlainTextResponse("Only Reviewed items can move to Approved.", status_code=409)
        citation_count = session.scalar(select(func.count(DraftCitation.id)).where(DraftCitation.draft_id == draft.id)) or 0
        if not citation_count:
            return PlainTextResponse("A draft without citations cannot be approved.", status_code=409)
        draft.status = "approved"
        safe_comments = scan_text(comments).redacted_text
        session.add(Approval(draft_id=draft.id, reviewer_id=user.id, decision="approved", comments=safe_comments))
        audit_event(session, user.id, "draft_approved", {"draft_id": draft.id})
        return RedirectResponse("/drafts?notice=Draft%20approved", status_code=303)

    @application.get("/drafts/{draft_id}/export")
    def export_draft(draft_id: int, request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        try:
            draft = authorized_draft(session, user, draft_id)
        except AccessDenied:
            return PlainTextResponse("Access denied", status_code=403)
        if draft is None:
            return PlainTextResponse("Draft not found", status_code=404)
        if draft.status != "approved":
            return PlainTextResponse("Only Approved drafts can be exported.", status_code=409)
        citations = session.scalars(select(DraftCitation).where(DraftCitation.draft_id == draft.id)).all()
        if not citations:
            return PlainTextResponse("Draft citation check failed.", status_code=409)
        audit_event(session, user.id, "draft_exported", {"draft_id": draft.id})
        return PlainTextResponse(
            f"{draft.content}\n\nSource citations: " + ", ".join(item.chunk_id for item in citations),
            headers={"Content-Disposition": f'attachment; filename="saps-draft-{draft.id}.txt"'},
        )

    @application.get("/admin/engagements", response_class=HTMLResponse)
    def independence_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "partner":
            audit_event(session, user.id, "admin_access_denied", {"page": "independence_controls"})
            return templates.TemplateResponse(request, "error.html", {
                "code": 403, "heading": "Access denied", "message": "Partner access is required for engagement assignment and independence review.",
            }, status_code=403)
        clients = session.scalars(select(Client).order_by(Client.name)).all()
        users = session.scalars(select(User).where(User.is_active.is_(True)).order_by(User.username)).all()
        engagements = session.execute(select(
            Engagement, Client.name, User.username,
        ).join(Client, Client.id == Engagement.client_id).join(User, User.id == Engagement.user_id)
         .where(Engagement.status == "active").order_by(Client.name, Engagement.service_line)).all()
        reviews = session.execute(select(
            IndependenceReview, Client.name, User.username,
        ).join(Client, Client.id == IndependenceReview.client_id)
         .join(User, User.id == IndependenceReview.partner_user_id)
         .order_by(IndependenceReview.created_at.desc())).all()
        return templates.TemplateResponse(request, "independence.html", {
            "user": user, "clients": clients, "users": users,
            "engagements": engagements, "reviews": reviews,
            "error": None, "notice": request.query_params.get("notice"),
        })

    @application.post("/admin/engagements/assign", response_class=HTMLResponse)
    def assign_engagement(
        request: Request, user_id: int = Form(...), client_id: int = Form(...),
        service_line: str = Form(...), session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "partner":
            audit_event(session, user.id, "admin_access_denied", {"action": "assign_engagement"})
            return PlainTextResponse("Partner access required", status_code=403)
        client = session.get(Client, client_id)
        assignee = session.get(User, user_id)
        if client is None or assignee is None or not assignee.is_active or assignee.role == "it_admin" or service_line not in SERVICE_LINES:
            return PlainTextResponse("Invalid engagement assignment", status_code=400)
        existing_lines = set(session.scalars(select(Engagement.service_line).where(
            Engagement.client_id == client_id, Engagement.status == "active",
        )).all())
        conflict = ((service_line == "audit" and any(line != "audit" for line in existing_lines)) or
                    (service_line != "audit" and "audit" in existing_lines))
        if conflict:
            latest_review = session.scalar(select(IndependenceReview).where(
                IndependenceReview.client_id == client_id,
            ).order_by(IndependenceReview.created_at.desc(), IndependenceReview.id.desc()))
            if latest_review is None or latest_review.decision != "cleared":
                audit_event(session, user.id, "independence_assignment_blocked", {
                    "client_id": client_id, "user_id": user_id, "service_line": service_line,
                    "reason": "partner_independence_review_required",
                })
                return templates.TemplateResponse(request, "error.html", {
                    "code": 409, "heading": "Independence review required",
                    "message": "This client has audit and non-audit work. Record a partner independence review before assigning the engagement.",
                }, status_code=409)
        existing = session.scalar(select(Engagement.id).where(
            Engagement.user_id == user_id, Engagement.client_id == client_id,
            Engagement.service_line == service_line,
        ))
        if existing is None:
            session.add(Engagement(user_id=user_id, client_id=client_id, service_line=service_line))
            session.flush()
        audit_event(session, user.id, "engagement_assigned", {
            "client_id": client_id, "user_id": user_id, "service_line": service_line,
        })
        return RedirectResponse("/admin/engagements?notice=Engagement%20assigned", status_code=303)

    @application.post("/admin/engagements/independence-review", response_class=HTMLResponse)
    def record_independence_review(
        request: Request, client_id: int = Form(...), decision: str = Form(...),
        review_text: str = Form(..., min_length=20, max_length=2000),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "partner":
            audit_event(session, user.id, "admin_access_denied", {"action": "record_independence_review"})
            return PlainTextResponse("Partner access required", status_code=403)
        if decision not in {"cleared", "prohibited"} or session.get(Client, client_id) is None:
            return PlainTextResponse("Invalid independence review", status_code=400)
        review_scan = scan_text(review_text)
        if review_scan.findings:
            audit_event(session, user.id, "independence_review_blocked", {
                "client_id": client_id, "categories": review_scan.categories,
            })
            return PlainTextResponse("Review text was blocked by the privacy scanner.", status_code=400)
        review = IndependenceReview(
            client_id=client_id, partner_user_id=user.id, review_text=review_scan.redacted_text,
            decision=decision,
        )
        session.add(review)
        session.flush()
        audit_event(session, user.id, "independence_review_recorded", {
            "review_id": review.id, "client_id": client_id, "decision": decision,
        })
        return RedirectResponse("/admin/engagements?notice=Independence%20review%20recorded", status_code=303)

    @application.get("/admin/users", response_class=HTMLResponse)
    def admin_users_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "it_admin":
            audit_event(session, user.id, "admin_access_denied", {"page": "user_management"})
            return templates.TemplateResponse(request, "error.html", {
                "code": 403, "heading": "Access denied", "message": "IT administrator access is required to manage accounts.",
            }, status_code=403)
        audit_event(session, user.id, "admin_user_list_viewed", {})
        users = session.scalars(select(User).order_by(User.username)).all()
        return templates.TemplateResponse(request, "admin_users.html", {
            "user": user, "users": users, "created_account": None,
            "error": None, "notice": request.query_params.get("notice"),
        })

    @application.post("/admin/users", response_class=HTMLResponse)
    def create_managed_user(
        request: Request, username: str = Form(..., min_length=3, max_length=80),
        role: str = Form(...), session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "it_admin":
            audit_event(session, user.id, "admin_access_denied", {"action": "create_user"})
            return PlainTextResponse("IT administrator access required", status_code=403)
        username = username.strip()
        roles = {"partner", "audit_staff", "accounting_staff", "cosec_staff", "it_admin"}
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", username) or role not in roles:
            return PlainTextResponse("Choose a valid username and role.", status_code=400)
        if session.scalar(select(User.id).where(User.username == username)) is not None:
            return PlainTextResponse("That username is already in use.", status_code=409)
        password = secrets.token_urlsafe(18)
        totp_secret = pyotp.random_base32()
        created = User(
            username=username, role=role, password_hash=hash_password(password),
            totp_secret=totp_secret, is_active=True,
        )
        session.add(created)
        session.flush()
        audit_event(session, user.id, "user_created", {"user_id": created.id, "username": username, "role": role})
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SAPS Local Lab")
        return templates.TemplateResponse(request, "admin_users.html", {
            "user": user, "users": session.scalars(select(User).order_by(User.username)).all(),
            "created_account": {"username": username, "password": password,
                                "totp_secret": totp_secret, "uri": uri},
            "error": None, "notice": None,
        })

    @application.post("/admin/users/{target_user_id}/status")
    def set_managed_user_status(
        target_user_id: int, request: Request, is_active: bool = Form(...),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "it_admin":
            audit_event(session, user.id, "admin_access_denied", {"action": "change_user_status"})
            return PlainTextResponse("IT administrator access required", status_code=403)
        if target_user_id == user.id:
            return PlainTextResponse("You cannot change your own account status.", status_code=400)
        target = session.get(User, target_user_id)
        if target is None:
            return PlainTextResponse("User not found", status_code=404)
        target.is_active = is_active
        audit_event(session, user.id, "user_status_changed", {
            "user_id": target.id, "is_active": target.is_active,
        })
        return RedirectResponse("/admin/users?notice=Account%20status%20updated", status_code=303)

    @application.get("/admin/logs", response_class=HTMLResponse)
    def admin_logs_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role != "it_admin":
            audit_event(session, user.id, "admin_access_denied", {"page": "system_logs"})
            return templates.TemplateResponse(request, "error.html", {
                "code": 403, "heading": "Access denied", "message": "IT administrator access is required to view system logs.",
            }, status_code=403)
        audit_event(session, user.id, "admin_system_logs_viewed", {"limit": 250})
        logs = session.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(250)).all()
        valid, chain_message = verify_audit_chain(session)
        return templates.TemplateResponse(request, "admin_logs.html", {
            "user": user, "logs": logs, "chain_valid": valid,
            "chain_message": chain_message,
        })

    @application.get("/admin/deletion", response_class=HTMLResponse)
    def admin_deletion_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role not in {"partner", "it_admin"}:
            audit_event(session, user.id, "admin_access_denied", {"page": "secure_deletion"})
            return templates.TemplateResponse(request, "error.html", {
                "code": 403, "heading": "Access denied", "message": "Partner or IT administrator access is required for secure deletion.",
            }, status_code=403)
        audit_event(session, user.id, "admin_deletion_page_viewed", {})
        clients = session.scalars(select(Client).where(Client.deleted_at.is_(None)).order_by(Client.name)).all()
        return templates.TemplateResponse(request, "admin_deletion.html", {
            "user": user, "clients": clients, "deleted": request.query_params.get("deleted"),
            "error": None,
        })

    @application.post("/admin/client-deletion", response_class=HTMLResponse)
    def delete_client_route(
        request: Request, client_id: int = Form(...), confirmation: str = Form(..., max_length=32),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if user.role not in {"partner", "it_admin"}:
            audit_event(session, user.id, "admin_access_denied", {"action": "secure_delete_client"})
            return PlainTextResponse("Partner or IT administrator access required", status_code=403)
        client = session.get(Client, client_id)
        if client is None or client.deleted_at is not None:
            return PlainTextResponse("Client not found or already deleted", status_code=404)
        if confirmation != "DELETE":
            audit_event(session, user.id, "client_deletion_denied", {
                "client_id": client_id, "reason": "confirmation_mismatch",
            })
            return PlainTextResponse("Type DELETE to confirm client data removal.", status_code=400)
        secure_delete_client(session, storage_root, client_id, user.id, local_vectors)
        return RedirectResponse("/admin/deletion?deleted=Client%20data%20removed", status_code=303)

    @application.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @application.get("/search", response_class=HTMLResponse)
    def search_page(request: Request, session: Session = Depends(db_session)):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(
            request, "search.html", {
                "user": user,
                "choices": user_engagement_choices(session, user.id),
                "result": None,
                "error": None,
                "saved_draft": None,
            }
        )

    @application.post("/search", response_class=HTMLResponse)
    def search(
        request: Request,
        client_service: str = Form(..., max_length=64),
        prompt: str = Form(..., max_length=4000),
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        try:
            client_text, service_line = client_service.split(":", maxsplit=1)
            client_id = int(client_text)
        except (ValueError, TypeError):
            client_id, service_line = 0, ""

        try:
            result = retrieval_service.chat(session, user.id, client_id, service_line, prompt)
            draft = save_ai_draft(session, user, client_id, service_line, "local_search_answer", result)
            return templates.TemplateResponse(request, "search.html", {
                "user": user,
                "choices": user_engagement_choices(session, user.id),
                "result": result,
                "error": None,
                "saved_draft": draft,
                "selected_client_service": client_service,
                "submitted_prompt": prompt,
            })
        except AccessDenied:
            error, status_code = "Access denied: you are not assigned to that client and service line.", 403
        except CrossScopeCanary:
            error, status_code = "Access denied: a canary from another client cannot be requested from this workspace.", 403
        except PromptBlocked as blocked:
            categories = ", ".join(category.replace("_", " ") for category in blocked.categories)
            error, status_code = f"Prompt blocked by the privacy scanner ({categories}). Remove sensitive values and try again.", 400
        except ValueError as exc:
            error, status_code = str(exc), 422
        except Exception as exc:
            session.add(AuditLog(
                actor_user_id=user.id,
                event_type="local_generation_failed",
                metadata_json=json.dumps({"client_id": client_id, "service_line": service_line,
                                          "error_type": type(exc).__name__}),
            ))
            session.commit()
            error, status_code = "Local retrieval or generation is unavailable. Check that Ollama is running with both configured models.", 503
        return templates.TemplateResponse(request, "search.html", {
            "user": user,
            "choices": user_engagement_choices(session, user.id),
            "result": None,
            "error": error,
            "saved_draft": None,
            "selected_client_service": client_service,
            "submitted_prompt": "",
        }, status_code=status_code)

    @application.get("/documents/{document_id}", response_class=HTMLResponse)
    def document_view(
        document_id: int,
        request: Request,
        client_id: int,
        service_line: str,
        session: Session = Depends(db_session),
    ):
        user = current_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        try:
            found = retrieval_service.document_by_id(
                session, user.id, client_id, service_line, document_id
            )
        except AccessDenied:
            return templates.TemplateResponse(request, "error.html", {
                "code": 403,
                "heading": "Access denied",
                "message": "You do not have an active engagement for this client and service line.",
            }, status_code=403)
        if found is None:
            return templates.TemplateResponse(request, "error.html", {
                "code": 404,
                "heading": "Document not found",
                "message": "No matching document is available in this assigned workspace.",
            }, status_code=404)
        document, content = found
        return templates.TemplateResponse(request, "document_view.html", {
            "user": user,
            "document": document,
            "content": content,
        })

    return application


app = create_app()
