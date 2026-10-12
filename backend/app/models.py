"""Database schema. Mirrors sql/schema.postgres.sql and the Alembic migrations (PostgreSQL / Supabase).

Conventions: integer surrogate keys, UTC DATETIME columns, foreign keys with explicit
delete policies, and indexes for every common filter. Raw passwords, tokens and bytecode
are never stored in audit_logs or usage_events.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base, utcnow

SCAN_STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role in ('user','admin')", name="ck_users_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(254), unique=True)   # stored lowercase
    password_hash: Mapped[str] = mapped_column(String(255))        # Argon2id
    role: Mapped[str] = mapped_column(String(10), default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class UserSession(Base):
    """Server-side session. Only an HMAC of the random cookie token is stored."""

    __tablename__ = "user_sessions"
    __table_args__ = (Index("ix_user_sessions_user", "user_id"), Index("ix_user_sessions_expires", "expires_at"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped[User] = relationship(lazy="joined")


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("owner_user_id", "project_name", name="uq_projects_owner_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    project_name: Mapped[str] = mapped_column(String(120))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class UploadedFile(Base):
    """A stored bytecode file. Content lives on disk under a server-generated key.

    Deletion is a hard delete (row + stored file); scans keep their history because
    scans.uploaded_file_id is SET NULL, and scans.target_identifier keeps the hash.
    """

    __tablename__ = "uploaded_files"
    __table_args__ = (
        Index("ix_files_owner_created", "owner_user_id", "created_at"),
        Index("ix_files_hash", "file_hash"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    original_filename: Mapped[str] = mapped_column(String(255))     # sanitized display name
    generated_storage_key: Mapped[str] = mapped_column(String(64), unique=True)
    file_size: Mapped[int] = mapped_column(Integer)                  # bytecode bytes
    file_hash: Mapped[str] = mapped_column(String(64))               # SHA-256 of the bytecode
    detected_input_type: Mapped[str] = mapped_column(String(30))     # hex_text | raw_binary | pasted_hex
    upload_status: Mapped[str] = mapped_column(String(20), default="stored")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)  # reserved; hard delete is used


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("scan_status in ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED')", name="ck_scans_status"),
        Index("ix_scans_owner_created", "owner_user_id", "created_at"),
        Index("ix_scans_owner_status", "owner_user_id", "scan_status"),
        Index("ix_scans_file", "uploaded_file_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    uploaded_file_id: Mapped[Optional[int]] = mapped_column(ForeignKey("uploaded_files.id", ondelete="SET NULL"), nullable=True)
    scan_type: Mapped[str] = mapped_column(String(30), default="bytecode")
    target_identifier: Mapped[str] = mapped_column(String(80))       # sha256 of the bytecode
    target_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # filename at scan time
    network_name: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scan_status: Mapped[str] = mapped_column(String(12), default="QUEUED")
    run_decompiler: Mapped[bool] = mapped_column(Boolean, default=True)
    run_mythril: Mapped[bool] = mapped_column(Boolean, default=True)
    input_bytes: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    analyzer_version: Mapped[str] = mapped_column(String(40))
    error_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True, order_by="Vulnerability.id"
    )
    reports: Mapped[list["ScanReport"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_scan", "scan_id"),
        Index("ix_vuln_category_severity", "category", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(String(200))
    swc_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    source: Mapped[str] = mapped_column(String(20))                  # mythril | heuristic
    severity: Mapped[str] = mapped_column(String(15))
    confidence_label: Mapped[str] = mapped_column(String(20))        # tool_reported | heuristic
    # corroborated | symbolically_feasible | heuristic
    verification_status: Mapped[str] = mapped_column(String(30))
    reentrancy_related: Mapped[bool] = mapped_column(Boolean, default=False)
    program_counter: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    opcode_evidence: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScanReport(Base):
    __tablename__ = "scan_reports"
    __table_args__ = (Index("ix_reports_scan", "scan_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    report_kind: Mapped[str] = mapped_column(String(30), default="analysis")   # analysis | ai_<kind>
    report_format: Mapped[str] = mapped_column(String(10))                      # json | md
    storage_key: Mapped[str] = mapped_column(String(64), unique=True)
    report_hash: Mapped[str] = mapped_column(String(64))                        # SHA-256 of the stored bytes
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class UsageEvent(Base):
    __tablename__ = "usage_events"
    __table_args__ = (Index("ix_usage_owner_created", "owner_user_id", "created_at"),
                      Index("ix_usage_type", "event_type"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(40))
    resource_type: Mapped[str] = mapped_column(String(30))
    resource_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AIAnalysis(Base):
    __tablename__ = "ai_analysis"
    __table_args__ = (Index("ix_ai_owner_created", "owner_user_id", "created_at"), Index("ix_ai_scan", "scan_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(40))                # "builtin-rules" when no LLM was used
    model_name: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    analysis_type: Mapped[str] = mapped_column(String(30))           # explain | risk | remediation | report | chat
    status: Mapped[str] = mapped_column(String(15))                  # completed | failed
    result_summary: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    result_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_usage: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    prompt_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_timestamp", "timestamp"), Index("ix_audit_actor", "actor_user_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    resource_type: Mapped[str] = mapped_column(String(30))
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(15))                 # success | denied | failure
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    request_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
