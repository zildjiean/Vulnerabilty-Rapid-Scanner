from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event,
                        inspect, text)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | analyst | viewer
    display_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    session_version: Mapped[int] = mapped_column(Integer, default=0)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), default="")  # copied so rows survive user deletion
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(512), default="")
    details: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    ip: Mapped[str] = mapped_column(String(64), default="")


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # nmap | nuclei | update
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed|cancelled
    command: Mapped[str] = mapped_column(Text, default="")
    log: Mapped[str] = mapped_column(Text, default="")
    output: Mapped[str] = mapped_column(Text, default="")
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def duration(self) -> int | None:
        if self.started_at is None:
            return None
        end = self.finished_at or utcnow()
        return int((end - self.started_at).total_seconds())


class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    services: Mapped[list["Service"]] = relationship(back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")
    service_name: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(255), default="")
    extra_info: Mapped[str] = mapped_column(String(255), default="")
    cpe: Mapped[str] = mapped_column(String(255), default="")
    tunnel: Mapped[str] = mapped_column(String(16), default="")
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host: Mapped["Host"] = relationship(back_populates="services")
    rule_matches: Mapped[list["RuleMatch"]] = relationship(back_populates="service", cascade="all, delete-orphan")


class TemplateIndex(Base):
    __tablename__ = "template_index"
    id: Mapped[int] = mapped_column(primary_key=True)
    template_id: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(String(1024), unique=True)
    name: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    tags: Mapped[str] = mapped_column(Text, default="")
    cve_ids: Mapped[str] = mapped_column(String(512), default="")
    source: Mapped[str] = mapped_column(String(16), default="official")  # official | custom
    indexed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    template_id: Mapped[str] = mapped_column(String(255), default="")
    template_name: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    host: Mapped[str] = mapped_column(String(512), default="")
    matched_at: Mapped[str] = mapped_column(Text, default="")
    type: Mapped[str] = mapped_column(String(32), default="")
    extracted: Mapped[str] = mapped_column(Text, default="")
    raw_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    product_pattern: Mapped[str] = mapped_column(String(255))
    version_constraint: Mapped[str] = mapped_column(String(255))
    cve_id: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    matches: Mapped[list["RuleMatch"]] = relationship(back_populates="rule", cascade="all, delete-orphan")


class RuleMatch(Base):
    __tablename__ = "rule_matches"
    __table_args__ = (UniqueConstraint("rule_id", "service_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"))
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    rule: Mapped["Rule"] = relationship(back_populates="matches")
    service: Mapped["Service"] = relationship(back_populates="rule_matches")


def make_engine(url: str) -> Engine:
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)


# Columns added after the first release: (table, column, DDL). Existing rows get the DDL default,
# so users created before roles existed become admins (they were the only, all-powerful account).
_ADDED_COLUMNS = [
    ("users", "role", "VARCHAR(16) NOT NULL DEFAULT 'admin'"),
    ("users", "display_name", "VARCHAR(128) NOT NULL DEFAULT ''"),
    ("users", "email", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("users", "is_active", "BOOLEAN NOT NULL DEFAULT 1"),
    ("users", "last_login_at", "DATETIME"),
    ("users", "session_version", "INTEGER NOT NULL DEFAULT 0"),
]


def migrate_db(engine: Engine) -> None:
    """Add columns introduced after the initial schema to an existing database (idempotent)."""
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, column, ddl in _ADDED_COLUMNS:
            if table not in tables:
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    migrate_db(engine)
