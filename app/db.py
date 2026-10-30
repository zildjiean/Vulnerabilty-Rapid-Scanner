from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event,
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
    campaign_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    schedule_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

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
    issue_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


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
    campaign_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
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


class Scope(Base):
    """A named group of assets (nmap target syntax) with an owner and a business criticality."""
    __tablename__ = "scopes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    targets: Mapped[str] = mapped_column(Text, default="")
    exclusions: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    owner: Mapped["User | None"] = relationship()


class Issue(Base):
    """One vulnerability on one asset (address:port), deduplicated across scans and rule evaluations."""
    __tablename__ = "issues"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(600), unique=True)  # "<asset>|<vuln_id>"
    asset: Mapped[str] = mapped_column(String(300), index=True)
    address: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[str] = mapped_column(String(8), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    vuln_id: Mapped[str] = mapped_column(String(255), default="")
    cve_id: Mapped[str] = mapped_column(String(64), default="")
    template_id: Mapped[str] = mapped_column(String(255), default="")
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    severity_overridden: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[str] = mapped_column(String(16), default="suspected")  # suspected | confirmed
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status_changed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    scope_id: Mapped[int | None] = mapped_column(ForeignKey("scopes.id", ondelete="SET NULL"), nullable=True, index=True)
    overdue_notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reverify_requested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    reverify_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assignee: Mapped["User | None"] = relationship()
    scope: Mapped["Scope | None"] = relationship()
    events: Mapped[list["IssueEvent"]] = relationship(back_populates="issue", cascade="all, delete-orphan",
                                                      order_by="IssueEvent.id")


class IssueEvent(Base):
    __tablename__ = "issue_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    issue_id: Mapped[int] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="system")
    kind: Mapped[str] = mapped_column(String(24))
    from_value: Mapped[str] = mapped_column(String(255), default="")
    to_value: Mapped[str] = mapped_column(String(255), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    issue: Mapped["Issue"] = relationship(back_populates="events")


class Campaign(Base):
    """Response to one vulnerability: intel + version rules + nuclei templates + the issues they produce."""
    __tablename__ = "campaigns"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    cve_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)  # active | closed
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str] = mapped_column(String(16), default="")
    cvss_vector: Mapped[str] = mapped_column(String(255), default="")
    cvss_version: Mapped[str] = mapped_column(String(8), default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    references: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of URLs
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_name: Mapped[str] = mapped_column(String(255), default="")
    kev_date_added: Mapped[str] = mapped_column(String(16), default="")
    kev_due: Mapped[str] = mapped_column(String(16), default="")
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_action: Mapped[str] = mapped_column(Text, default="")
    intel_error: Mapped[str] = mapped_column(Text, default="")
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    templates: Mapped[list["CampaignTemplate"]] = relationship(back_populates="campaign", cascade="all, delete-orphan",
                                                               order_by="CampaignTemplate.template_id")


class CampaignTemplate(Base):
    __tablename__ = "campaign_templates"
    __table_args__ = (UniqueConstraint("campaign_id", "path"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    template_id: Mapped[str] = mapped_column(String(255), default="")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    campaign: Mapped["Campaign"] = relationship(back_populates="templates")


class Schedule(Base):
    """A recurring job: nmap discovery or nuclei scan of a scope, or verification of active campaigns."""
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(24))  # nmap | nuclei | campaign_verify
    scope_id: Mapped[int | None] = mapped_column(ForeignKey("scopes.id", ondelete="CASCADE"), nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    frequency: Mapped[str] = mapped_column(String(16), default="daily")  # interval | daily | weekly
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    time_of_day: Mapped[str] = mapped_column(String(5), default="02:00")
    weekday: Mapped[int] = mapped_column(Integer, default=0)  # 0 = Monday
    config: Mapped[str] = mapped_column(Text, default="{}")
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="")  # started | skipped | error
    last_message: Mapped[str] = mapped_column(Text, default="")
    last_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    scope: Mapped["Scope | None"] = relationship()


class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16))  # webhook | slack | teams | email | jira | gitlab
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[str] = mapped_column(Text, default="{}")
    secret: Mapped[str] = mapped_column(Text, default="")  # Fernet token (app/secretbox.py)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_message: Mapped[str] = mapped_column(Text, default="")
    rules: Mapped[list["NotificationRule"]] = relationship(back_populates="channel", cascade="all, delete-orphan",
                                                           order_by="NotificationRule.id")


class NotificationRule(Base):
    __tablename__ = "notification_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True)
    events: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of event names
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    scope_id: Mapped[int | None] = mapped_column(ForeignKey("scopes.id", ondelete="SET NULL"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    channel: Mapped["NotificationChannel"] = relationship(back_populates="rules")
    scope: Mapped["Scope | None"] = relationship()


class Delivery(Base):
    """Outbox row: one message or ticket operation for one channel, retried until sent or failed."""
    __tablename__ = "notification_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True)
    event: Mapped[str] = mapped_column(String(48))
    title: Mapped[str] = mapped_column(String(512), default="")
    payload: Mapped[str] = mapped_column(Text, default="{}")
    issue_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    channel: Mapped["NotificationChannel"] = relationship()


class IssueTicket(Base):
    __tablename__ = "issue_tickets"
    __table_args__ = (UniqueConstraint("issue_id", "channel_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    issue_id: Mapped[int] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(64), default="")
    external_id: Mapped[str] = mapped_column(String(64), default="")
    url: Mapped[str] = mapped_column(String(1024), default="")
    state: Mapped[str] = mapped_column(String(16), default="open")  # open | closed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    channel: Mapped["NotificationChannel"] = relationship()


class ApiKey(Base):
    """REST API credential. Only a SHA-256 hash is stored; the key acts with ``role`` (never above its owner)."""
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_ip: Mapped[str] = mapped_column(String(64), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    owner: Mapped["User"] = relationship()


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


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
    ("findings", "issue_id", "INTEGER"),
    ("rules", "campaign_id", "INTEGER"),
    ("jobs", "campaign_id", "INTEGER"),
    ("issues", "scope_id", "INTEGER"),
    ("jobs", "schedule_id", "INTEGER"),
    ("issues", "overdue_notified_at", "DATETIME"),
    ("issues", "reverify_requested_at", "DATETIME"),
    ("issues", "reverify_job_id", "INTEGER"),
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
