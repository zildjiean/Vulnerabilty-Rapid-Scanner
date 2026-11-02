"""Get started checklist: the first things to do on a new install, shown on the Dashboard until they are done or
the user dismisses the card. Each step is shown only to users whose role may act on it."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .authz import has_perm
from .db import Issue, Job, NotificationChannel, Schedule, TemplateIndex


@dataclass
class Step:
    key: str
    title: str
    help: str
    href: str
    action: str
    done: bool
    allowed: bool


def _exists(db: Session, stmt) -> bool:
    return db.scalar(stmt.limit(1)) is not None


# key, title, help, link, button label, permission to act, "done" query
_STEPS = [
    ("templates", "Download the vulnerability checks",
     "Get the latest nuclei templates so scans know what to look for.", "/updates", "Update templates",
     "system.update", lambda: select(TemplateIndex.id)),
    ("scan", "Run your first scan",
     "Quick scan finds open services and checks them for known vulnerabilities in one go.", "/quick", "Quick scan",
     "scan.run", lambda: select(Job.id).where(Job.kind == "nmap", Job.status == "done")),
    ("triage", "Review an issue",
     "Open an issue and assign it, start work on it, or mark it as accepted or a false positive.", "/issues",
     "Open issues", "issues.manage", lambda: select(Issue.id).where(Issue.status != "new")),
    ("schedule", "Schedule regular scans",
     "Re-scan a scope automatically so new exposure shows up without anyone remembering to look.", "/schedules",
     "Add a schedule", "scopes.manage", lambda: select(Schedule.id)),
    ("notify", "Get notified",
     "Send new critical issues to Slack, Microsoft Teams, email or a webhook.", "/integrations", "Add a channel",
     "integrations.manage", lambda: select(NotificationChannel.id)),
]


def checklist(db: Session, user) -> list[Step]:
    return [Step(key=key, title=title, help=help_, href=href, action=action, done=_exists(db, query()),
                 allowed=has_perm(user, perm))
            for key, title, help_, href, action, perm, query in _STEPS]


def visible(steps: list[Step]) -> list[Step]:
    return [s for s in steps if s.allowed]


def card(db: Session, user) -> list[Step] | None:
    """The steps to show in the Get started card, or None when it is hidden: dismissed, nothing the user may act
    on, or everything they may act on is done."""
    if user is None or getattr(user, "onboarding_dismissed_at", None) is not None:
        return None
    steps = visible(checklist(db, user))
    if not steps or all(s.done for s in steps):
        return None
    return steps


def show_card(db: Session, user) -> bool:
    return card(db, user) is not None
