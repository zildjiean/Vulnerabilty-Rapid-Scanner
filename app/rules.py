"""Version-match rules: flag inventory services whose product matches a regex and whose version
satisfies a constraint. Lets the operator react to a new 0-day before any nuclei template exists."""
from __future__ import annotations

import re

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from .db import Campaign, Rule, RuleMatch, Service, utcnow
from .version_compare import check_clauses, parse_constraint

# Campaigns waiting for review (0-day watch drafts) or turned down: their rules never produce issues.
UNREVIEWED = ("draft", "dismissed")


def validate_rule(product_pattern: str, version_constraint: str) -> str | None:
    try:
        re.compile(product_pattern)
    except re.error as e:
        return f"Invalid regex: {e}"
    try:
        parse_constraint(version_constraint)
    except ValueError as e:
        return str(e)
    return None


def _service_version(svc: Service) -> str:
    if svc.version:
        return svc.version
    if svc.cpe and svc.cpe.count(":") >= 4:
        return svc.cpe.split(":")[4]
    return ""


def evaluate_rules(db: Session) -> int:
    unreviewed = select(Campaign.id).where(Campaign.status.in_(UNREVIEWED))
    rules = list(db.scalars(select(Rule).where(Rule.enabled.is_(True),
                                               or_(Rule.campaign_id.is_(None), Rule.campaign_id.not_in(unreviewed)))))
    services = list(db.scalars(select(Service)))
    db.execute(delete(RuleMatch))
    now = utcnow()
    count = 0
    for rule in rules:
        try:
            pattern = re.compile(rule.product_pattern, re.IGNORECASE)
            clauses = parse_constraint(rule.version_constraint)
        except (re.error, ValueError):
            continue
        for svc in services:
            haystack = " ".join(x for x in (svc.product, svc.service_name, svc.cpe) if x)
            if not pattern.search(haystack):
                continue
            if check_clauses(_service_version(svc), clauses):
                db.add(RuleMatch(rule_id=rule.id, service_id=svc.id, evaluated_at=now))
                count += 1
    db.flush()
    from .issues import sync_rule_issues  # local import: issues imports rule models
    sync_rule_issues(db)
    return count


def seed_example_rule(db: Session) -> None:
    if db.scalar(select(Rule).limit(1)) is not None:
        return
    db.add(Rule(
        name="Example: PHP < 8.3.15 (CVE-2026-109619 use-after-free)",
        product_pattern=r"php",
        version_constraint="< 8.3.15",
        cve_id="CVE-2026-109619",
        severity="critical",
        description="Example rule shipped disabled. Enable it, or edit it when a new PHP 0-day drops.",
        enabled=False,
    ))
    db.commit()
