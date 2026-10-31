"""Threat campaigns: one vulnerability's intel, version rules and nuclei templates, and the issues they produce."""
from __future__ import annotations

import json

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .db import Campaign, CampaignTemplate, Host, Issue, Rule, Service, TemplateIndex, utcnow
from .issues import CLOSED, ISSUE_SEVERITIES, SCAN_CONFIRMED, STATUSES
from .rules import UNREVIEWED, evaluate_rules, validate_rule

REMEDIATED = ("fixed", "verified", "false_positive", "accepted_risk")


def severity_from_intel(cvss_severity: str) -> str:
    s = (cvss_severity or "").lower()
    if s in ISSUE_SEVERITIES:
        return s
    return "low" if s == "none" else "high"


def apply_intel(c: Campaign, info: dict, errors: list[str]) -> None:
    c.description = c.description or info.get("description", "")
    c.cvss_score = info.get("cvss_score")
    c.cvss_severity = info.get("cvss_severity", "")
    c.cvss_vector = info.get("cvss_vector", "")
    c.cvss_version = info.get("cvss_version", "")
    c.published_at = info.get("published")
    c.references = json.dumps(info.get("references") or [])
    c.kev = bool(info.get("kev"))
    c.kev_name = info.get("kev_name", "")
    c.kev_date_added = info.get("kev_date_added", "")
    c.kev_due = info.get("kev_due", "")
    c.kev_ransomware = bool(info.get("kev_ransomware"))
    c.kev_action = info.get("kev_action", "")
    c.intel_error = " ".join(errors)
    c.enriched_at = utcnow()


def references(c: Campaign) -> list[str]:
    try:
        refs = json.loads(c.references or "[]")
    except json.JSONDecodeError:
        return []
    return [r for r in refs if isinstance(r, str) and r.startswith(("http://", "https://"))]


def add_rule(db: Session, c: Campaign, product_pattern: str, version_constraint: str) -> Rule:
    product_pattern, version_constraint = product_pattern.strip(), version_constraint.strip()
    err = validate_rule(product_pattern, version_constraint)
    if err:
        raise ValueError(err)
    rule = Rule(name=c.name[:255], product_pattern=product_pattern, version_constraint=version_constraint,
                cve_id=c.cve_id, severity=c.severity, description=f"Campaign: {c.name}",
                enabled=c.status not in UNREVIEWED, campaign_id=c.id)   # a draft's rules wait for Activate
    db.add(rule)
    db.flush()
    if rule.enabled:
        evaluate_rules(db)
    return rule


def remove_rule(db: Session, c: Campaign, rule_id: int) -> Rule | None:
    rule = db.get(Rule, rule_id)
    if rule is None or rule.campaign_id != c.id:
        return None
    db.delete(rule)
    db.flush()
    evaluate_rules(db)
    return rule


def attach_template(db: Session, c: Campaign, path: str) -> CampaignTemplate | None:
    """Attach an indexed template. Returns None if already attached; raises for unknown paths."""
    t = db.scalar(select(TemplateIndex).where(TemplateIndex.path == path))
    if t is None:
        raise ValueError("That template is not in the template index.")
    if db.scalar(select(CampaignTemplate).where(CampaignTemplate.campaign_id == c.id, CampaignTemplate.path == path)):
        return None
    ct = CampaignTemplate(campaign_id=c.id, path=t.path, template_id=t.template_id)
    db.add(ct)
    db.flush()
    return ct


def templates_for_cve(db: Session, cve: str) -> list[TemplateIndex]:
    if not cve:
        return []
    rows = db.scalars(select(TemplateIndex).where(or_(TemplateIndex.cve_ids.ilike(f"%{cve}%"),
                                                      TemplateIndex.template_id.ilike(cve))))
    return sorted(rows, key=lambda t: (t.source != "custom", t.template_id))


def suggested_templates(db: Session, c: Campaign) -> list[TemplateIndex]:
    attached = {t.path for t in c.templates}
    return [t for t in templates_for_cve(db, c.cve_id) if t.path not in attached]


def create_campaign(db: Session, *, name: str, cve_id: str, description: str, severity: str, product_pattern: str,
                    version_constraint: str, attach_templates: bool, intel: tuple[dict, list[str]] | None,
                    created_by: str, status: str = "active") -> Campaign:
    """Validate, create, attach rule + templates and evaluate. Raises ValueError with a user-facing message.
    ``status="draft"`` (0-day watch) creates the campaign for review: its rules stay disabled until activated."""
    if status not in ("active", "draft"):
        raise ValueError("Unknown campaign status.")
    name = name.strip() or cve_id
    if not name:
        raise ValueError("Give the campaign a name or a CVE id.")
    if severity not in ISSUE_SEVERITIES and severity != "auto":
        raise ValueError("Unknown severity.")
    if product_pattern.strip() or version_constraint.strip():
        err = validate_rule(product_pattern.strip(), version_constraint.strip())
        if err:
            raise ValueError(f"Version rule: {err}")
    c = Campaign(name=name[:255], cve_id=cve_id, description=description.strip(), status=status, created_by=created_by,
                 severity=severity if severity != "auto" else "high")
    db.add(c)
    db.flush()
    if intel is not None:
        apply_intel(c, *intel)
        if severity == "auto":
            c.severity = severity_from_intel(c.cvss_severity)
    if attach_templates:
        for t in templates_for_cve(db, cve_id):
            attach_template(db, c, t.path)
    if product_pattern.strip():
        add_rule(db, c, product_pattern, version_constraint)
    db.flush()
    return c


def activate_campaign(db: Session, c: Campaign) -> int:
    """Draft -> active: enable the campaign's rules and evaluate them. Returns the number of rules enabled."""
    if c.status != "draft":
        raise ValueError("Only a draft campaign can be activated.")
    c.status, c.closed_at = "active", None
    rules = list(db.scalars(select(Rule).where(Rule.campaign_id == c.id)))
    for r in rules:
        r.enabled = True
    db.flush()
    evaluate_rules(db)
    return len(rules)


def dismiss_campaign(db: Session, c: Campaign) -> None:
    """Draft -> dismissed: the rules stay disabled and the 0-day watch never drafts this CVE again."""
    if c.status != "draft":
        raise ValueError("Only a draft campaign can be dismissed.")
    c.status = "dismissed"
    for r in db.scalars(select(Rule).where(Rule.campaign_id == c.id)):
        r.enabled = False
    db.flush()


def campaign_issues(db: Session, c: Campaign) -> list[Issue]:
    conds = []
    if c.cve_id:
        conds.append(Issue.vuln_id == c.cve_id)
    rule_ids = list(db.scalars(select(Rule.id).where(Rule.campaign_id == c.id)))
    if rule_ids:
        conds.append(Issue.rule_id.in_(rule_ids))
    template_ids = [t.template_id for t in c.templates if t.template_id]
    if template_ids:
        conds.append(Issue.template_id.in_(template_ids))
    if not conds:
        return []
    return list(db.scalars(select(Issue).where(or_(*conds)).order_by(Issue.asset)))


def campaigns_for_issue(db: Session, issue: Issue) -> list[Campaign]:
    conds = []
    if issue.cve_id:
        conds.append(Campaign.cve_id == issue.cve_id)
    if issue.rule_id:
        rule = db.get(Rule, issue.rule_id)
        if rule and rule.campaign_id:
            conds.append(Campaign.id == rule.campaign_id)
    if issue.template_id:
        conds.append(Campaign.id.in_(select(CampaignTemplate.campaign_id).where(
            CampaignTemplate.template_id == issue.template_id)))
    if not conds:
        return []
    return list(db.scalars(select(Campaign).where(or_(*conds), Campaign.status.not_in(UNREVIEWED))))


def progress(issues: list[Issue]) -> dict:
    counts = {s: 0 for s in STATUSES}
    for i in issues:
        counts[i.status] = counts.get(i.status, 0) + 1
    total = len(issues)
    remediated = sum(counts[s] for s in REMEDIATED)
    return {**counts, "total": total, "remediated": remediated,
            "remediated_pct": round(100 * remediated / total) if total else 0,
            "confirmed": sum(1 for i in issues if i.confidence == "confirmed"),
            "conf_verified": sum(1 for i in issues if i.confidence == "verified"),   # "verified" is the status count
            "suspected": sum(1 for i in issues if i.confidence == "suspected"),
            "scan_confirmed": sum(1 for i in issues if i.confidence in SCAN_CONFIRMED),
            "open": sum(1 for i in issues if i.status in ("new", "triaged", "in_progress"))}


def verify_targets(db: Session, c: Campaign) -> list[str]:
    """nuclei targets for every not-closed campaign issue, built from the inventory service when known."""
    from .routers.inventory import service_to_target  # local import: routers import this module
    out: list[str] = []
    for issue in campaign_issues(db, c):
        if issue.status in CLOSED:
            continue
        svc = None
        if issue.port.isdigit():
            svc = db.scalar(select(Service).join(Host, Host.id == Service.host_id)
                            .where(Host.address == issue.address, Service.port == int(issue.port)))
        target = service_to_target(issue.address, svc) if svc else issue.asset
        if target not in out:
            out.append(target)
    return out
