"""Role-based access control: roles, permissions and the FastAPI / Jinja helpers that enforce them."""
from __future__ import annotations

from fastapi import HTTPException, Request

ROLES = ("admin", "analyst", "viewer")
ROLE_LABELS = {"admin": "Admin", "analyst": "Analyst", "viewer": "Viewer"}
ROLE_DESCRIPTIONS = {
    "admin": "Everything, including updates, user management and the audit log.",
    "analyst": "Run scans, triage issues, manage inventory, version rules and templates.",
    "viewer": "Read-only access to every page.",
}

PERMISSIONS = {
    "view": "Read every page, job log, finding and inventory row",
    "scan.run": "Start nmap / nuclei scans and cancel jobs",
    "inventory.manage": "Delete inventory services or clear the inventory",
    "rules.manage": "Create, edit, toggle, delete and evaluate version rules",
    "templates.manage": "Upload, pull, delete and reindex nuclei templates",
    "issues.manage": "Triage issues: change status, assign, change severity, comment",
    "campaigns.manage": "Create and run 0-day campaigns: intel, version rules, templates",
    "scopes.manage": "Define scopes (asset groups, owners, criticality) and scheduled scans",
    "system.update": "Update nmap, nuclei and the nuclei templates",
    "users.manage": "Create, edit, deactivate and delete users",
    "audit.view": "Read and export the audit log",
    "settings.manage": "Change platform settings such as remediation SLAs",
    "integrations.manage": "Configure notification channels, rules and ticketing integrations",
    "ai.use": "Ask the AI assistant: drafts, explanations, triage, search, summaries",
    "ai.manage": "Configure AI providers and API keys, see AI usage",
}

_ANALYST = {"view", "scan.run", "inventory.manage", "rules.manage", "templates.manage", "issues.manage",
            "campaigns.manage", "scopes.manage", "ai.use"}
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset(PERMISSIONS),
    "analyst": frozenset(_ANALYST),
    "viewer": frozenset({"view"}),
}


def has_perm(user, perm: str) -> bool:
    """True when ``user`` is active and its role grants ``perm``. Unknown permissions raise KeyError."""
    if perm not in PERMISSIONS:
        raise KeyError(perm)
    if user is None or not getattr(user, "is_active", False):
        return False
    return perm in ROLE_PERMISSIONS.get(getattr(user, "role", ""), frozenset())


class Forbidden(HTTPException):
    def __init__(self, perm: str):
        super().__init__(status_code=403, detail=perm)
        self.perm = perm


def require(perm: str):
    """FastAPI dependency factory: ``dependencies=[Depends(require("scan.run"))]``."""
    if perm not in PERMISSIONS:
        raise KeyError(perm)

    def _dep(request: Request) -> None:
        if not has_perm(getattr(request.state, "user", None), perm):
            raise Forbidden(perm)

    _dep.__name__ = f"require_{perm.replace('.', '_')}"
    return _dep
