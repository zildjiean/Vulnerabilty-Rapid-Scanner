"""Guided tours: short spotlight walkthroughs that point at menus and controls (app/static/app.js runs them).

A tour only points: it never clicks, submits or fills anything. Each step names a page (``path``) and the
``data-tour="..."`` value of the element to highlight there (``""`` = a centred note with no highlight). ``@follow``
as a path means "the page the previous step's target links to" (e.g. the first issue in the list).

Visibility follows the sidebar: a step that points at a sidebar item (``nav-<item key>``) or group header
(``nav-group-<group key>``) is dropped when the user's sidebar does not show it (see ``navigation.nav_items``), and a
step or tour whose ``perm`` the user lacks is dropped too. Visibility never grants access: pages check their own.

Text is English source; ``payload()`` translates it with ``t()`` for the language being rendered (Thai in
``app/i18n_th.py``).
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .authz import has_perm
from .i18n import t

FOLLOW = "@follow"


@dataclass(frozen=True)
class Step:
    path: str
    target: str
    title: str
    body: str
    perm: str = "view"


@dataclass(frozen=True)
class Tour:
    key: str
    title: str
    summary: str
    perm: str
    steps: tuple[Step, ...]


TOURS: tuple[Tour, ...] = (
    Tour("menus", "Get to know the menus", "A quick look at where everything is.", "view", (
        Step("/", "", "Welcome to 0-Day Rapid Scanner",
             "This tour shows where things are. It only points; it never clicks or changes anything."),
        Step("/", "nav-dashboard", "Dashboard", "Your overview: active issues, overdue work, trends and recent jobs."),
        Step("/", "nav-issues", "Issues", "Every vulnerability found, ordered by risk. Triage, assign and close them here."),
        Step("/", "nav-campaigns", "Campaigns",
             "Track one 0-day across your assets. 0-day watch suggests new campaigns."),
        Step("/", "nav-inventory", "Inventory", "Hosts, ports and services that scans found, and what changed."),
        Step("/", "nav-reports", "Reports", "Executive, scope and campaign reports to share or print."),
        Step("/", "nav-group-scan", "Scanning", "New scan starts a scan; Jobs shows its progress and log."),
        Step("/", "nav-group-system", "System",
             "Updates, API keys and, for admins, users, settings and the audit log."),
        Step("/", "lang-switch", "Language", "Switch between Thai and English. Your choice is saved to your profile."),
        Step("/", "user-chip", "Your profile", "Your details, role, language and menu preferences."),
        Step("/", "guide-button", "Guide", "Reopen tours here at any time."),
    )),
    Tour("first-scan", "Run your first scan", "Start a Quick scan and follow it to the results.", "scan.run", (
        Step("/", "nav-quick", "New scan", "Scans start here. Quick scan is the simplest way."),
        Step("/quick", "quick-targets", "Targets",
             "Enter one IP address, network, range or hostname per line. Only scan systems you are allowed to test."),
        Step("/quick", "quick-level", "How deep",
             "Pick how many ports to check and how thorough the vulnerability checks are."),
        Step("/quick", "quick-start", "Start quick scan", "Nothing runs until you press Start quick scan."),
        Step("/quick", "page-tabs", "More scan types", "Nmap, Nuclei and Discovery give full control for advanced use."),
        Step("/jobs", "nav-jobs", "Jobs", "Every scan runs as a job. Open one to watch its live log."),
        Step("/jobs", "jobs-table", "Job list", "Status, duration and summary of each scan and update."),
        Step("/", "nav-issues", "Issues", "When a scan finishes, results land in Issues."),
    )),
    Tour("triage", "Handle an issue", "Filter issues, open one and decide what to do with it.", "issues.manage", (
        Step("/issues", "issues-filters", "Filters", "Narrow the list by status, severity, owner or text."),
        Step("/issues", "issues-table", "Issue list", "Ordered by risk, highest first. Select rows for bulk actions."),
        Step("/issues", "issue-link", "Open an issue", "Click a title to see its details, evidence and history."),
        Step(FOLLOW, "next-step", "Next step", "The suggested action for the issue's current status."),
        Step(FOLLOW, "issue-status", "Change status",
             "Move the issue along: Triaged, In progress, Fixed. False positive and Accepted risk need a reason."),
        Step(FOLLOW, "issue-verify", "Verify the fix",
             "Re-run the check against the asset to prove the fix, and keep the proof.", perm="scan.run"),
        Step(FOLLOW, "issue-proof", "Proof", "What the scanner sent and received when it found the problem."),
    )),
    Tour("admin", "Set up for your team", "Where to set up scopes, schedules, users and integrations.", "view", (
        Step("/", "nav-scopes", "Scopes", "Group assets with an owner and criticality. Issues inherit them.",
             perm="scopes.manage"),
        Step("/", "nav-schedules", "Schedules", "Re-scan scopes automatically, daily or weekly.", perm="scopes.manage"),
        Step("/", "nav-users", "Users", "Add people and give each a role: Admin, Analyst or Viewer.",
             perm="users.manage"),
        Step("/", "nav-settings", "Settings", "Remediation SLAs and other platform settings.", perm="settings.manage"),
        Step("/", "nav-integrations", "Integrations", "Send new issues to Slack, Microsoft Teams, email or a webhook.",
             perm="integrations.manage"),
        Step("/", "nav-updates", "Updates", "Keep nmap, nuclei and the templates up to date.", perm="system.update"),
        Step("/", "nav-audit", "Audit log", "Who did what, and when.", perm="audit.view"),
    )),
)

_BY_KEY = {tr.key: tr for tr in TOURS}


def get(key: str) -> Tour | None:
    return _BY_KEY.get(key)


def _sidebar_targets(user) -> set[str]:
    from .navigation import nav_items
    groups = nav_items(user)
    return {f"nav-{i.key}" for g in groups for i in g.items} | {f"nav-group-{g.key}" for g in groups}


def available(user) -> list[Tour]:
    """The tours ``user`` may take, each with only the steps they may see (empty tours are dropped)."""
    if user is None or not getattr(user, "is_active", False):
        return []
    shown = _sidebar_targets(user)
    out = []
    for tr in TOURS:
        if not has_perm(user, tr.perm):
            continue
        steps = tuple(s for s in tr.steps if has_perm(user, s.perm)
                      and (not s.target.startswith("nav-") or s.target in shown))
        if steps:
            out.append(replace(tr, steps=steps))
    return out


def done_keys(user) -> set[str]:
    """Known tour keys the user finished (``users.tours_done`` is comma-separated)."""
    raw = getattr(user, "tours_done", "") or ""
    return {k for k in raw.split(",") if k in _BY_KEY}


def payload(user, done: set[str]) -> list[dict]:
    """JSON-ready tours for the page being rendered, translated with t() (current request language)."""
    return [{"key": tr.key, "title": t(tr.title), "summary": t(tr.summary), "done": tr.key in done,
             "steps": [{"path": s.path, "target": s.target, "title": t(s.title), "body": t(s.body)} for s in tr.steps]}
            for tr in available(user)]


def start_href(tour: Tour) -> str:
    """Where a tour starts (Profile -> Start): its first step's page with ?tour=&step=0."""
    path = tour.steps[0].path if tour.steps and tour.steps[0].path != FOLLOW else "/"
    return f"{path}?tour={tour.key}&step=0"


def show_prompt(user) -> bool:
    """The Dashboard "New here?" card: until the user dismisses it, starts a tour or finishes one."""
    return (user is not None and getattr(user, "tour_prompt_dismissed_at", None) is None
            and not done_keys(user) and bool(available(user)))


def strings() -> set[str]:
    """Every English string the tours show (for the catalog checks)."""
    out = set()
    for tr in TOURS:
        out |= {tr.title, tr.summary}
        for s in tr.steps:
            out |= {s.title, s.body}
    return out
