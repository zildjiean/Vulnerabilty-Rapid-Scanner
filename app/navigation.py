"""The one navigation structure: sidebar groups -> items -> page tabs, filtered per user.

``base.html`` renders the sidebar from :func:`nav_items` and the page tab bar from :func:`page_tabs_for`, so the menu
and the tabs cannot drift apart. Visibility never grants access: every page still checks its own permission.

Rules (the "focused" menu):
- an item / tab is shown only when the user may open it (``perm``, default ``view``);
- an item / tab whose purpose is starting work (``act``, e.g. ``scan.run`` for New scan) is hidden without that
  permission;
- read-only users (no permission beyond ``view``) see only the core group.
``show_all_menus`` (Profile) drops the last two rules: every page the user may open is listed.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .authz import PERMISSIONS, has_perm


@dataclass(frozen=True)
class Tab:
    label: str
    href: str
    perm: str = "view"
    act: str | None = None

    @property
    def path(self) -> str:
        return urlsplit(self.href).path


@dataclass(frozen=True)
class Item:
    key: str
    label: str
    href: str
    icon: str
    active: tuple[str, ...] = ()
    tabs: tuple[Tab, ...] = ()
    perm: str = "view"
    act: str | None = None

    def __post_init__(self):
        if not self.active:
            object.__setattr__(self, "active", (self.key,))


@dataclass(frozen=True)
class Group:
    key: str
    label: str
    items: tuple[Item, ...]
    closed_by_default: bool = False

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(k for i in self.items for k in i.active)


CORE = "core"
_SCAN = "scan.run"

NAV: tuple[Group, ...] = (
    Group(CORE, "", (
        Item("dashboard", "Dashboard", "/", "dashboard"),
        Item("issues", "Issues", "/issues", "target", ("issues", "findings"),
             (Tab("Issues", "/issues"), Tab("Raw findings", "/findings"))),
        Item("campaigns", "Campaigns", "/campaigns", "flag", ("campaigns", "watch"),
             (Tab("Campaigns", "/campaigns"), Tab("0-day watch", "/watch"))),
        Item("inventory", "Inventory", "/inventory", "server", ("inventory", "changes"),
             (Tab("Inventory", "/inventory"), Tab("Changes", "/changes"), Tab("Discovered", "/discovery#assets"))),
        Item("reports", "Reports", "/reports", "file"),
    )),
    Group("scan", "Scanning", (
        Item("quick", "New scan", "/quick", "zap", ("quick", "nmap", "nuclei", "discovery"),
             (Tab("Quick", "/quick", act=_SCAN), Tab("Nmap", "/nmap", act=_SCAN), Tab("Nuclei", "/nuclei", act=_SCAN),
              Tab("Discovery", "/discovery", act=_SCAN)), act=_SCAN),
        Item("jobs", "Jobs", "/jobs", "activity"),
    )),
    Group("automation", "Automation", (
        Item("scopes", "Scopes", "/scopes", "layers"),
        Item("schedules", "Schedules", "/schedules", "clock"),
    )),
    Group("library", "Detection library", (
        Item("templates", "Templates & rules", "/templates", "book", ("templates", "rules"),
             (Tab("Templates", "/templates"), Tab("Version rules", "/rules"))),
    )),
    Group("system", "System", (
        Item("updates", "Updates", "/updates", "refresh", act="system.update"),
        Item("api", "API", "/api-keys", "key"),
        Item("users", "Users", "/users", "users", perm="users.manage"),
        Item("settings", "Settings", "/settings", "sliders", perm="settings.manage"),
        Item("integrations", "Integrations", "/integrations", "link", perm="integrations.manage"),
        Item("ai", "AI assistant", "/ai", "spark", perm="ai.manage"),
        Item("audit", "Audit log", "/audit", "scroll", perm="audit.view"),
    ), closed_by_default=True),
)


def _read_only(user) -> bool:
    return not any(has_perm(user, p) for p in PERMISSIONS if p != "view")


def _shown(user, perm: str, act: str | None, show_all: bool) -> bool:
    return has_perm(user, perm) and (show_all or act is None or has_perm(user, act))


def nav_items(user) -> list[Group]:
    """The sidebar for ``user``: groups with only the items (and each item's tabs) the user should see."""
    if user is None or not getattr(user, "is_active", False):
        return []
    show_all = bool(getattr(user, "show_all_menus", False))
    read_only = _read_only(user)
    out = []
    for g in NAV:
        if read_only and not show_all and g.key != CORE:
            continue
        items = tuple(replace(i, tabs=tuple(t for t in i.tabs if _shown(user, t.perm, t.act, show_all)))
                      for i in g.items if _shown(user, i.perm, i.act, show_all))
        if items:
            out.append(replace(g, items=items))
    return out


def _item_for(active: str) -> tuple[Group, Item] | tuple[None, None]:
    for g in NAV:
        for i in g.items:
            if active in i.active:
                return g, i
    return None, None


def section_for(active: str) -> str:
    """Breadcrumb section: the group label for grouped items, the item label for core items."""
    g, i = _item_for(active)
    if i is None:
        return ""
    return i.label if g.key == CORE else g.label


@dataclass(frozen=True)
class PageTabs:
    label: str
    tabs: tuple[Tab, ...]
    current: str          # href of the current tab


def resolve_page(user, active: str, path: str) -> tuple[str, PageTabs | None]:
    """(sidebar ``active`` key, tab bar or None) for the page at ``path`` whose own key is ``active``."""
    _, base = _item_for(active)
    if base is None:
        return active, None
    visible = {i.key: i for g in nav_items(user) for i in g.items}
    if base.key in visible:
        tabs = visible[base.key].tabs
    else:
        # The page's own item is hidden from this user's menu (e.g. a viewer on /discovery, reached from the
        # Inventory "Discovered" tab): show the visible item that links here instead, with that tab current.
        alt = next((i for i in visible.values() if any(t.path == path for t in i.tabs)), None)
        if alt is not None:
            cur = next(t for t in alt.tabs if t.path == path)
            return alt.active[0], (PageTabs(alt.label, alt.tabs, cur.href) if len(alt.tabs) >= 2 else None)
        show_all = bool(getattr(user, "show_all_menus", False))
        tabs = tuple(t for t in base.tabs if _shown(user, t.perm, t.act, show_all))
    current = next((t for t in tabs if t.path == path and "#" not in t.href), None)
    if current is None or len(tabs) < 2:
        return active, None
    return active, PageTabs(base.label, tabs, current.href)


def active_for(user, active: str, path: str) -> str:
    """The ``active`` key the sidebar highlights for this user (it differs from the page's own key only when the
    page's item is hidden from them and another visible item links to the page)."""
    return resolve_page(user, active, path)[0]


def page_tabs_for(user, active: str, path: str) -> PageTabs | None:
    """The tab bar for the page at ``path`` (highlighting ``active``), or None when it has none.

    Only the tab pages themselves get a bar (detail pages do not), and only when at least two tabs are visible."""
    if not active:
        return None
    return resolve_page(user, active, path)[1]
