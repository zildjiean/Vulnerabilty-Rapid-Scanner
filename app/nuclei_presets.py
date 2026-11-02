"""Nuclei presets: a few named, safe template / severity / tag combinations so a scan can be started without knowing
nuclei. ``custom`` means "use the advanced form" and is never launched from here."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .db import Job

PRESETS = {
    "recommended": {"label": "Recommended",
                    "help": "Every official and custom template, critical, high and medium severity. Good default.",
                    "severities": ["critical", "high", "medium"], "tags": [], "profile": "normal"},
    "critical_cves": {"label": "Critical CVEs only",
                      "help": "Known CVEs rated critical or high. Fastest way to find what must be patched now.",
                      "severities": ["critical", "high"], "tags": ["cve"], "profile": "normal"},
    "full": {"label": "Full",
             "help": "Every template at every severity, including low and info. Slowest, most detail.",
             "severities": [], "tags": [], "profile": "normal"},
    "custom": {"label": "Custom",
               "help": "Choose templates, filters and speed yourself under Advanced options."},
}
DEFAULT_PRESET = "recommended"


def preset_label(key: str) -> str:
    return PRESETS.get(key, {}).get("label", key)


def preset_args(key: str) -> dict:
    """{severities, tags, profile} for a launchable preset. Raises ValueError for an unknown key or ``custom``."""
    p = PRESETS.get(key)
    if not p or key == "custom":
        raise ValueError("Invalid preset.")
    return {"severities": list(p["severities"]), "tags": list(p["tags"]), "profile": p["profile"]}


def preset_launch(db: Session, settings, runner, targets: list[str], key: str, params: dict | None = None,
                  **launch_kwargs) -> Job:
    """Start a nuclei job over every template (official + custom) with preset ``key``. ``targets`` must already be
    validated; ``params`` are merged into the job params and ``launch_kwargs`` go to ``launch_nuclei``."""
    from .routers.nuclei import launch_nuclei
    from .scanners.nuclei_runner import PROFILES, all_template_paths, profile_flags
    args = preset_args(key)
    paths = all_template_paths(settings)
    prof = PROFILES[args["profile"]]
    job_params = {"targets": targets, "mode": "all", "tags": args["tags"], "severities": args["severities"],
                  "profile": args["profile"], "preset": key, **(params or {})}
    return launch_nuclei(db, settings, runner, targets, paths, job_params, rate_limit=prof["rate_limit"],
                         timeout=prof["timeout"], extra_flags=profile_flags(args["profile"], False),
                         tags=args["tags"], severities=args["severities"], **launch_kwargs)
