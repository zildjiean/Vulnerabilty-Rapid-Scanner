"""Index nuclei templates (official + custom) into the DB for fast search; manage custom templates."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import httpx
import yaml
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from .config import Settings
from .db import TemplateIndex, utcnow
from .render import SEVERITY_ORDER, normalize_severity

try:
    _Loader = yaml.CSafeLoader
except AttributeError:  # libyaml not available
    _Loader = yaml.SafeLoader

_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
MAX_TEMPLATE_BYTES = 10 * 1024 * 1024
SKIP_DIRS = {".git", ".github", "helpers", "workflows", "profiles"}


@dataclass
class TemplateInfo:
    template_id: str
    path: str
    name: str
    severity: str
    tags: str
    cve_ids: str
    source: str


def _as_csv(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(v).strip() for v in value if str(v).strip())
    return ",".join(p.strip() for p in str(value).split(",") if p.strip())


def _info_from_doc(doc, path: str, source: str) -> TemplateInfo | None:
    if not isinstance(doc, dict):
        return None
    tid = doc.get("id")
    info = doc.get("info")
    if not isinstance(tid, str) or not isinstance(info, dict):
        return None
    classification = info.get("classification") or {}
    cve = classification.get("cve-id") if isinstance(classification, dict) else None
    return TemplateInfo(
        template_id=tid.strip(),
        path=path,
        name=str(info.get("name") or "").strip(),
        severity=normalize_severity(info.get("severity")),
        tags=_as_csv(info.get("tags")),
        cve_ids=_as_csv(cve),
        source=source,
    )


def read_template_info(path: Path, source: str) -> TemplateInfo | None:
    try:
        with open(path, "rb") as f:
            doc = yaml.load(f, Loader=_Loader)
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return None
    return _info_from_doc(doc, str(path), source)


def scan_templates_dir(root: Path, source: str) -> list[TemplateInfo]:
    if not root.is_dir():
        return []
    infos: list[TemplateInfo] = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in (".yaml", ".yml") or not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        info = read_template_info(p, source)
        if info is not None:
            infos.append(info)
    return infos


def reindex(db: Session, settings: Settings) -> dict:
    official = scan_templates_dir(settings.nuclei_templates_dir, "official")
    custom = scan_templates_dir(settings.custom_templates_dir, "custom")
    db.execute(delete(TemplateIndex))
    now = utcnow()
    seen: set[str] = set()
    rows = []
    for info in official + custom:
        if info.path in seen:
            continue
        seen.add(info.path)
        rows.append(dict(template_id=info.template_id, path=info.path, name=info.name, severity=info.severity,
                         tags=info.tags, cve_ids=info.cve_ids, source=info.source, indexed_at=now))
    if rows:
        db.execute(TemplateIndex.__table__.insert(), rows)
    db.commit()
    return {"official": len(official), "custom": len(custom)}


def index_single(db: Session, path: Path, source: str) -> TemplateInfo | None:
    info = read_template_info(path, source)
    if info is None:
        return None
    row = db.scalar(select(TemplateIndex).where(TemplateIndex.path == str(path)))
    if row is None:
        row = TemplateIndex(path=str(path))
        db.add(row)
    row.template_id, row.name, row.severity = info.template_id, info.name, info.severity
    row.tags, row.cve_ids, row.source, row.indexed_at = info.tags, info.cve_ids, info.source, utcnow()
    db.commit()
    return info


def remove_from_index(db: Session, path: Path) -> None:
    db.execute(delete(TemplateIndex).where(TemplateIndex.path == str(path)))
    db.commit()


def search_templates(db: Session, q: str, severity: str = "", source: str = "", limit: int = 100) -> list[TemplateIndex]:
    terms = [t for t in (q or "").lower().split() if t]
    if not terms:
        return []
    conds = []
    for t in terms:
        like = f"%{t}%"
        conds.append(or_(TemplateIndex.template_id.ilike(like), TemplateIndex.name.ilike(like),
                         TemplateIndex.tags.ilike(like), TemplateIndex.cve_ids.ilike(like)))
    stmt = select(TemplateIndex).where(and_(*conds))
    if severity:
        stmt = stmt.where(TemplateIndex.severity == severity)
    if source:
        stmt = stmt.where(TemplateIndex.source == source)
    rows = list(db.scalars(stmt.limit(2000)))
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 99), r.template_id.lower()))
    return rows[:limit]


def count_templates(db: Session) -> dict:
    rows = db.execute(select(TemplateIndex.source, TemplateIndex.indexed_at)).all()
    counts = {"official": 0, "custom": 0, "last_indexed": None}
    for source, at in rows:
        counts[source] = counts.get(source, 0) + 1
        if counts["last_indexed"] is None or at > counts["last_indexed"]:
            counts["last_indexed"] = at
    return counts


def validate_template_yaml(text: str) -> TemplateInfo:
    if len(text.encode("utf-8", "replace")) > MAX_TEMPLATE_BYTES:
        raise ValueError("Template is larger than 10 MB.")
    try:
        doc = yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as e:
        raise ValueError(f"Not valid YAML: {e}") from e
    info = _info_from_doc(doc, "", "custom")
    if info is None:
        raise ValueError("Not a nuclei template: needs a top-level 'id' and an 'info' mapping.")
    if not info.name:
        raise ValueError("Template 'info.name' is required.")
    if not _TEMPLATE_ID_RE.match(info.template_id):
        raise ValueError("Template 'id' may only contain letters, digits, '.', '_' and '-'.")
    return info


def save_custom_template(settings: Settings, text: str) -> Path:
    info = validate_template_yaml(text)
    path = settings.custom_templates_dir / f"{info.template_id}.yaml"
    path.write_text(text)
    return path


def is_custom_path(settings: Settings, path: str) -> bool:
    try:
        resolved = Path(path).resolve()
        return resolved.is_relative_to(settings.custom_templates_dir.resolve()) and resolved.suffix in (".yaml", ".yml")
    except (OSError, ValueError):
        return False


def http_fetch(url: str) -> tuple[int, str]:
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "zero-day-rapid-scanner"}) as c:
        with c.stream("GET", url) as r:
            chunks = []
            size = 0
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > MAX_TEMPLATE_BYTES:
                    raise ValueError("Download exceeds 10 MB.")
                chunks.append(chunk)
            return r.status_code, b"".join(chunks).decode("utf-8", "replace")


def fetch_template_from_url(url: str, fetch: Callable[[str], tuple[int, str]] | None = None) -> str:
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("URL must start with http:// or https://")
    fetch = fetch or http_fetch
    try:
        status, text = fetch(url)
    except (httpx.HTTPError, OSError) as e:
        raise ValueError(f"Download failed: {e}") from e
    if status != 200:
        raise ValueError(f"Download failed with HTTP {status}.")
    if len(text.encode("utf-8", "replace")) > MAX_TEMPLATE_BYTES:
        raise ValueError("Download exceeds 10 MB.")
    return text
