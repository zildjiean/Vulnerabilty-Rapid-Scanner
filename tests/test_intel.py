import json
import os
import time
from datetime import datetime

import httpx
import pytest

from app import intel

NVD_V31 = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2021-41773", "published": "2021-10-05T09:15:07.593", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "es", "value": "Una falla"}, {"lang": "en", "value": "A flaw in Apache HTTP Server 2.4.49 path normalization."}],
    "metrics": {
        "cvssMetricV31": [
            {"source": "other@example", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/X"}},
            {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}}]},
    "references": [{"url": f"https://ref.example/{i}"} for i in range(20)]}}]}
NVD_V40 = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2026-0001", "published": "2026-10-28T10:00:00.000", "descriptions": [{"lang": "en", "value": "New bug."}],
    "metrics": {"cvssMetricV40": [{"source": "x", "type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:N"}}],
                "cvssMetricV31": [{"source": "x", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
    "references": []}}]}
NVD_RESERVED = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0002", "published": "2026-10-29T00:00:00.000",
                                                                 "descriptions": [{"lang": "en", "value": "Awaiting analysis"}], "metrics": {}}}]}
KEV = {"vulnerabilities": [{"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server",
                            "vulnerabilityName": "Apache HTTP Server Path Traversal", "dateAdded": "2021-11-03",
                            "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Known",
                            "requiredAction": "Apply updates per vendor instructions.", "shortDescription": "..."}]}


class FakeNet:
    def __init__(self, nvd=None, kev=KEV, fail=()):
        self.nvd, self.kev, self.fail, self.calls = nvd or {}, kev, set(fail), []

    def __call__(self, url, params=None):
        self.calls.append(url)
        if url == intel.NVD_URL:
            if "nvd" in self.fail:
                raise httpx.ConnectError("offline")
            return self.nvd.get(params["cveId"], {"totalResults": 0, "vulnerabilities": []})
        if url == intel.KEV_URL:
            if "kev" in self.fail:
                raise httpx.ConnectError("offline")
            return self.kev
        raise AssertionError(url)


def test_normalize_cve():
    assert intel.normalize_cve(" cve-2021-41773 ") == "CVE-2021-41773"
    assert intel.normalize_cve("CVE-2026-109619") == "CVE-2026-109619"
    for bad in ("", "CVE-21-1", "2021-41773", "CVE-2021-41773; rm -rf /"):
        with pytest.raises(ValueError):
            intel.normalize_cve(bad)


def test_parse_nvd_prefers_primary_v31_over_secondary_and_v2():
    d = intel.parse_nvd(NVD_V31)
    assert d["cvss_score"] == 7.5 and d["cvss_severity"] == "high" and d["cvss_version"] == "3.1"
    assert d["cvss_vector"].startswith("CVSS:3.1/AV:N/AC:L")
    assert d["description"].startswith("A flaw in Apache")
    assert d["published"] == datetime(2021, 10, 5, 9, 15, 7, 593000)
    assert len(d["references"]) == 15


def test_parse_nvd_prefers_v40_and_handles_missing_metrics():
    d = intel.parse_nvd(NVD_V40)
    assert d["cvss_score"] == 9.3 and d["cvss_severity"] == "critical" and d["cvss_version"] == "4.0"
    d = intel.parse_nvd(NVD_RESERVED)
    assert d["cvss_score"] is None and d["cvss_severity"] == "" and d["description"] == "Awaiting analysis"
    assert intel.parse_nvd({"totalResults": 0, "vulnerabilities": []}) is None


def test_kev_cache(tmp_path):
    net = FakeNet()
    cache = tmp_path / "kev.json"
    assert intel.kev_entry("CVE-2021-41773", cache, net)["dueDate"] == "2021-11-17"
    assert intel.kev_entry("CVE-2026-0001", cache, net) is None
    assert net.calls.count(intel.KEV_URL) == 1  # second lookup served from cache
    old = time.time() - 25 * 3600
    os.utime(cache, (old, old))
    intel.kev_entry("CVE-2021-41773", cache, net)
    assert net.calls.count(intel.KEV_URL) == 2  # stale cache refreshed
    # an explicit refresh bypasses a fresh cache
    intel.kev_entry("CVE-2021-41773", cache, net, refresh=True)
    assert net.calls.count(intel.KEV_URL) == 3
    # offline with a stale cache: fall back to the cache instead of failing
    os.utime(cache, (old, old))
    assert intel.kev_entry("CVE-2021-41773", cache, FakeNet(fail={"kev"}))["dateAdded"] == "2021-11-03"


def test_enrich_combines_sources_and_reports_errors(tmp_path):
    info, errors = intel.enrich("CVE-2021-41773", tmp_path / "kev.json", FakeNet(nvd={"CVE-2021-41773": NVD_V31}))
    assert errors == []
    assert info["kev"] is True and info["kev_due"] == "2021-11-17" and info["kev_ransomware"] is True
    assert info["kev_name"] == "Apache HTTP Server Path Traversal" and info["cvss_severity"] == "high"

    info, errors = intel.enrich("CVE-2026-0001", tmp_path / "kev2.json", FakeNet(nvd={}, fail={"kev"}))
    assert info["kev"] is False and info["description"] == ""
    assert any("NVD has no record" in e for e in errors) and any("CISA KEV" in e for e in errors)

    info, errors = intel.enrich("CVE-2026-0001", tmp_path / "kev3.json", FakeNet(fail={"nvd", "kev"}))
    assert len(errors) == 2 and all("offline" in e for e in errors)
    json.dumps(info, default=str)  # serialisable for storage
