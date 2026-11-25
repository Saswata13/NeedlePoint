"""A simulated NVD, KEV and EPSS, for testing 01_acquire_data.ipynb offline.

The test runner replaces `requests.Session.get` with `fake_get` below, so the notebook runs unchanged
but never touches the network. The data are synthetic (336 CVEs, 12 per download window) but shaped
like the real services, and they include the awkward cases the notebook must handle:

- pagination (at most 5 records per page)
- a transient HTTP 503 on the third request, which must be retried
- a window that over-reports its total once, so its first attempt comes up short and is repeated
- KEV entries bulk-loaded on the catalogue's first day (November 3, 2021)
- KEV listings on day 0, day 365, day 366 and before publication
- an EPSS day missing on the main host (served by the fallback host) and a day missing everywhere
- one CVE missing from its first target day's EPSS file
- optionally, a window that always fails (set the environment variable FAKE_FAIL_WINDOW)
- optionally, a newer KEV catalogue with one more, late, listing (set FAKE_KEV_NEWER)
"""
import datetime as dt, gzip, os, random
from urllib.parse import parse_qs

FMT = "%Y-%m-%dT%H:%M:%S.000"
PAGE_CAP = 5                         # force pagination
PER_WINDOW = 12
STATE = {"window_glitch_done": False, "five03_done": False, "calls": 0}   # one kernel = one fresh state
FAIL_WINDOW = os.environ.get("FAKE_FAIL_WINDOW")    # e.g. "2018-12-07": every request for it fails
KEV_NEWER = bool(os.environ.get("FAKE_KEV_NEWER"))    # serve a later catalogue version

def windows():
    "The notebook's 28 windows of 119 days covering 2016-2024."
    start, stop, step = dt.datetime(2016, 1, 1), dt.datetime(2025, 1, 1), dt.timedelta(days=119)
    cur = start
    while cur < stop:
        end = min(cur + step, stop)
        yield cur, end
        cur = end

def build_cves():
    "Synthetic NVD records: some with a CNA score, some without; one withdrawn record per window."
    rnd = random.Random(510)
    cves, counter = [], 0
    cnas = ["secure@microsoft.com", "psirt@vendor.example", "cve@mitre.org"]
    for w_start, w_end in windows():
        span = (w_end - w_start) / PER_WINDOW
        for k in range(PER_WINDOW):
            counter += 1
            pub = w_start + span * k + dt.timedelta(hours=3 + (k % 5) * 4)
            cna = cnas[k % 3]
            metrics = {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                          "cvssData": {"baseScore": 7.5, "vectorString": "AV:N", "baseSeverity": "HIGH"}}]}
            if k % 2 == 0:
                metrics["cvssMetricV31"].append({"source": cna, "type": "Secondary",
                                                 "cvssData": {"baseScore": 9.8, "vectorString": "AV:N/AC:L", "baseSeverity": "CRITICAL"}})
            cves.append({
                "id": f"CVE-{pub.year}-{counter:05d}", "sourceIdentifier": cna,
                "published": pub.strftime(FMT), "lastModified": (pub + dt.timedelta(days=30)).strftime(FMT),
                "vulnStatus": "Rejected" if k == 5 else ("Analyzed" if k % 4 == 0 else "Modified"),
                "descriptions": [{"lang": "en", "value": f"Synthetic flaw {counter} in product {rnd.randint(1, 50)}"}],
                "metrics": metrics,
                "weaknesses": [{"source": cna, "type": "Secondary", "description": [{"lang": "en", "value": f"CWE-{79 + k}"}]}],
                "references": [{"url": "https://example.org", "tags": ["Vendor Advisory"]}],
            })
    return cves

CVES = build_cves()
PUB = {c["id"]: dt.datetime.strptime(c["published"], FMT) for c in CVES}

def build_kev():
    """KEV entries chosen to exercise every labelling boundary."""
    entries, live = [], [c for c in CVES if c["vulnStatus"] != "Rejected"]
    launch = dt.date(2021, 11, 3)
    offsets = [0, 365, 366, -5, 30, 400, 2]          # cycled through post-launch CVEs
    j = 0
    for c in live:
        pub = PUB[c["id"]]
        if pub < dt.datetime(2021, 11, 3):
            if int(c["id"][-5:]) % 9 == 0:                     # some old CVEs: bulk-loaded at launch
                entries.append((c["id"], launch))
        elif int(c["id"][-5:]) % 4 == 0:
            off = offsets[j % len(offsets)]; j += 1
            entries.append((c["id"], max((pub + dt.timedelta(days=off)).date(), launch)))   # KEV starts at launch
    entries.append(("CVE-2021-44228", dt.date(2021, 12, 10)))            # Log4Shell (not in our NVD)
    entries.append(("CVE-2014-0160", launch))                            # an old CVE outside 2016-2024
    rows = [{"cveID": i, "dateAdded": d.isoformat(), "vendorProject": "x", "notes": "must never cross over",
             "cwes": ["CWE-79", "CWE-20"]} for i, d in entries]        # a list per entry, as in the real catalogue
    return rows

KEV = build_kev()

def late_listing():
    "A KEV entry added in 2026 for a live 2022 CVE not yet listed: past day 365, so no label changes."
    listed = {r["cveID"] for r in KEV}
    cve = next(c["id"] for c in CVES if c["id"].startswith("CVE-2022") and c["vulnStatus"] != "Rejected"
               and c["id"] not in listed)
    return {"cveID": cve, "dateAdded": "2026-11-11", "vendorProject": "x", "notes": "must never cross over",
            "cwes": ["CWE-787"]}

class Resp:
    "Just enough of requests.Response for http_get: status_code, headers, text, content, json()."
    def __init__(self, status=200, payload=None, content=b"", text="", headers=None):
        self.status_code, self._payload, self.content = status, payload, content
        self.text, self.headers = text, headers or {}
    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload

def nvd(params):
    "Answer an NVD CVE API query: filter by publication window [start, end), then page."
    q = parse_qs(params if isinstance(params, str) else "&".join(f"{k}={v}" for k, v in (params or {}).items()),
                 keep_blank_values=True)
    start = dt.datetime.strptime(q["pubStartDate"][0][:19], "%Y-%m-%dT%H:%M:%S")
    end = dt.datetime.strptime(q["pubEndDate"][0][:19], "%Y-%m-%dT%H:%M:%S")
    index = int(q.get("startIndex", ["0"])[0])
    size = min(int(q.get("resultsPerPage", ["2000"])[0]), PAGE_CAP)
    match = [c for c in CVES if start <= PUB[c["id"]] < end]
    total = len(match)
    # Glitch: the 2nd window over-reports its total once, so the first attempt comes up one short.
    if start == dt.datetime(2016, 4, 29) and index == 0 and not STATE["window_glitch_done"]:
        STATE["window_glitch_done"] = True
        total += 1
    return Resp(payload={"totalResults": total, "startIndex": index, "resultsPerPage": size,
                         "vulnerabilities": [{"cve": c} for c in match[index:index + size]]})

def epss_file(host, day):
    "One day's EPSS file, gzip-compressed, with the model-version header line."
    d = dt.date.fromisoformat(day)
    if day == "2024-08-01" or (day == "2024-06-15" and "empiricalsecurity" in host):
        return Resp(status=404, text="Not Found")
    rows = []
    for c in CVES:
        if c["vulnStatus"] == "Rejected":
            continue
        p = PUB[c["id"]].date()
        if p >= d:
            continue                                   # scored from the day after publication
        if c["id"] == SKIP_CVE and d == p + dt.timedelta(days=1):
            continue                                   # missing from its first target day
        score = round(((int(c["id"][-5:]) * 37 + d.toordinal()) % 1000) / 100000 + 0.0001, 5)
        rows.append(f"{c['id']},{score},{0.5}")
    text = f"#model_version:v2023.03.01,score_date:{day}T00:00:00+0000\ncve,epss,percentile\n" + "\n".join(rows) + "\n"
    return Resp(content=gzip.compress(text.encode()))

SKIP_CVE = next(c["id"] for c in CVES if c["id"].startswith("CVE-2024") and c["vulnStatus"] != "Rejected")

def fake_get(self, url, params=None, headers=None, timeout=None, **kw):
    "Stands in for requests.Session.get: routes each URL to the simulated service."
    STATE["calls"] += 1
    if url.startswith("https://services.nvd.nist.gov/rest/json/cves/2.0"):
        if FAIL_WINDOW and FAIL_WINDOW in str(params):
            return Resp(status=503, text="", headers={"message": "simulated outage"})
        if STATE["calls"] == 3 and not STATE["five03_done"]:
            STATE["five03_done"] = True
            return Resp(status=503, text="", headers={"message": "Service temporarily unavailable"})
        return nvd(params)
    if url.startswith("https://www.cisa.gov/"):
        STATE["kev_downloads"] = STATE.get("kev_downloads", 0) + 1
        entries = KEV + [late_listing()] if KEV_NEWER else KEV
        return Resp(payload={"title": "CISA KEV (synthetic)", "catalogVersion": "2026.11.12" if KEV_NEWER else "2026.11.10",
                             "dateReleased": "2026-11-12T00:00:00Z" if KEV_NEWER else "2026-11-10T00:00:00Z",
                             "count": len(entries), "vulnerabilities": entries})
    if "/epss_scores-" in url:
        host, day = url.split("/epss_scores-")[0], url.split("/epss_scores-")[1][:10]
        return epss_file(host, day)
    return Resp(status=404, text=f"unexpected url {url}")

def expectations():
    """Counts computed independently of the notebook's code, for the synthetic validation report."""
    launch = dt.datetime(2021, 11, 3)
    splits = {"pre-KEV (description only)": (dt.datetime(2016, 1, 1), launch), "train": (launch, dt.datetime(2023, 1, 1)),
              "validate": (dt.datetime(2023, 1, 1), dt.datetime(2024, 1, 1)), "test": (dt.datetime(2024, 1, 1), dt.datetime(2025, 1, 1))}
    kev = {r["cveID"]: dt.date.fromisoformat(r["dateAdded"]) for r in KEV}
    live = [c for c in CVES if c["vulnStatus"] != "Rejected"]
    sizes, labels = [], []
    for name, (a, b) in splits.items():
        members = [c for c in live if a <= PUB[c["id"]] < b]
        pos = [c for c in members if c["id"] in kev and (kev[c["id"]] - PUB[c["id"]].date()).days <= 365]
        sizes.append({"split": name, "excluding_rejected": len(members)})
        labels.append({"split": name, "listed_within_365d": len(pos)})
    launch_day = sum(1 for d in kev.values() if d == dt.date(2021, 11, 3))
    return {"started": "2026-11-10T00:19:44-08:00",
            "steps": {"17-dataset-size": {"total_2016_2024": len(CVES), "excluding_rejected": len(live)},
                      "12-kev": {"launch_day_entries": launch_day}},
            "findings": {"dataset_size": sizes, "label_feasibility": {"splits": labels}}}
