"""Offline tests for 02_descriptive_analysis.ipynb.

Builds a synthetic analysis table (same columns and types as the real one) whose answers are known,
runs the notebook on it unchanged, and compares its saved tables with answers computed here
independently. The NVD Source API is simulated, so no network is used.

Usage, from the project folder:

    python tests/run_descriptive_tests.py                    # tests 02_descriptive_analysis.ipynb
    python tests/run_descriptive_tests.py some_copy.ipynb    # or another copy of it

Needs nbclient, nbformat and ipykernel (installed with Jupyter). Takes about a minute and works in
temporary folders, so the project's own data, results and figures are never touched.
"""
import datetime as dt
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

import nbformat
import numpy as np
import pandas as pd
from nbclient import NotebookClient

TESTS = Path(__file__).resolve().parent
NOTEBOOK = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else TESTS.parent / "02_descriptive_analysis.ipynb"
CHECKS = ["A1-statistics-selftest", "B1-table-loaded", "B2-publisher-names", "B3-cvss-parser-selftest",
          "B4-derived-columns", "C0-rate-table-selftest", "D1-timing-complete"]
SOURCES = [   # what the simulated NVD Source API returns: one organisation can have two identifiers
    {"name": "Microsoft Corporation", "sourceIdentifiers": ["secure@microsoft.com"], "created": "x", "lastModified": "x"},
    {"name": "Vendor A", "sourceIdentifiers": ["psirt@vendor-a.example", "11111111-2222-3333-4444-555555555555"],
     "created": "x", "lastModified": "x"},
    {"name": "MITRE", "sourceIdentifiers": ["cve@mitre.org"], "created": "x", "lastModified": "x"},
    {"name": "Small Co", "sourceIdentifiers": ["security@small.example"], "created": "x", "lastModified": "x"},
]


# ------------------------------------------------------------------------------- synthetic data
def synthetic_table(seed=7):
    "A table shaped like analysis_table.parquet, with exploitation depending on severity and publisher."
    rng = np.random.default_rng(seed)
    n = 24_000
    start, stop = pd.Timestamp("2019-01-01"), pd.Timestamp("2025-01-01")
    published = (start + pd.to_timedelta(rng.uniform(0, (stop - start).days, n), unit="D")).astype("datetime64[us]")
    cna = rng.choice(["secure@microsoft.com", "psirt@vendor-a.example", "11111111-2222-3333-4444-555555555555",
                      "cve@mitre.org", "security@small.example"], n, p=[0.1, 0.15, 0.1, 0.45, 0.2])
    score = np.where(rng.random(n) < 0.4, np.nan, np.round(rng.uniform(0, 10, n), 1))
    version = np.where(np.isnan(score), None, rng.choice(["3.1", "4.0", "2.0"], n, p=[0.7, 0.2, 0.1]))
    av = rng.choice(list("NALP"), n, p=[0.6, 0.1, 0.25, 0.05])
    vector = [None if v is None else ("AV:N/AC:L/Au:N/C:P/I:P/A:P" if v == "2.0"
              else f"CVSS:{v}/AV:{a}/AC:L/PR:{rng.choice(list('NLH'))}/UI:{rng.choice(list('NR'))}/S:U")
              for v, a in zip(version, av)]
    cwe = rng.choice(["CWE-79", "CWE-787", "CWE-20", "CWE-416", "CWE-9999", None], n, p=[0.3, 0.15, 0.15, 0.1, 0.1, 0.2])
    # Exploitation: more likely for high scores, unscored CVEs, Microsoft and network attack vectors.
    p = 0.002 + 0.02 * (np.nan_to_num(score) >= 9) + 0.008 * np.isnan(score) + 0.03 * (cna == "secure@microsoft.com")
    in_kev = rng.random(n) < p * 1.3
    days = np.where(in_kev, np.round(rng.exponential(60, n) - rng.choice([0, 15], n, p=[0.85, 0.15])), np.nan)
    days = np.where(in_kev & (rng.random(n) < 0.12), days + 400, days)            # some late listings
    t = pd.DataFrame({"cve_id": [f"CVE-T-{i:06d}" for i in range(n)], "published": published,
                      "cna": cna, "cvss_score": score, "cvss_vector": vector,
                      "cvss_version": version, "cwe_primary": cwe})
    t["pub_year"] = t["published"].dt.year.astype("int32")
    t["kev_date_added"] = (t["published"].dt.normalize() + pd.to_timedelta(days, unit="D")).where(in_kev)
    t["in_kev"] = in_kev
    t["days_to_kev"] = pd.array(np.where(in_kev, days, np.nan), dtype="Float64").astype("Int64")
    t["label_365"] = t["days_to_kev"].le(365).fillna(False).astype(bool)
    t["kev_before_publication"] = t["days_to_kev"].lt(0).fillna(False).astype(bool)
    launch = pd.Timestamp("2021-11-03")
    t["split"] = np.select([t["published"] < launch, t["published"] < "2023-01-01", t["published"] < "2024-01-01"],
                           ["pre-KEV", "train", "validate"], default="test")
    return t


def prepare(workdir, table, with_log=True, tamper=False):
    "A project folder with the synthetic table, its column dictionary and (optionally) an acquisition log."
    (workdir / "data" / "processed").mkdir(parents=True, exist_ok=True)
    (workdir / "logs").mkdir(exist_ok=True)
    table.to_parquet(workdir / "data" / "processed" / "analysis_table.parquet", index=False)
    pd.DataFrame({"column": table.columns, "role": "x"}).to_csv(workdir / "data" / "processed" / "analysis_table_columns.csv", index=False)
    if with_log:
        exploited = table.groupby("split")["label_365"].sum().astype(int).to_dict()
        if tamper:
            exploited["test"] += 1
        log = {"started": "2026-11-10T13:58:58-08:00",
               "checks": {"D2-analysis-table": {"rows": len(table), "exploited": exploited}},
               "sources": {"CISA KEV catalog": {"date_released": "2026-11-10T19:03:29.8375Z"}}}
        (workdir / "logs" / "acquisition_log.json").write_text(json.dumps(log), encoding="utf-8")


# ------------------------------------------------------------------------------- running
def run_notebook(workdir, api="up"):
    "Execute the notebook in workdir with the NVD Source API simulated ('up') or unreachable ('down')."
    nb = nbformat.read(NOTEBOOK, as_version=4)
    fake = (
        "import requests, json\n"
        f"_SOURCES = json.loads({json.dumps(json.dumps(SOURCES))})\n"
        "class _Resp:\n"
        "    def __init__(self, payload): self._p = payload\n"
        "    def raise_for_status(self): pass\n"
        "    def json(self): return self._p\n"
        "def _fake_get(url, params=None, **kw):\n"
        f"    if {api!r} == 'down':\n"
        "        raise requests.ConnectionError('simulated: no network')\n"
        "    start = int((params or {}).get('startIndex', 0))\n"
        "    return _Resp({'resultsPerPage': 2, 'startIndex': start, 'totalResults': len(_SOURCES),\n"
        "                  'sources': _SOURCES[start:start + 2]})       # two per page: tests paging\n"
        "requests.get = _fake_get\n"
        "import time, threading\n"
        "# Skip pauses in the notebook's own code (the main thread) only. The kernel's background threads\n"
        "# must keep sleeping: its parent poller calls sleep(1.0) in a loop and would otherwise spin.\n"
        "_real_sleep = time.sleep\n"
        "time.sleep = lambda s: None if threading.current_thread() is threading.main_thread() else _real_sleep(s)\n")
    nb.cells.insert(0, nbformat.v4.new_code_cell(fake))
    NotebookClient(nb, timeout=900, kernel_name="python3", resources={"metadata": {"path": str(workdir)}}).execute()
    errors = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("output_type") == "error"]
    stderr = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("name") == "stderr"]
    log = json.loads((workdir / "logs" / "descriptive_log.json").read_text(encoding="utf-8"))
    return log, errors, stderr


# ------------------------------------------------------------------------------- independent answers
def independent_checks(workdir, t):
    "Recompute key results with plain pandas/NumPy and compare with the notebook's saved tables."
    problems = []
    m = t[t["split"].isin(["train", "validate", "test"])].copy()
    res = workdir / "results"

    sev = pd.read_csv(res / "q1_rate_by_severity.csv", index_col=0)
    s = m["cvss_score"]
    band = np.select([s >= 9, s >= 7, s >= 4, s.notna()], ["Critical", "High", "Medium", "Low or none"], "No publisher score")
    expected = m.groupby(band)["label_365"].agg(["size", "sum"])
    for b, row in expected.iterrows():
        if (sev.loc[b, "cves"], sev.loc[b, "exploited"]) != (row["size"], row["sum"]):
            problems.append(f"severity band {b}: counts differ")
    from scipy.stats import binomtest                      # an independent Wilson implementation
    ci = binomtest(int(expected.loc["Critical", "sum"]), int(expected.loc["Critical", "size"])).proportion_ci(method="wilson")
    lo, hi = ci.low, ci.high
    if not np.allclose([sev.loc["Critical", "rate_low"], sev.loc["Critical", "rate_high"]], [lo, hi], atol=1e-9):
        problems.append("the Wilson interval differs from SciPy's")

    tri = pd.read_csv(res / "q1_triage_rules.csv", index_col=[0, 1])
    flag = m["cvss_score"] >= 7
    cov = (flag & m["label_365"]).sum() / m["label_365"].sum()
    if abs(tri.loc[("all", "Publisher score 7.0+"), "coverage"] - cov) > 1e-12:
        problems.append("triage coverage for 'Publisher score 7.0+' differs")
    flag2 = (m["cvss_score"] >= 7) | m["cvss_score"].isna()
    eff2 = flag2.mean()
    if abs(tri.loc[("all", "Score 7.0+, or no publisher score"), "effort"] - eff2) > 1e-12:
        problems.append("triage effort for 'Score 7.0+, or no publisher score' differs")

    timing = pd.read_csv(res / "q3_timing_by_year.csv", index_col=0)
    ex = m[m["label_365"]]
    for year in ("2022", "2023", "2024"):
        d = ex.loc[ex["pub_year"] == int(year), "days_to_kev"].astype(float)
        if abs(timing.loc[year, "median_days"] - d.median()) > 1e-9 or timing.loc[year, "exploited"] != len(d):
            problems.append(f"Q3 median or count for {year} differs")
        if abs(timing.loc[year, "on_or_before_share"] - (d <= 0).mean()) > 1e-12:
            problems.append(f"Q3 on-or-before share for {year} differs")

    pub = pd.read_csv(res / "q1_rate_by_publisher.csv", index_col=0)
    if "Vendor A" in pub.index:          # names resolved: two identifiers must be one publisher
        va = m["cna"].isin(["psirt@vendor-a.example", "11111111-2222-3333-4444-555555555555"])
        if pub.loc["Vendor A", "cves"] != int(va.sum()):
            problems.append("Vendor A's two identifiers were not merged into one publisher")
    late = pd.read_csv(res / "q3_late_listings.csv", index_col=0)
    if int(late["after_365"].sum()) != int((m["in_kev"] & m["days_to_kev"].gt(365).fillna(False)).sum()):
        problems.append("late-listing count differs")
    label_columns = {"grouping", "group", "component", "value", "severity", "weakness", "publisher", "period",
                     "cohort", "rule", "comparison", "measure"}
    for path in sorted(res.glob("*.csv")):               # every label must survive a round trip through CSV
        table = pd.read_csv(path)
        lost = [c for c in table.columns if (c in label_columns or c == table.columns[0]) and table[c].isna().any()]
        if lost:
            problems.append(f"{path.name}: labels read back as missing in {lost}")
    for name in ("q1_severity", "q1_weakness", "q1_publisher_concentration", "q1_top_publishers",
                 "q1_triage", "q3_time_to_listing", "q3_median_delay"):
        if not (workdir / "figures" / f"{name}.png").exists():
            problems.append(f"figure {name}.png not written")
    return problems


def scenario(name, table, expected, api="up", with_log=True, tamper=False, extra=True):
    workdir = Path(tempfile.mkdtemp(prefix="descriptive_tests_"))
    prepare(workdir, table, with_log, tamper)
    started = time.time()
    log, errors, stderr = run_notebook(workdir, api)
    got = {c: log["checks"].get(c, {}).get("verdict") for c in CHECKS}
    problems = [f"{c}: expected {expected.get(c, 'PASS')}, got {got[c]}" for c in CHECKS if got[c] != expected.get(c, "PASS")]
    problems += [f"error in a cell: {e.get('ename')}: {e.get('evalue')}" for e in errors]
    problems += [f"warning printed: {''.join(o.get('text', ''))[:160]}" for o in stderr]
    if extra:
        problems += independent_checks(workdir, table)
    print(f"{'PASS' if not problems else 'FAIL'}  {name}  ({time.time() - started:.0f} s)")
    for p in problems:
        print(f"      - {p}")
    if not problems:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(f"      (folder kept: {workdir})")
    return problems


def main():
    table = synthetic_table()
    print(f"testing {NOTEBOOK.name} on a synthetic table of {len(table):,} CVEs "
          f"({int(table['label_365'].sum())} exploited)\n")
    failures = []
    failures += scenario("1. clean run: tables match independent answers", table, {})
    failures += scenario("2. NVD unreachable: names fall back, numbers unchanged", table, {"B2-publisher-names": "WARN"},
                         api="down")
    failures += scenario("3. no acquisition log: the comparison is WARN", table, {"B1-table-loaded": "WARN"}, with_log=False, extra=False)
    failures += scenario("4. table differs from the acquisition log: FAIL", table, {"B1-table-loaded": "FAIL"}, tamper=True, extra=False)
    print(f"\n{'ALL SCENARIOS PASSED' if not failures else f'{len(failures)} PROBLEM(S) FOUND'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
