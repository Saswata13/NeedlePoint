"""Offline tests for 01_acquire_data.ipynb.

Runs the whole notebook, unchanged, against simulated NVD, KEV and EPSS services (fake_services.py),
in eight scenarios, and checks both the notebook's own verdicts and the contents of the tables it
writes against answers computed independently here.

Usage, from the project folder:

    python tests/run_acquisition_tests.py                     # tests 01_acquire_data.ipynb
    python tests/run_acquisition_tests.py some_copy.ipynb     # or another copy of it

Needs nbclient, nbformat and ipykernel, which come with Jupyter. Takes about five minutes, uses no
network, and works in temporary folders, so the project's own data/ and logs/ are never touched.
"""
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import nbformat
import pandas as pd
from nbclient import NotebookClient

TESTS = Path(__file__).resolve().parent
NOTEBOOK = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else TESTS.parent / "01_acquire_data.ipynb"
sys.path.insert(0, str(TESTS))
import fake_services as fake  # noqa: E402  (needs the path above)

CHECKS = ["A1-key-loaded", "A2-windows", "A3-parser-selftest", "B1-nvd-windows", "B2-nvd-combined",
          "C1-kev-snapshot", "D1-label-selftest", "D2-analysis-table", "D3-table-saved",
          "E1-epss-days", "E2-epss-benchmark", "F1-data-fingerprints"]
FAIL_WINDOW = "2018-12-07"          # with FAKE_FAIL_WINDOW set, the two windows touching this date fail


def verdicts(**changes):
    "Expected verdicts: PASS everywhere, E1 WARN (one EPSS day is missing by design), plus `changes`."
    expected = {name: "PASS" for name in CHECKS}
    expected["E1-epss-days"] = "WARN"
    expected.update({name.replace("_", "-"): v for name, v in changes.items()})
    return expected


# ------------------------------------------------------------------------------- running the notebook
def prepare(workdir, with_report=True):
    "A fresh project folder: a dummy key and, optionally, a validation report with the right counts."
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / ".env").write_text("NVD_API_KEY=" + "k" * 36 + "\n", encoding="utf-8")
    if with_report:
        (workdir / "logs").mkdir(exist_ok=True)
        report = workdir / "logs" / "validation_report_2026-11-10.json"
        report.write_text(json.dumps(fake.expectations()), encoding="utf-8")


def run_notebook(workdir, fail_window=None, kev_newer=False, edits=()):
    "Execute the notebook in `workdir` with the network replaced by fake_services. Returns (log, text)."
    nb = nbformat.read(NOTEBOOK, as_version=4)
    for cell in nb.cells:
        if cell.cell_type == "code" and cell.source.lstrip().startswith("%pip"):
            cell.source = "pass  # %pip install skipped in the offline test"
        for old, new in edits:                                 # e.g. a different KEV_SNAPSHOT setting
            if cell.cell_type == "code" and old in cell.source:
                cell.source = cell.source.replace(old, new)
    nb.cells.insert(0, nbformat.v4.new_code_cell(
        "import sys, time, requests\n"
        f"sys.path.insert(0, {str(TESTS)!r})\n"
        "import fake_services\n"
        "requests.Session.get = fake_services.fake_get     # no network from here on\n"
        "import threading\n"
        "# Skip pauses in the notebook's own code (the main thread) only. The kernel's background threads\n"
        "# must keep sleeping: its parent poller calls sleep(1.0) in a loop and would otherwise spin.\n"
        "_real_sleep = time.sleep\n"
        "time.sleep = lambda s: None if threading.current_thread() is threading.main_thread() else _real_sleep(s)\n"))
    if fail_window:
        os.environ["FAKE_FAIL_WINDOW"] = fail_window       # inherited by the kernel process
    if kev_newer:
        os.environ["FAKE_KEV_NEWER"] = "1"                 # CISA has published a newer catalogue
    try:
        NotebookClient(nb, timeout=900, kernel_name="python3",
                       resources={"metadata": {"path": str(workdir)}}).execute()
    finally:
        os.environ.pop("FAKE_FAIL_WINDOW", None)
        os.environ.pop("FAKE_KEV_NEWER", None)
    text = "\n".join("".join(o.get("text", "")) for c in nb.cells if c.cell_type == "code" for o in c.outputs)
    errors = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("output_type") == "error"]
    log = json.loads((workdir / "logs" / "acquisition_log.json").read_text(encoding="utf-8"))
    return log, text, errors


# ------------------------------------------------------------------------------- independent checks
def table_checks(workdir):
    "Compare the saved tables with answers computed here, from the simulated data, without the notebook."
    problems = []
    processed = workdir / "data" / "processed"
    missing = [name for name in ("analysis_table.parquet", "analysis_table_columns.csv", "epss_benchmark.parquet")
               if not (processed / name).exists()]
    if missing:
        return [f"output not written: {missing}"]
    table = pd.read_parquet(processed / "analysis_table.parquet")
    kev = {r["cveID"]: dt.date.fromisoformat(r["dateAdded"]) for r in fake.KEV}
    live = {c["id"] for c in fake.CVES if c["vulnStatus"] != "Rejected"}
    if set(table["cve_id"]) != live:
        problems.append("the analysis table does not hold exactly the live CVEs")
    wrong = [r.cve_id for r in table.itertuples()
             if (r.cve_id in kev and (kev[r.cve_id] - r.published.date()).days <= 365) != r.label_365]
    if wrong:
        problems.append(f"{len(wrong)} labels differ from the independent calculation, e.g. {wrong[:3]}")
    columns = pd.read_csv(workdir / "data" / "processed" / "analysis_table_columns.csv")
    kev_side = {"kev_date_added", "in_kev", "days_to_kev", "label_365", "kev_before_publication"}
    leaked = columns.loc[columns["may_be_model_input"] & (columns["column"].str.startswith("diag_")
                         | columns["role"].eq("label") | columns["column"].isin(kev_side)), "column"].tolist()
    if leaked or "notes" in table.columns or "vendorProject" in table.columns:
        problems.append(f"a label, diagnostic or KEV column is usable as an input: {leaked}")

    bench = pd.read_parquet(workdir / "data" / "processed" / "epss_benchmark.parquet")
    for r in bench.itertuples():                          # every value as the simulated file gave it
        expected = round(((int(r.cve_id[-5:]) * 37 + r.score_day.date().toordinal()) % 1000) / 100000 + 0.0001, 5)
        if abs(expected - r.epss) > 1e-9:
            problems.append(f"EPSS value for {r.cve_id} on {r.score_day.date()} differs from the source")
            break
    first = bench[(bench["cve_id"] == fake.SKIP_CVE) & (bench["horizon_days"] == 1)]
    if first["days_late"].tolist() != [1]:
        problems.append("the CVE missing from its target day was not taken from the next day")
    gap = bench[bench["target_day"] == pd.Timestamp("2024-08-01")]
    if gap.empty or not (gap["days_late"] == 1).all():
        problems.append("scores for the day missing everywhere were not taken from the next day")
    leftovers = list((workdir / "data").rglob("*.part"))
    if leftovers:
        problems.append(f"half-written files left behind: {leftovers[:3]}")
    return problems


# ------------------------------------------------------------------------------- the scenarios
def scenario(name, workdir, expected, fail_window=None, with_report=True, fresh=True, extra=None,
             kev_newer=False, edits=()):
    "Run one scenario; return the list of problems (empty means it passed)."
    if fresh:
        shutil.rmtree(workdir, ignore_errors=True)
        prepare(workdir, with_report)
    started = time.time()
    log, text, errors = run_notebook(workdir, fail_window, kev_newer, edits)
    got = {name_: log["checks"].get(name_, {}).get("verdict") for name_ in CHECKS}
    problems = [f"{c}: expected {expected[c]}, got {got[c]}" for c in CHECKS if got[c] != expected[c]]
    problems += [f"error in a cell: {e.get('ename')}: {e.get('evalue')}" for e in errors]
    if extra:
        problems += extra(workdir, text, log) if extra.__code__.co_argcount == 3 else extra(workdir, text)
    print(f"{'PASS' if not problems else 'FAIL'}  {name}  ({time.time() - started:.0f} s)")
    for p in problems:
        print(f"      - {p}")
    return problems


def clean_run_extra(workdir, text):
    problems = table_checks(workdir)
    if "HTTP 503" not in text:
        problems.append("the simulated server error was not seen and retried")
    if "attempt 1 failed" not in text:
        problems.append("the window with a changing total was not downloaded a second time")
    return problems


def resume_extra(workdir, text, log):
    problems = table_checks(workdir)
    if "28 already finished, 0 to download" not in text:
        problems.append("the re-run did not skip the finished windows")
    problems += pinned_extra(workdir, text, log)
    if "same" not in text or "CHANGED" in text:
        problems.append("the re-run's fingerprints were not all reported as the same")
    return problems


def pinned_extra(workdir, text, log):
    "The pinned KEV snapshot was loaded, not downloaded, and no newer copy was saved."
    problems = []
    kev = log.get("sources", {}).get("CISA KEV catalog", {})
    if (kev.get("catalog_version"), kev.get("origin")) != ("2026.11.10", "pinned snapshot"):
        problems.append(f"the pinned KEV snapshot was not the one used: {kev}")
    if list((workdir / "data" / "raw" / "kev").glob("kev_2026.11.12*")):
        problems.append("a newer KEV catalogue was downloaded although the snapshot is pinned")
    return problems


def unpinned_extra(workdir, text, log):
    "Unpinned: today's catalogue was downloaded, labels unchanged, and the changed tables were named."
    problems = table_checks(workdir)
    kev = log.get("sources", {}).get("CISA KEV catalog", {})
    if (kev.get("catalog_version"), kev.get("origin")) != ("2026.11.12", "downloaded"):
        problems.append(f"today's KEV catalogue was not downloaded: {kev}")
    changed = set(log["checks"].get("F1-data-fingerprints", {}).get("changed", []))
    if changed != {"analysis_table", "kev_snapshot"}:
        problems.append(f"expected the analysis table and KEV snapshot to be flagged as changed, got {sorted(changed)}")
    return problems


def outage_extra(workdir, text):
    saved = [p for p in ("data/interim/nvd_2016_2024.parquet", "data/processed/analysis_table.parquet")
             if (workdir / p).exists()]
    return [f"an incomplete table was saved: {saved}"] if saved else []


def main():
    if not NOTEBOOK.exists():
        sys.exit(f"notebook not found: {NOTEBOOK}")
    base = Path(tempfile.mkdtemp(prefix="acquisition_tests_"))
    print(f"testing {NOTEBOOK.name} offline, in {base}\n")
    failures = []
    run = lambda *a, **k: failures.extend(scenario(*a, **k))
    run("1. clean run: retries, fallbacks, labels and values", base / "main", verdicts(), extra=clean_run_extra)
    run("2. re-run in the same folder resumes and changes nothing", base / "main", verdicts(),
        fresh=False, extra=resume_extra)
    run("3. a window keeps failing: nothing incomplete is saved", base / "outage",
        verdicts(B1_nvd_windows="FAIL", B2_nvd_combined="FAIL", D2_analysis_table="FAIL",
                 D3_table_saved="FAIL", E1_epss_days="FAIL", E2_epss_benchmark="FAIL",
                 F1_data_fingerprints="FAIL"),
        fail_window=FAIL_WINDOW, extra=outage_extra)
    run("4. after the outage, a re-run completes the download", base / "outage", verdicts(),
        fresh=False, extra=lambda w, t: table_checks(w))
    run("5. a newer KEV catalogue exists: the pinned snapshot is still used, nothing changes", base / "main",
        verdicts(), fresh=False, kev_newer=True, extra=lambda w, t, log: table_checks(w) + pinned_extra(w, t, log))
    run("6. unpinned: today's catalogue is downloaded, and the changed tables are flagged", base / "main",
        verdicts(F1_data_fingerprints="WARN"), fresh=False, kev_newer=True,
        edits=[('KEV_SNAPSHOT = "2026.11.10"', "KEV_SNAPSHOT = None")], extra=unpinned_extra)
    run("7. the pinned version's files are missing: today's catalogue is used, with a WARN", base / "unpinned",
        verdicts(C1_kev_snapshot="WARN"), edits=[('KEV_SNAPSHOT = "2026.11.10"', 'KEV_SNAPSHOT = "2099.01.01"')],
        extra=lambda w, t: table_checks(w))
    run("8. without a validation report, count checks are WARN", base / "noreport",
        verdicts(B2_nvd_combined="WARN", C1_kev_snapshot="WARN", D2_analysis_table="WARN"),
        with_report=False, extra=lambda w, t: table_checks(w))
    print(f"\n{'ALL SCENARIOS PASSED' if not failures else f'{len(failures)} PROBLEM(S) FOUND'}")
    if failures:
        print(f"the test folders are kept for inspection: {base}")
        sys.exit(1)
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
