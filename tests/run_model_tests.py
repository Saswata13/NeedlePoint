"""Offline tests for 03_model.ipynb.

Builds a synthetic analysis table whose signal is known (publisher, severity, attack vector, and a
phrase in the description that the structured fields don't reveal), plants exploitation sentences in
some descriptions (some present on publication day, some added after the KEV listing), simulates the
NVD change-history API and PyPI, runs the notebook unchanged, and compares its saved results with
answers computed here independently.

Usage, from the project folder:

    python tests/run_model_tests.py                     # tests 03_model.ipynb
    python tests/run_model_tests.py some_copy.ipynb     # or another copy of it

Needs nbclient, nbformat, ipykernel and scikit-learn. Takes a few minutes, uses no network, and works
in temporary folders, so the project's own data, results and logs are never touched.
"""
import hashlib
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
NOTEBOOK = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else TESTS.parent / "03_model.ipynb"
SEALED_CHECKS = ["A1-evaluation-selftest", "B1-table-loaded", "B2-inputs-permitted", "C1-description-masking",
                 "C2-description-history", "D0-cvss-parser-selftest", "D1-features-built", "E1-models-trained",
                 "F1-pytorch-readiness", "G1-selection-frozen"]
PHRASE_SENTENCE = "This vulnerability is known to be exploited in the wild."
APPLE_SENTENCE = "Apple is aware of a report that this issue may have been actively exploited."
SOURCES = [{"name": "Microsoft Corporation", "sourceIdentifiers": ["secure@microsoft.com"]},
           {"name": "Vendor A", "sourceIdentifiers": ["psirt@vendor-a.example", "11111111-2222-3333-4444-555555555555"]},
           {"name": "MITRE", "sourceIdentifiers": ["cve@mitre.org"]},
           {"name": "Apple Inc.", "sourceIdentifiers": ["product-security@apple.com"]},
           {"name": "Wordfence", "sourceIdentifiers": ["security@wordfence.com"]}]


# ------------------------------------------------------------------------------- synthetic data
def synthetic_table(seed=11, n=24_000):
    "A table shaped like analysis_table.parquet, with a known signal and planted exploitation sentences."
    rng = np.random.default_rng(seed)
    start, stop = pd.Timestamp("2019-01-01"), pd.Timestamp("2025-01-01")
    published = (start + pd.to_timedelta(rng.uniform(0, (stop - start).days, n), unit="D")).astype("datetime64[us]")
    cna = rng.choice(["secure@microsoft.com", "psirt@vendor-a.example", "11111111-2222-3333-4444-555555555555",
                      "cve@mitre.org", "product-security@apple.com", "security@wordfence.com", "small@tiny.example"],
                     n, p=[0.08, 0.1, 0.05, 0.4, 0.05, 0.22, 0.10])
    score = np.where(rng.random(n) < 0.35, np.nan, np.round(rng.uniform(1, 10, n), 1))
    version = np.where(np.isnan(score), None, rng.choice(["3.1", "4.0", "2.0"], n, p=[0.7, 0.2, 0.1]))
    av = rng.choice(list("NALP"), n, p=[0.6, 0.1, 0.25, 0.05])
    pr = rng.choice(list("NLH"), n)
    vector = [None if v is None else ("AV:N/AC:L/Au:N/C:P/I:P/A:P" if v == "2.0" else
              f"CVSS:{v}/AV:{a}/AC:L/PR:{p}/UI:N/S:U/C:H/I:H/A:H" if v == "3.1" else
              f"CVSS:4.0/AV:{a}/AC:L/AT:N/PR:{p}/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") for v, a, p in zip(version, av, pr)]
    cwe = rng.choice(["CWE-79", "CWE-787", "CWE-20", "CWE-416", "CWE-89", None], n, p=[0.3, 0.15, 0.15, 0.1, 0.1, 0.2])
    rce = rng.random(n) < 0.15                     # a trait only the description reveals
    p = (0.002 + 0.03 * (cna == "secure@microsoft.com") + 0.02 * (np.nan_to_num(score) >= 9)
         + 0.01 * ((av == "N") & (pr == "N")) + 0.08 * rce)
    p = np.where(cna == "security@wordfence.com", 0.0005, p)
    in_kev = rng.random(n) < p
    days = np.where(in_kev, np.round(rng.exponential(40, n) - rng.choice([0, 10], n, p=[0.9, 0.1])), np.nan)
    days = np.where(in_kev & (rng.random(n) < 0.08), days + 400, days)
    words = rng.choice(["buffer handling", "input parsing", "session management", "file upload", "template engine"], n)
    impact = np.where(rce, "allows remote code execution by an unauthenticated attacker",     # all of similar length,
                      rng.choice(["allows a denial of service by sending a crafted request",   # so the length of the
                                  "allows cross-site scripting through a crafted parameter",   # text does not reveal it
                                  "discloses sensitive information to a local low user"], n))
    original = [f"A flaw in the {w} component of product {i % 37} {imp}. Versions before {i % 9}.{i % 7} are affected."
                for i, (w, imp) in enumerate(zip(words, impact))]
    t = pd.DataFrame({"cve_id": [f"CVE-T-{i:06d}" for i in range(n)], "published": published, "cna": cna,
                      "cvss_score": score, "cvss_vector": vector, "cvss_version": version, "cwe_primary": cwe})
    t["pub_year"] = t["published"].dt.year.astype("int32")
    t["kev_date_added"] = (t["published"].dt.normalize() + pd.to_timedelta(days, unit="D")).where(in_kev)
    t["in_kev"] = in_kev
    t["days_to_kev"] = pd.array(np.where(in_kev, days, np.nan), dtype="Float64").astype("Int64")
    t["label_365"] = t["days_to_kev"].le(365).fillna(False).astype(bool)
    t["kev_before_publication"] = t["days_to_kev"].lt(0).fillna(False).astype(bool)
    # Planted sentences: 40% of exploited CVEs; half said so on publication day, half had it added later.
    plant = t["label_365"].to_numpy() & (rng.random(n) < 0.4)
    at_publication = plant & (rng.random(n) < 0.5)
    apple = (cna == "product-security@apple.com") & (rng.random(n) < 0.1) & ~plant
    current = [o + (" " + PHRASE_SENTENCE if pl else "") + (" " + APPLE_SENTENCE if ap else "")
               for o, pl, ap in zip(original, plant, apple)]
    first = [o + (" " + PHRASE_SENTENCE if pub else "") + (" " + APPLE_SENTENCE if ap else "")
             for o, pub, ap in zip(original, at_publication, apple)]
    t["description"], t["first_description"] = current, first
    t["description_len"] = t["description"].str.len()
    t["added_later"] = plant & ~at_publication
    t["cvss_missing"], t["cwe_missing"] = t["cvss_score"].isna(), t["cwe_primary"].isna()
    t["cwes"] = t["cwe_primary"].fillna("")
    t["diag_nvd_score"] = np.where(t["label_365"], 9.8, rng.uniform(0, 9, n))     # a leaky column, never permitted
    launch = pd.Timestamp("2021-11-03")
    t["split"] = np.select([t["published"] < launch, t["published"] < "2023-01-01", t["published"] < "2024-01-01"],
                           ["pre-KEV", "train", "validate"], default="test")
    return t


def late_start(cve_id, added_later):
    "Every fourth history whose phrase was there from the start begins 30 days after publication, as many real ones do."
    return not added_later and int(cve_id[-6:]) % 4 == 0


def histories(t):
    "Change histories, in the NVD's format, for every CVE with a planted sentence."
    out = {}
    for r in t[t["description"].str.contains("exploited")].itertuples():
        first = r.published + pd.Timedelta(days=30) if late_start(r.cve_id, r.added_later) else r.published
        changes = [{"change": {"cveId": r.cve_id, "eventName": "New CVE Received", "cveChangeId": "x",
                               "sourceIdentifier": r.cna, "created": f"{first:%Y-%m-%dT%H:%M:%S.000}",
                               "details": [{"action": "Added", "type": "Description", "newValue": r.first_description}]}}]
        if r.added_later:
            when = max(r.kev_date_added + pd.Timedelta(days=3), r.published + pd.Timedelta(days=1))
            changes.append({"change": {"cveId": r.cve_id, "eventName": "CVE Modified", "cveChangeId": "y",
                                       "sourceIdentifier": r.cna, "created": f"{when:%Y-%m-%dT%H:%M:%S.000}",
                                       "details": [{"action": "Changed", "type": "Description",
                                                    "oldValue": r.first_description, "newValue": r.description}]}})
        out[r.cve_id] = {"resultsPerPage": len(changes), "startIndex": 0, "totalResults": len(changes),
                         "format": "NVD_CVEHistory", "version": "2.0", "timestamp": "2026-11-11T00:00:00.000",
                         "cveChanges": changes}
    return out


def columns_dictionary(t):
    "The column dictionary, with the same roles as the real one."
    inputs = {"cna", "description", "description_len", "cvss_score", "cvss_severity", "cvss_vector", "cvss_version",
              "cvss_missing", "cwes", "cwe_primary", "cwe_missing"}
    role = {c: "input" if c in inputs else "diagnostic" if c.startswith("diag_") else
            "label" if c in {"kev_date_added", "in_kev", "days_to_kev", "label_365", "kev_before_publication"} else
            "split" if c == "split" else "id" if c == "cve_id" else "time" for c in t.columns}
    return pd.DataFrame({"column": list(role), "role": list(role.values()),
                         "may_be_model_input": [c in inputs for c in role]})


def prepare(workdir, t, key=True):
    "A project folder with the table, its dictionary, an acquisition log, the publisher cache and (optionally) a key."
    (workdir / "data" / "processed").mkdir(parents=True, exist_ok=True)
    (workdir / "data" / "raw").mkdir(parents=True, exist_ok=True)
    (workdir / "logs").mkdir(exist_ok=True)
    table = t.drop(columns=["first_description", "added_later"])
    table.to_parquet(workdir / "data" / "processed" / "analysis_table.parquet", index=False)
    columns_dictionary(table).to_csv(workdir / "data" / "processed" / "analysis_table_columns.csv", index=False)
    exploited = table.groupby("split")["label_365"].sum().astype(int).to_dict()
    log = {"started": "x", "checks": {"D2-analysis-table": {"rows": len(table), "exploited": exploited}}}
    (workdir / "logs" / "acquisition_log.json").write_text(json.dumps(log), encoding="utf-8")
    (workdir / "data" / "raw" / "nvd_sources.json").write_text(json.dumps(SOURCES), encoding="utf-8")
    if key:
        (workdir / ".env").write_text("NVD_API_KEY=" + "k" * 36 + "\n", encoding="utf-8")


# ------------------------------------------------------------------------------- running
def run_notebook(workdir, hist, network="up", evaluate_test=False, notebook=NOTEBOOK, edit=None):
    "Execute the notebook in workdir with the NVD history API and PyPI simulated; return (log, errors, stderr)."
    nb = nbformat.read(notebook, as_version=4)
    for cell in nb.cells:
        if cell.cell_type == "code" and cell.source.lstrip().startswith("%pip"):
            cell.source = "pass  # %pip skipped in the offline test"
        if cell.cell_type == "code" and "EVALUATE_TEST = False" in cell.source and evaluate_test:
            cell.source = cell.source.replace("EVALUATE_TEST = False", "EVALUATE_TEST = True")
        if edit and cell.cell_type == "code" and edit[0] in cell.source:
            cell.source = cell.source.replace(*edit)
    (workdir / "_histories.json").write_text(json.dumps(hist), encoding="utf-8")
    tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    fake = (
        "import json, requests, threading, time\n"
        "_H = json.load(open('_histories.json', encoding='utf-8'))\n"
        "class _Resp:\n"
        "    def __init__(self, payload, status=200): self._p, self.status_code = payload, status\n"
        "    def raise_for_status(self):\n"
        "        if self.status_code != 200: raise requests.HTTPError(str(self.status_code))\n"
        "    def json(self): return self._p\n"
        "def _fake_get(url, params=None, **kw):\n"
        "    with open('_calls.txt', 'a', encoding='utf-8') as f: f.write(url + '\\n')\n"
        f"    if {network!r} == 'down': raise requests.ConnectionError('simulated: no network')\n"
        "    if 'cvehistory' in url:\n"
        "        cve = (params or {}).get('cveId')\n"
        "        return _Resp(_H.get(cve, {'resultsPerPage': 0, 'startIndex': 0, 'totalResults': 0, 'cveChanges': []}))\n"
        "    if 'pypi.org' in url:\n"
        f"        return _Resp({{'info': {{'version': '9.9.9'}}, 'urls': [{{'filename': 'torch-9.9.9-{tag}-{tag}-manylinux_2_28_x86_64.whl'}}]}})\n"
        "    return _Resp({}, 404)\n"
        "requests.get = _fake_get\n"
        "_real_sleep = time.sleep\n"
        "def _sleep(s):  # skip the notebook's own waits (main thread, history threads); keep the kernel's\n"
        "    t = threading.current_thread()\n"
        "    if t is not threading.main_thread() and not t.name.startswith('nvd-history'): _real_sleep(s)\n"
        "time.sleep = _sleep\n")
    nb.cells.insert(0, nbformat.v4.new_code_cell(fake))
    try:
        NotebookClient(nb, timeout=1200, kernel_name="python3", resources={"metadata": {"path": str(workdir)}}).execute()
    except Exception as exc:                                 # a cell raised: inspect the outputs and the log
        if "CellExecutionError" not in type(exc).__name__:
            raise
    errors = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("output_type") == "error"]
    stderr = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("name") == "stderr"]
    log_path = workdir / "logs" / ("model_log_test.json" if evaluate_test else "model_log.json")
    log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else {"checks": {}}
    return log, errors, stderr


# ------------------------------------------------------------------------------- independent answers
def expected_coverage(score, y, effort):
    "Expected coverage with ties split evenly, computed group by group with pandas (a different method)."
    df = pd.DataFrame({"s": score, "y": y}).groupby("s", sort=True)["y"].agg(["size", "sum"]).iloc[::-1]
    k, found = effort * len(y), 0.0
    for size, hits in zip(df["size"], df["sum"]):
        take = min(size, k)
        found += hits * take / size
        k -= take
        if k <= 0:
            break
    return found / y.sum()


def sealed_checks(workdir, t):
    problems = []
    res, val = workdir / "results", t[t["split"] == "validate"].reset_index(drop=True)
    for name in ("logs/test_openings.json", "data/processed/model_scores_test.parquet", "results/q2_test_results.csv"):
        if (workdir / name).exists():
            problems.append(f"{name} exists although the test year is sealed")
    models = pd.read_csv(res / "q2_validation_models.csv", index_col=0)
    scores = pd.read_parquet(workdir / "data" / "processed" / "model_scores_validate.parquet")
    if not scores["cve_id"].equals(val["cve_id"]):
        problems.append("validation scores are not aligned with the validation CVEs")
    y = val["label_365"].to_numpy(int)
    for name in ("LR · structured + text", "CVSS score, unscored slotted in", "Publisher's past rate"):
        for e in (0.05, 0.10, 0.26):
            if abs(expected_coverage(scores[name].to_numpy(), y, e) - models.loc[name, f"coverage_{round(e * 100)}"]) > 1e-9:
                problems.append(f"coverage of {name} at {e:.0%} differs from the independent calculation")
    s = val["cvss_score"]
    flag = (s >= 7).to_numpy()
    print(f"      (rule 7.0+ on validation: effort {flag.mean():.3f}, coverage {(flag & (y == 1)).sum() / y.sum():.3f})")
    final = json.loads((res / "q2_selection.json").read_text(encoding="utf-8"))
    content = {k: v for k, v in final.items() if k not in ("sha256", "frozen_at")}
    if hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode()).hexdigest() != final["sha256"]:
        problems.append("the selection fingerprint does not match the selection's content")
    if models.loc[final["final_model"], "coverage_10"] < 0.3:
        problems.append("the final model barely beats a random order on data with a strong signal")
    top = pd.read_csv(res / "q2_top_features.csv", index_col=0)
    leaked = [w for w in top.index if any(x in w for x in ("exploited", "wild", "aware", "report"))]
    if leaked:
        problems.append(f"an exploitation word reached the model: {leaked}")
    hist = pd.read_csv(res / "q2_description_history.csv")
    pool = t[t["split"].isin(["train", "validate"]) & t["description"].str.contains("exploited")]
    planted_late = pool[pool["added_later"]]
    if hist["status"].eq("phrase added later").sum() != len(planted_late) or hist["added_after_kev"].eq(True).sum() != len(planted_late):
        problems.append("the audit did not find exactly the sentences planted after the KEV listing")
    starts_late = pool[[late_start(c, a) for c, a in zip(pool["cve_id"], pool["added_later"])]]
    if hist["status"].eq("phrase in first recorded text, later than publication").sum() != len(starts_late):
        problems.append("histories that start after publication were not labelled as undatable")
    if hist["status"].eq("phrase at publication").sum() != len(pool) - len(planted_late) - len(starts_late):
        problems.append("the count of phrases at publication is wrong")
    if "listed_before_publication" not in hist.columns:
        problems.append("the audit table lacks listed_before_publication")
    diff = pd.read_csv(res / "q2_validation_differences.csv")
    row = diff[(diff["compared_with"] == "CVSS score, unscored slotted in") & (diff["effort"] == 0.10)].iloc[0]
    expected = models.loc[row["model"], "coverage_10"] - models.loc["CVSS score, unscored slotted in", "coverage_10"]
    if abs(row["change"] - expected) > 1e-9:
        problems.append("the 2023 difference table does not match the coverage table")
    decision = json.loads((res / "q2_pytorch_decision.json").read_text(encoding="utf-8"))
    if decision["decision"] not in ("go", "go, framed as exploratory", "probably skip"):
        problems.append(f"unexpected PyTorch decision: {decision['decision']}")
    ablation = pd.read_csv(res / "q2_text_ablation.csv")
    signal = ablation[(ablation["family"] == "LR") & (ablation["comparison"] == "text alone vs random order")]
    if not signal["clear"].all():
        problems.append("the text signal planted in the data was not detected")
    return problems


def opened_checks(workdir, t, openings_expected):
    problems = []
    test = t[t["split"] == "test"].reset_index(drop=True)
    sel = json.loads((workdir / "results" / "q2_selection.json").read_text(encoding="utf-8"))
    openings = json.loads((workdir / "logs" / "test_openings.json").read_text(encoding="utf-8"))
    if len(openings) != openings_expected or any(o["selection_sha256"] != sel["sha256"] for o in openings):
        problems.append(f"test openings log: expected {openings_expected} opening(s) with the frozen fingerprint")
    scores = pd.read_parquet(workdir / "data" / "processed" / "model_scores_test.parquet")
    if not scores["cve_id"].equals(test["cve_id"]):
        problems.append("test scores are not aligned with the 2024 CVEs")
    results = pd.read_csv(workdir / "results" / "q2_test_results.csv", index_col=0)
    y = test["label_365"].to_numpy(int)
    final = sel["final_model"]
    if abs(expected_coverage(scores[final].to_numpy(), y, 0.10) - results.loc[final, "coverage_10"]) > 1e-9:
        problems.append("test coverage of the final model differs from the independent calculation")
    sealed_log = workdir / "logs" / "model_log.json"
    if not sealed_log.exists() or json.loads(sealed_log.read_text(encoding="utf-8")).get("evaluate_test") is not False:
        problems.append("the sealed run's log was overwritten by the test-year run")
    if not (workdir / "results" / "q2_summary.json").exists() or not (workdir / "results" / "q2_summary_test.json").exists():
        problems.append("the two summary files are not both present")
    for name in ("q2_coverage_test.png",):
        if not (workdir / "figures" / name).exists():
            problems.append(f"figure {name} not written")
    return problems


def scenario(name, workdir, t, hist, expected, fresh=True, key=True, extra=None, **run):
    if fresh:
        shutil.rmtree(workdir, ignore_errors=True)
        prepare(workdir, t, key)
    started = time.time()
    log, errors, stderr = run_notebook(workdir, hist, **run)
    got = {c: log["checks"].get(c, {}).get("verdict") for c in expected}
    problems = [f"{c}: expected {expected[c]}, got {got[c]}" for c in expected if got[c] != expected[c]]
    allowed_error = run.get("edit") is not None
    problems += [f"error in a cell: {e.get('ename')}: {e.get('evalue')}" for e in errors if not allowed_error]
    problems += [f"warning printed: {''.join(o.get('text', ''))[:200]}" for o in stderr]
    if extra:
        problems += extra(workdir)
    print(f"{'PASS' if not problems else 'FAIL'}  {name}  ({time.time() - started:.0f} s)")
    for p in problems:
        print(f"      - {p}")
    return problems


def copies_match():
    "03_model_test.ipynb must be 03_model.ipynb with only the switch (and the title banner) changed."
    test_copy = NOTEBOOK.with_name(NOTEBOOK.stem + "_test.ipynb")
    if not test_copy.exists():
        return [f"{test_copy.name} not found"]
    a, b = nbformat.read(NOTEBOOK, as_version=4), nbformat.read(test_copy, as_version=4)
    if len(a.cells) != len(b.cells):
        return ["the two copies have different numbers of cells"]
    problems = []
    for i, (x, y) in enumerate(zip(a.cells, b.cells)):
        if x.source == y.source:
            continue
        if x.cell_type == "code" and x.source.replace("EVALUATE_TEST = False", "EVALUATE_TEST = True ") == y.source:
            continue
        if i == 0 and y.source.startswith(x.source.splitlines()[0]):
            continue
        problems.append(f"cell {i} differs between the two copies")
    return problems


def main():
    t = synthetic_table()
    hist = histories(t)
    m = t[t["split"].isin(["train", "validate", "test"])]
    print(f"testing {NOTEBOOK.name} on a synthetic table of {len(t):,} CVEs "
          f"({int(m['label_365'].sum())} exploited in the modelling period; {len(hist)} change histories)\n")
    base = Path(tempfile.mkdtemp(prefix="model_tests_"))
    sealed = {c: "PASS" for c in SEALED_CHECKS}
    opened = {**sealed, "G2-test-evaluated": "PASS"}
    failures = copies_match()
    print(f"{'PASS' if not failures else 'FAIL'}  0. {NOTEBOOK.stem}_test.ipynb differs from {NOTEBOOK.name} only in the switch")
    for p in failures:
        print(f"      - {p}")
    failures += scenario("1. sealed run: validation results match independent answers; 2024 untouched",
                         base / "main", t, hist, sealed, extra=lambda w: sealed_checks(w, t))
    failures += scenario("2. test year opened: frozen choices, one logged opening, 2024 scored",
                         base / "main", t, hist, opened, fresh=False, evaluate_test=True,
                         extra=lambda w: opened_checks(w, t, 1))
    failures += scenario("3. opened again with the same choices: still PASS, two openings logged",
                         base / "main", t, hist, opened, fresh=False, evaluate_test=True,
                         extra=lambda w: opened_checks(w, t, 2))
    damaged = sorted((base / "main" / "data" / "raw" / "nvd_history").glob("*.json"))[0]
    damaged.write_text(damaged.read_text(encoding="utf-8")[:50], encoding="utf-8")      # as if cut short

    def repaired(w):
        try:
            json.loads(damaged.read_text(encoding="utf-8"))
            return []
        except json.JSONDecodeError:
            return ["the damaged cache file was not fetched again"]
    failures += scenario("3b. a damaged cache file (an interrupted run) is fetched again",
                         base / "main", t, hist, sealed, fresh=False, extra=repaired)
    failures += scenario("4. no network and no key: audit and PyTorch check are WARN, models unaffected",
                         base / "offline", t, hist, {**sealed, "C2-description-history": "WARN",
                                                      "F1-pytorch-readiness": "WARN"}, key=False, network="down")
    leak = ('FEATURE_COLUMNS = ["cna", ', 'FEATURE_COLUMNS = ["diag_nvd_score", "cna", ')
    def gave_up_early(w):
        calls = (w / "_calls.txt").read_text(encoding="utf-8").count("cvehistory") if (w / "_calls.txt").exists() else 0
        hist_rows = len(pd.read_csv(w / "results" / "q2_description_history.csv"))
        return ([] if 5 <= calls <= 12 else [f"{calls} history requests with the NVD unreachable (expected 5-12)"]) + \
               ([] if hist_rows > 0 else ["the audit table is empty"])
    failures += scenario("4b. a key but no network: the audit gives up after five failed requests, C2 WARN",
                         base / "offline_key", t, hist, {**sealed, "C2-description-history": "WARN",
                                                          "F1-pytorch-readiness": "WARN"}, key=True, network="down",
                         extra=gave_up_early)
    failures += scenario("5. a forbidden column among the features: B2 FAIL, the run stops before any model",
                         base / "leak", t, hist, {"B2-inputs-permitted": "FAIL"}, edit=leak,
                         extra=lambda w: ["a model table was written"] if (w / "results" / "q2_validation_models.csv").exists() else [])
    print(f"\n{'ALL SCENARIOS PASSED' if not failures else f'{len(failures)} PROBLEM(S) FOUND'}")
    if failures:
        print(f"the test folders are kept for inspection: {base}")
        sys.exit(1)
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
