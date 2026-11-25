"""Tests for the demo app (app/). Run from the project folder:   python tests/run_app_tests.py

1. The code copied from 03_model.ipynb into app/cve_model.py is word for word the notebook's.
2. The app's model, refitted on Nov 2021-2023, reproduces 03_model_test.ipynb's 2024 scores.
3. A live NVD record is flattened exactly as 01_acquire_data.ipynb did (saved 2024 records as stand-ins), and scored
   as 03 scored it.
4. The NVD lookup handles success, unknown IDs, refusals, withdrawn CVEs and no network, without the internet.
5. Every explanation adds up exactly to the model's score.
6. Every page runs without an error (through the navigation and on its own), and the comparison page
   reproduces notebook 04.
No network is needed; the model is built if missing (about a minute)."""
import json
import re
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))

import nbformat  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import requests  # noqa: E402

import cve_model as cm  # noqa: E402

RESULTS = []


def scenario(name):
    def wrap(fn):
        def run():
            t0 = time.perf_counter()
            try:
                problems = fn() or []
            except Exception:                                    # a crash is a failure, with its traceback
                problems = [traceback.format_exc(limit=3)]
            RESULTS.append((name, problems, time.perf_counter() - t0))
            print(f"{'PASS' if not problems else 'FAIL'}  {name}  ({time.perf_counter() - t0:.0f} s)")
            for p in problems:
                print("      " + p.replace("\n", "\n      "))
        return run
    return wrap


@scenario("1 · copied code is word for word 03_model.ipynb's")
def copied_code():
    nb = nbformat.read(ROOT / "03_model.ipynb", as_version=4)
    code = "\n".join(c.source for c in nb.cells if c.cell_type == "code")
    src = (ROOT / "app" / "cve_model.py").read_text(encoding="utf-8")
    blocks = re.findall(r"# copied from 03_model\.ipynb: begin (\w+)\n(.*?)# copied from 03_model\.ipynb: end", src, re.S)
    problems = [] if len(blocks) == 8 else [f"expected 8 copied blocks, found {len(blocks)}"]
    for name, block in blocks:
        if block.strip() not in code:
            problems.append(f"block '{name}' differs from 03_model.ipynb")
    return problems


@scenario("2 · the app's model reproduces 03's 2024 scores")
def model_reproduces():
    fm = cm.load_final_model() or cm.build_final_model()
    chk = fm.b["check"]
    sel = json.loads((ROOT / "results" / "q2_selection.json").read_text(encoding="utf-8"))
    problems = []
    if chk["max_abs_difference"] > 1e-4 or chk["rank_correlation"] < 0.99999:
        problems.append(f"check failed: {chk}")
    if fm.b["selection_sha256"] != sel["sha256"]:
        problems.append("the model was built from another selection than results/q2_selection.json")
    print(f"      max difference {chk['max_abs_difference']:.1e}, rank correlation {chk['rank_correlation']:.6f}")
    return problems


@scenario("3 · live records are flattened as 01 did, and scored as 03 did")
def live_flatten():
    recs = json.loads((ROOT / "tests" / "fixtures" / "nvd_sample_records.json").read_text(encoding="utf-8"))
    live = pd.DataFrame([cm.flatten_live(r) for r in recs])
    table = pd.read_parquet(ROOT / "data" / "processed" / "analysis_table.parquet",
                            columns=["cve_id", "split"] + cm.FEATURE_COLUMNS)
    m = live.merge(table, on="cve_id", suffixes=("_live", "_table"))
    problems = [] if len(m) >= 0.9 * len(live) else [f"only {len(m)} of {len(live)} records found in the table"]
    for col in cm.FEATURE_COLUMNS:
        a, b = m[f"{col}_live"], m[f"{col}_table"]
        bad = ~((a == b) | (a.isna() & b.isna()))
        if bad.any():
            problems.append(f"{col}: {int(bad.sum())} differ, e.g. {m.loc[bad, 'cve_id'].iloc[0]}")
    fm = cm.load_final_model()
    test = m[m["split"] == "test"]
    scores = fm.score(cm.model_frame(live[live["cve_id"].isin(test["cve_id"])].reset_index(drop=True)))
    saved = pd.read_parquet(ROOT / "data" / "processed" / "model_scores_test.parquet").set_index("cve_id")
    ids = live.loc[live["cve_id"].isin(test["cve_id"]), "cve_id"]
    diff = np.abs(scores - saved.loc[ids, cm.FINAL_NAME].to_numpy()).max()
    if diff > 1e-4:
        problems.append(f"live scores differ from 03's by up to {diff:.2g}")
    print(f"      {len(m)} records compared field by field; {len(ids)} scored, max difference {diff:.1e}")
    return problems


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers, self.text = status, body, headers or {}, json.dumps(body or "")

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.HTTPError(str(self.status_code))


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        if self.error:
            raise self.error
        return self.response


@scenario("4 · the NVD lookup handles every answer, offline")
def lookup_cases():
    real_sleep, cm.time.sleep = cm.time.sleep, lambda s: None          # no waiting in tests
    try:
        rec = json.loads((ROOT / "tests" / "fixtures" / "nvd_sample_records.json").read_text(encoding="utf-8"))[0]
        problems = []
        ok = FakeSession(FakeResponse(200, {"vulnerabilities": [{"cve": rec}]}))
        if cm.fetch_nvd(rec["id"], None, session=ok)["id"] != rec["id"]:
            problems.append("a found record is not returned")
        if "apiKey" in ok.calls[0]["headers"]:
            problems.append("an API key header was sent without a key")
        keyed = FakeSession(FakeResponse(200, {"vulnerabilities": [{"cve": rec}]}))
        cm.fetch_nvd(rec["id"], "test-key", session=keyed)
        if keyed.calls[0]["headers"].get("apiKey") != "test-key" or "test-key" in json.dumps(keyed.calls[0]["params"]):
            problems.append("the key must travel in a header, never in the URL")
        cases = {
            "unknown ID": FakeSession(FakeResponse(200, {"vulnerabilities": []})),
            "refusal": FakeSession(FakeResponse(403, None, {"message": "rate limit"})),
            "withdrawn": FakeSession(FakeResponse(200, {"vulnerabilities": [{"cve": {**rec, "vulnStatus": "Rejected"}}]})),
            "not JSON": FakeSession(FakeResponse(200, None)),
            "no network": FakeSession(error=requests.ConnectionError("offline")),
        }
        for name, session in cases.items():
            try:
                cm.fetch_nvd("CVE-2099-0001", None, session=session)
                problems.append(f"{name}: no error raised")
            except cm.LookupError_ as exc:
                print(f"      {name}: {exc}")
        kev, src = cm.fetch_kev(session=FakeSession(error=requests.ConnectionError("offline")))
        if kev is not None and "snapshot" not in src:
            problems.append("KEV without network should fall back to the saved snapshot")
        if cm.fetch_epss(["CVE-2024-3400"], session=FakeSession(error=requests.ConnectionError("offline"))) != {}:
            problems.append("EPSS without network should give an empty answer")
        if cm.parse_ids("cve-2024-3400, CVE-2024-3400;CVE-2025-12345 junk") != ["CVE-2024-3400", "CVE-2025-12345"]:
            problems.append("parse_ids")
        return problems
    finally:
        cm.time.sleep = real_sleep


@scenario("5 · every explanation adds up to the score")
def explanations():
    fm = cm.load_final_model()
    t = pd.read_parquet(ROOT / "data" / "processed" / "analysis_table.parquet", columns=["cve_id", "split"] + cm.FEATURE_COLUMNS)
    sample = t[t["split"] == "test"].sample(150, random_state=510).reset_index(drop=True)
    frame = cm.model_frame(sample)
    scores = fm.score(frame)
    worst = 0.0
    for i in range(len(frame)):
        e = fm.explain(frame.iloc[[i]])
        worst = max(worst, abs(sum(g["push"] for g in e["groups"]) - (e["logit"] - e["average_logit"])),
                    abs(e["score"] - scores[i]))
        for g in e["groups"]:
            cm.label_group(g)                                  # every group has a label
    return [] if worst < 1e-8 else [f"explanations off by up to {worst:.2g}"]


@scenario("6 · every page runs, and the comparison page reproduces 04")
def pages():
    from streamlit.testing.v1 import AppTest
    problems = []
    views = ["views/problem.py", "views/overview.py", "views/triage.py", "views/model_vs_epss.py",
             "views/what_we_learned.py"]
    at = AppTest.from_file(str(ROOT / "app" / "Home.py"), default_timeout=300).run()   # the app as started
    if at.exception:
        problems.append(f"Home.py (first page): {at.exception[0].value[:200]}")
    if hasattr(at, "switch_page"):                                   # each page through the navigation
        for view in views[1:]:
            at.switch_page(view).run()
            if at.exception:
                problems.append(f"{view} via the navigation: {at.exception[0].value[:200]}")
    for view in views:                                               # and each page on its own
        at = AppTest.from_file(str(ROOT / "app" / view), default_timeout=300).run()
        if at.exception:
            problems.append(f"{view}: {at.exception[0].value[:200]}")
    at = AppTest.from_file(str(ROOT / "app" / "views" / "model_vs_epss.py"), default_timeout=300).run()
    q4 = pd.read_csv(ROOT / "results" / "q4_all_cves.csv", index_col=0)
    fair4 = pd.read_csv(ROOT / "results" / "q4_equal_information.csv")
    expect = {"Model": q4.loc["final model", "coverage_10"], "EPSS, day 1": q4.loc["EPSS, day 1", "coverage_10"],
              "EPSS, day 7": q4.loc["EPSS, day 7", "coverage_10"], "EPSS, day 30": q4.loc["EPSS, day 30", "coverage_10"],
              "CVSS score": q4.loc["CVSS score, unscored slotted in", "coverage_10"],
              "Publisher's past rate": q4.loc["Publisher's past rate", "coverage_10"]}

    def shown():
        df = at.dataframe[0].value
        return {r: float(c.rstrip("%")) / 100 for r, c in zip(df["ranking"], df["coverage"])}

    got = shown()
    for name, value in expect.items():
        if abs(got.get(name, -1) - value) > 0.0006:
            problems.append(f"all CVEs, {name}: page {got.get(name)} vs notebook {value:.4f}")
    for h in (1, 7, 30):
        at.radio[0].set_value(f"Equal information: EPSS day {h}").run()
        got = shown()
        r4 = fair4[(fair4["epss_day"] == h) & np.isclose(fair4["effort"], 0.10)].iloc[0]
        for name, value in [("Model", r4["final_model"]), (f"EPSS, day {h}", r4["epss"])]:
            if abs(got.get(name, -1) - value) > 0.0006:
                problems.append(f"equal information day {h}, {name}: page {got.get(name)} vs notebook {value:.4f}")
    at = AppTest.from_file(str(ROOT / "app" / "views" / "triage.py"), default_timeout=300).run()
    at.text_area(key="ids_text").set_value("CVE-2024-3400 CVE-2023-5877 CVE-2024-21413").run()
    if at.exception:
        problems.append(f"triage with a list: {at.exception[0].value[:200]}")
    elif list(at.dataframe[0].value["CVE"]) != ["CVE-2024-3400", "CVE-2024-21413", "CVE-2023-5877"]:
        problems.append(f"triage order: {list(at.dataframe[0].value['CVE'])}")
    at = AppTest.from_file(str(ROOT / "app" / "views" / "problem.py"), default_timeout=300).run()
    at.select_slider(key="problem_effort").set_value(0.26).run()                  # the problem page's slider
    if at.exception:
        problems.append(f"problem page slider: {at.exception[0].value[:200]}")
    return problems


if __name__ == "__main__":
    print(f"app tests | project folder {ROOT}")
    for test in (copied_code, model_reproduces, live_flatten, lookup_cases, explanations, pages):
        test()
    failed = [name for name, problems, _ in RESULTS if problems]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} scenarios passed" + (f"; failed: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)
