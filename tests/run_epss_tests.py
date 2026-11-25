"""Offline tests for 04_epss_comparison.ipynb.

Runs 03_model.ipynb with the test year opened on the synthetic table of run_model_tests.py (as
03_model_test.ipynb would), builds a synthetic EPSS benchmark whose structure is known (a floor value
shared by most CVEs, CVEs not yet scored on day 1, high scores for exploited CVEs once KEV lists them),
runs the comparison notebook unchanged, and checks its results against answers computed here by other
methods. Planted problems must make the right check fail. Also checks that the code the notebook shares
with 03_model.ipynb is word for word the same.

Usage, from the project folder:

    python tests/run_epss_tests.py

Needs nbclient, nbformat, ipykernel, scipy and scikit-learn. Takes a few minutes, uses no network, and
works in temporary folders, so the project's own data, results and logs are never touched.
"""
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
sys.path.insert(0, str(TESTS))
import run_model_tests as rmt                                     # the synthetic table and the 03 runner
from run_split_tests import definitions                          # top-level definitions of a notebook

MODEL = TESTS.parent / "03_model.ipynb"
EPSS_NB = TESTS.parent / "04_epss_comparison.ipynb"
CHECKS = ["A1-evaluation-selftest", "B1-inputs-from-03", "B2-epss-benchmark", "E1-inclusion-selftest",
          "D1-equal-information"]
SHARED = ["now_iso", "check", "show_conditions", "save_table", "save_json", "Ranking", "coverage", "bootstrap_coverage",
          "tag", "evaluation_table", "difference", "pick_font", "save_figure", "PUBLISHER_NAMES", "WORDPRESS",
          "publisher_of", "is_wordpress", "coverage_row", "coverage_curves"]
HORIZONS = (1, 7, 30)
FLOOR = 0.00043


def shared_code_matches():
    a, b = definitions(MODEL), definitions(EPSS_NB)
    return [f"{name} differs between the two notebooks" for name in SHARED if a.get(name) != b.get(name)]


def synthetic_epss(t, seed=4):
    "One row per 2024 CVE and EPSS day, shaped like notebook 01's benchmark, with a known structure."
    rng = np.random.default_rng(seed)
    test = t[t["split"] == "test"].reset_index(drop=True)
    pub_day = test["published"].dt.normalize()
    rows = []
    for h in HORIZONS:
        target = pub_day + pd.Timedelta(days=h)
        late = rng.choice([0, 1, 2], len(test), p=[0.95, 0.04, 0.01])
        score_day = target + pd.to_timedelta(late, unit="D")
        listed = test["label_365"].to_numpy() & (test["kev_date_added"] <= score_day).to_numpy()
        noise = rng.random(len(test))
        epss = np.where(listed, 0.5 + 0.4 * noise,                                       # EPSS reads KEV
               np.where(noise < 0.6, FLOOR, np.round(0.0004 + 0.02 * noise ** 6, 5)))    # a floor shared by most
        epss = np.where(test["label_365"].to_numpy() & ~listed & (noise > 0.7), 0.05, epss)
        unscored = (rng.random(len(test)) < (0.08 if h == 1 else 0.01))
        rows.append(pd.DataFrame({"cve_id": test["cve_id"], "pub_day": pub_day, "horizon_days": h, "target_day": target,
                                  "score_day": score_day.where(~unscored), "days_late": np.where(unscored, np.nan, late),
                                  "epss": np.where(unscored, np.nan, epss), "percentile": np.where(unscored, np.nan, noise),
                                  "model_version": np.where(unscored, None, "v2023.03.01")}))
    return pd.concat(rows, ignore_index=True).sort_values(["cve_id", "horizon_days"]).reset_index(drop=True)


def prepare(base, t, hist):
    "A project folder where 03 has been run with the test year opened, plus the EPSS benchmark and log entry."
    rmt.prepare(base, t)
    _, errors, _ = rmt.run_notebook(base, hist, evaluate_test=True, notebook=MODEL)
    if errors:
        raise RuntimeError(f"03_model.ipynb (test year opened) did not run: {errors[0].get('evalue')}")
    epss = synthetic_epss(t)
    epss.to_parquet(base / "data" / "processed" / "epss_benchmark.parquet", index=False)
    log_path = base / "logs" / "acquisition_log.json"
    log = json.loads(log_path.read_text(encoding="utf-8"))
    log["checks"]["E2-epss-benchmark"] = {"rows": len(epss)}
    log_path.write_text(json.dumps(log), encoding="utf-8")


def run_epss(workdir, edit=None):
    "Execute the comparison notebook in workdir; return (log, errors, stderr)."
    nb = nbformat.read(EPSS_NB, as_version=4)
    if edit:
        cells = [c for c in nb.cells if c.cell_type == "code" and edit[0] in c.source]
        assert len(cells) == 1, "the planted edit did not match"
        cells[0].source = cells[0].source.replace(*edit)
    try:
        NotebookClient(nb, timeout=1200, kernel_name="python3", resources={"metadata": {"path": str(workdir)}}).execute()
    except Exception as exc:
        if "CellExecutionError" not in type(exc).__name__:
            raise
    errors = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("output_type") == "error"]
    stderr = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("name") == "stderr"]
    log_path = workdir / "logs" / "epss_log.json"
    log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else {"checks": {}}
    return log, errors, stderr


def result_problems(workdir, t):
    "Compare the saved results with answers computed here independently."
    problems, res = [], workdir / "results"
    test = t[t["split"] == "test"].reset_index(drop=True)
    y = test["label_365"].to_numpy(int)
    epss = pd.read_parquet(workdir / "data" / "processed" / "epss_benchmark.parquet")
    model = pd.read_parquet(workdir / "data" / "processed" / "model_scores_test.parquet")
    final = json.loads((res / "q2_selection.json").read_text(encoding="utf-8"))["final_model"]
    allc = pd.read_csv(res / "q4_all_cves.csv", index_col=0)
    diff = pd.read_csv(res / "q4_differences.csv")
    fair = pd.read_csv(res / "q4_equal_information.csv")
    overlap = pd.read_csv(res / "q4_overlap.csv", index_col=0)
    saved = pd.read_parquet(workdir / "data" / "processed" / "q4_scores_test.parquet")
    for h in HORIZONS:
        e = epss[epss["horizon_days"] == h].set_index("cve_id").reindex(test["cve_id"])
        score = e["epss"].fillna(-1.0).to_numpy()
        for eff in (0.05, 0.10, 0.26):
            want = rmt.expected_coverage(score, y, eff)
            if abs(allc.loc[f"EPSS, day {h}", f"coverage_{round(eff * 100)}"] - want) > 1e-9:
                problems.append(f"EPSS day {h} coverage at {eff:.0%} differs from the independent answer")
        day = e["score_day"].fillna(e["target_day"])
        known = (y == 1) & test["kev_date_added"].notna().to_numpy() & (test["kev_date_added"] <= day.to_numpy()).to_numpy()
        keep = ~known
        row = fair[(fair["epss_day"] == h) & np.isclose(fair["effort"], 0.10)].iloc[0]
        if row["exploited_kept"] != int(y[keep].sum()):
            problems.append(f"day {h}: wrong number of exploited CVEs kept on equal information")
        if abs(row["epss"] - rmt.expected_coverage(score[keep], y[keep], 0.10)) > 1e-9 or \
           abs(row["final_model"] - rmt.expected_coverage(model[final].to_numpy()[keep], y[keep], 0.10)) > 1e-9:
            problems.append(f"day {h}: equal-information coverage differs from the independent answer")
        if abs(overlap.loc[h, ["both", "final model only", "EPSS only", "neither"]].sum() - y.sum()) > 1e-6:
            problems.append(f"day {h}: the four groups of exploited CVEs do not add up")
        both_minus = overlap.loc[h, "both"] + overlap.loc[h, "final model only"]
        if abs(both_minus / y.sum() - allc.loc["final model", "coverage_10"]) > 1e-9:
            problems.append(f"day {h}: 'both' + 'final model only' is not the model's coverage")
    for e_ in (0.05, 0.10, 0.26):
        if abs(allc.loc["final model", f"coverage_{round(e_ * 100)}"] - rmt.expected_coverage(model[final].to_numpy(), y, e_)) > 1e-9:
            problems.append(f"final model coverage at {e_:.0%} differs from the independent answer")
    for _, r in diff.iterrows():
        k = f"coverage_{round(r['effort'] * 100)}"
        if abs(r["change"] - (allc.loc[r["ranking"], k] - allc.loc[r["minus"], k])) > 1e-9:
            problems.append(f"a difference is not the difference of the coverages ({r['ranking']} - {r['minus']})")
    if not saved["cve_id"].equals(test["cve_id"]) or len(saved.columns) != 8:
        problems.append("q4_scores_test.parquet does not hold one row per 2024 CVE and every ranking")
    for name in ("figures/q4_coverage.png", "figures/q4_listing_timing.png", "figures/q4_disagreement.png",
                 "results/q4_summary.json", "results/q4_sensitivity.csv"):
        if not (workdir / name).exists():
            problems.append(f"{name} not written")
    return problems


def scenario(name, workdir, expected, edit=None, extra=None, expect_error=None):
    started = time.time()
    log, errors, stderr = run_epss(workdir, edit)
    got = {c: log["checks"].get(c, {}).get("verdict") for c in expected}
    problems = [f"{c}: expected {expected[c]}, got {got[c]}" for c in expected if got[c] != expected[c]]
    if expect_error:
        if not any(expect_error in str(e.get("evalue", "")) for e in errors):
            problems.append(f"expected an error mentioning: {expect_error}")
    else:
        problems += [f"error in a cell: {e.get('ename')}: {e.get('evalue')}" for e in errors]
    problems += [f"warning printed: {''.join(o.get('text', ''))[:200]}" for o in stderr]
    if extra:
        problems += extra(workdir)
    print(f"{'PASS' if not problems else 'FAIL'}  {name}  ({time.time() - started:.0f} s)")
    for p in problems:
        print(f"      - {p}")
    return problems


def main():
    t = rmt.synthetic_table()
    hist = rmt.histories(t)
    base = Path(tempfile.mkdtemp(prefix="epss_tests_"))
    failures = shared_code_matches()
    print(f"{'PASS' if not failures else 'FAIL'}  0. the code shared with 03_model.ipynb is word for word the same")
    for p in failures:
        print(f"      - {p}")

    prepare(base / "main", t, hist)
    for folder in ("leaky", "edited", "versions", "twice"):
        shutil.copytree(base / "main", base / folder)
    passed = {c: "PASS" for c in CHECKS}
    failures += scenario("1. every check passes and the results match independent answers", base / "main", passed,
                         extra=lambda w: result_problems(w, t))
    failures += scenario("2. planted bug: 'already listed' judged on the publication day, not EPSS's day: D1 FAIL",
                         base / "leaky", {"D1-equal-information": "FAIL"},
                         edit=('(test["kev_date_added"] <= pd.to_datetime(epss[f"day_{h}"]))',
                               '(test["kev_date_added"] <= test["published"].dt.normalize())'))
    sel = base / "edited" / "results" / "q2_selection.json"
    content = json.loads(sel.read_text(encoding="utf-8"))
    content["candidates"][content["final_model"]]["params"]["C"] = 99.0       # edited after it was frozen
    sel.write_text(json.dumps(content), encoding="utf-8")
    failures += scenario("3. frozen choices edited after 03 ran: B1 FAIL", base / "edited", {"B1-inputs-from-03": "FAIL"})
    bench = base / "versions" / "data" / "processed" / "epss_benchmark.parquet"
    b = pd.read_parquet(bench)
    b.loc[b.index[:50], "model_version"] = "v2025.03.14"                          # a second EPSS model
    b.loc[b.index[60], "days_late"] = 5                                          # a score from much later
    b.to_parquet(bench, index=False)
    failures += scenario("4. two EPSS model versions and a late score: B2 FAIL", base / "versions",
                         {"B2-epss-benchmark": "FAIL"})
    openings = base / "twice" / "logs" / "test_openings.json"
    entries = json.loads(openings.read_text(encoding="utf-8"))
    openings.write_text(json.dumps(entries * 2), encoding="utf-8")
    failures += scenario("5. the test year was opened twice: B1 WARN, everything else PASS", base / "twice",
                         {**passed, "B1-inputs-from-03": "WARN"})
    (base / "empty").mkdir()
    rmt.prepare(base / "empty", t)                                               # data, but 03 never opened 2024
    failures += scenario("6. 03_model_test.ipynb not run: a clear error before any work", base / "empty", {},
                         expect_error="run 01_acquire_data.ipynb and 03_model_test.ipynb first")
    print(f"\n{'ALL SCENARIOS PASSED' if not failures else f'{len(failures)} PROBLEM(S) FOUND'}")
    if failures:
        print(f"the test folders are kept for inspection: {base}")
        sys.exit(1)
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
