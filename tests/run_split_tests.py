"""Offline tests for 03b_random_split_check.ipynb.

Runs 03_model.ipynb (sealed) on the synthetic table of run_model_tests.py, then runs the companion
notebook on its outputs and checks the results; also checks that the code the two notebooks share is
word for word the same.

Usage, from the project folder:

    python tests/run_split_tests.py

Needs nbclient, nbformat, ipykernel and scikit-learn. Takes a few minutes, uses no network, and works
in temporary folders, so the project's own data, results and logs are never touched.
"""
import ast
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

import nbformat
import pandas as pd
from nbclient import NotebookClient

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
import run_model_tests as rmt                                     # the synthetic table and the 03 runner

MODEL = TESTS.parent / "03_model.ipynb"
SPLIT = TESTS.parent / "03b_random_split_check.ipynb"
CHECKS = ["S0-evaluation-selftest", "S1-inputs-from-03", "S2-model-reproduced", "S3-designs-checked"]
SHARED = ["Ranking", "coverage", "bootstrap_coverage", "tag", "evaluation_table", "difference", "now_iso", "check",
          "show_conditions", "save_table", "save_json", "publisher_of", "EXPLOITATION_PHRASES", "PHRASE",
          "has_phrase", "SENTENCE_END", "mask_exploitation", "COMPONENTS", "V4_NAMES", "vector_components",
          "CATEGORICAL", "NUMERIC", "structured_inputs", "StructuredEncoder", "TextEncoder", "FEATURE_SETS",
          "build_features", "design", "fit_model", "predict", "publisher_baseline", "pick_font", "save_figure"]


def definitions(path):
    "Every top-level definition or assignment in a notebook's code cells: {name: source text}."
    found = {}
    for cell in nbformat.read(path, as_version=4).cells:
        if cell.cell_type != "code" or cell.source.lstrip().startswith("%"):
            continue
        for node in ast.parse(cell.source).body:
            names = [node.name] if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else []
            if isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            for name in names:
                found.setdefault(name, ast.get_source_segment(cell.source, node))
    return found


def shared_code_matches():
    a, b = definitions(MODEL), definitions(SPLIT)
    return [f"{name} differs between the two notebooks" for name in SHARED if a.get(name) != b.get(name)]


def run_split(workdir, edit=None):
    "Execute the companion notebook in workdir; return (log, errors, stderr)."
    nb = nbformat.read(SPLIT, as_version=4)
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
    log_path = workdir / "logs" / "split_check_log.json"
    log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else {"checks": {}}
    return log, errors, stderr


def result_problems(workdir, t):
    "Right CVEs, right sizes, forward rows equal to 03's, steps that add up, 2024 untouched."
    problems, res = [], workdir / "results"
    split = pd.read_csv(res / "q2_split_check.csv", index_col=0)
    diff = pd.read_csv(res / "q2_split_check_differences.csv")
    meta = json.loads((res / "q2_split_check.json").read_text(encoding="utf-8"))
    models = pd.read_csv(res / "q2_validation_models.csv", index_col=0)
    final = json.loads((res / "q2_selection.json").read_text(encoding="utf-8"))["final_model"]
    fit_period, train = t[t["split"].isin(["train", "validate"])], t[t["split"] == "train"]
    if meta["pool_cves"] != len(fit_period) or meta["pool_exploited"] != int(fit_period["label_365"].sum()):
        problems.append("the check did not use exactly the training and validation CVEs")
    fits = pd.DataFrame(meta["fits"])
    same = fits[fits["design"].str.endswith("same size")]
    if not ((same["cves"] == len(train)).all() and (same["exploited"] == int(train["label_365"].sum())).all()):
        problems.append("the same-size designs do not match the training period")
    if fits["rows_in_both"].sum() != 0:
        problems.append("a CVE was scored by a model fitted on it")
    if (fits.loc[fits["design"] == "random, grouped, same size", "publisher_weeks_in_both"] != 0).any():
        problems.append("the grouped design split a publisher-week")
    if fits.loc[fits["design"] != "random, grouped, same size", "publisher_weeks_in_both"].sum() == 0:
        problems.append("the ungrouped designs never split a publisher-week: grouping cannot be told apart")
    for e in (5, 10, 26):
        if abs(split.loc["forward (the design used) · final model", f"coverage_{e}"] - models.loc[final, f"coverage_{e}"]) > 1e-9:
            problems.append(f"forward coverage at {e}% differs from 03's validation table")
    for (kind, e), g in diff.groupby(["ranking", "effort"]):
        steps = g.set_index("what_changes")["change"]
        if abs(steps.drop("total: plain random split vs forward").sum() - steps["total: plain random split vs forward"]) > 1e-9:
            problems.append(f"the steps do not add up to the total ({kind}, {e:.0%})")
    for name in ("figures/q2_split_check.png", "results/q2_split_check_summary.json"):
        if not (workdir / name).exists():
            problems.append(f"{name} not written")
    if (workdir / "data" / "processed" / "model_scores_test.parquet").exists():
        problems.append("a 2024 file exists although the test year is sealed")
    return problems


def scenario(name, workdir, expected, edit=None, extra=None, expect_error=None):
    started = time.time()
    log, errors, stderr = run_split(workdir, edit)
    got = {c: log["checks"].get(c, {}).get("verdict") for c in expected}
    problems = [f"{c}: expected {expected[c]}, got {got[c]}" for c in expected if got[c] != expected[c]]
    if expect_error:
        if not any(expect_error in str(e.get("evalue", "")) for e in errors):
            problems.append(f"expected an error mentioning: {expect_error}")
    else:
        problems += [f"error in a cell: {e.get('ename')}: {e.get('evalue')}" for e in errors if not edit]
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
    base = Path(tempfile.mkdtemp(prefix="split_tests_"))
    passed = {c: "PASS" for c in CHECKS}
    failures = shared_code_matches()
    print(f"{'PASS' if not failures else 'FAIL'}  0. the code shared with 03_model.ipynb is word for word the same")
    for p in failures:
        print(f"      - {p}")

    rmt.prepare(base / "main", t)                                 # 03 first, sealed, as in the project
    _, errors, _ = rmt.run_notebook(base / "main", hist)
    if errors:
        print("FAIL  03_model.ipynb did not run on the synthetic table; the companion cannot be tested")
        sys.exit(1)
    for folder in ("ungrouped", "edited"):
        shutil.copytree(base / "main", base / folder)

    failures += scenario("1. after 03: every check passes and the results are consistent", base / "main", passed,
                         extra=lambda w: result_problems(w, t))
    ungroup = ("StratifiedGroupKFold(SPLIT_FOLDS, shuffle=True, random_state=seed)\n"
               "                   .split(split_cves, y_split, split_groups)",
               "StratifiedKFold(SPLIT_FOLDS, shuffle=True, random_state=seed + 99)\n"
               "                   .split(split_cves, y_split)")
    failures += scenario("2. planted bug: the 'grouped' split ignores publisher-weeks: S3 FAIL", base / "ungrouped",
                         {"S3-designs-checked": "FAIL"}, edit=ungroup)
    sel = base / "edited" / "results" / "q2_selection.json"
    content = json.loads(sel.read_text(encoding="utf-8"))
    content["candidates"][content["final_model"]]["params"]["C"] = 99.0      # edited after it was frozen
    sel.write_text(json.dumps(content), encoding="utf-8")
    failures += scenario("3. frozen choices edited after 03 ran: S1 and S2 FAIL", base / "edited",
                         {"S1-inputs-from-03": "FAIL", "S2-model-reproduced": "FAIL"})
    (base / "empty").mkdir()
    rmt.prepare(base / "empty", t)                                # data, but 03 never run
    failures += scenario("4. 03 not run yet: a clear error before any work", base / "empty", {},
                         expect_error="run 03_model.ipynb")
    print(f"\n{'ALL SCENARIOS PASSED' if not failures else f'{len(failures)} PROBLEM(S) FOUND'}")
    if failures:
        print(f"the test folders are kept for inspection: {base}")
        sys.exit(1)
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
