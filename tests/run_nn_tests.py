"""Offline tests for 05_pytorch_extension.ipynb and its test-year copy.

Runs 03_model.ipynb on the synthetic table of run_model_tests.py (sealed, then with the test year opened,
as the project does), builds the synthetic EPSS benchmark of run_epss_tests.py, and runs the extension
notebook unchanged except for one thing: the pretrained language model, which needs a download from
Hugging Face, is replaced by a small stand-in that turns each description into 384 numbers from its
words (so the description still carries the synthetic table's signal). PyTorch itself is real. The
results are checked against answers computed here; planted problems must make the right check fail.

Usage, from the project folder:

    python tests/run_nn_tests.py

Needs torch, nbclient, nbformat, ipykernel, scipy and scikit-learn. Takes about ten minutes, uses no
network, and works in temporary folders, so the project's own data, results and logs are never touched.
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
from run_epss_tests import synthetic_epss                         # the synthetic EPSS benchmark
from run_split_tests import definitions                          # top-level definitions of a notebook

MODEL = TESTS.parent / "03_model.ipynb"
SEALED = TESTS.parent / "05_pytorch_extension.ipynb"
OPENED = TESTS.parent / "05_pytorch_extension_test.ipynb"
CHECKS = ["A1-evaluation-selftest", "B1-table-loaded", "B2-inputs-permitted", "C1-description-masking",
          "D0-cvss-parser-selftest", "C2-embeddings", "D1-network-selftest", "E1-networks-trained", "G1-selection-frozen"]
SHARED = ["now_iso", "check", "show_conditions", "save_table", "save_json", "stop", "pick_font", "save_figure",
          "Ranking", "coverage", "bootstrap_coverage", "tag", "evaluation_table", "difference",
          "load_acquisition_reference", "FEATURE_COLUMNS", "period_frame", "PUBLISHER_NAMES", "WORDPRESS",
          "publisher_of", "is_wordpress", "EXPLOITATION_PHRASES", "PHRASE", "has_phrase", "SENTENCE_END",
          "mask_exploitation", "COMPONENTS", "V4_NAMES", "vector_components", "CATEGORICAL", "NUMERIC",
          "structured_inputs", "StructuredEncoder", "coverage_curves"]

# A stand-in for sentence_transformers: a deterministic embedding of each text's words, 384 numbers, unit length.
FAKE = r'''
import hashlib, re, sys, types
import numpy as np
_WORDS = {}
def _word(w):
    if w not in _WORDS:
        _WORDS[w] = np.random.default_rng(int(hashlib.md5(w.encode()).hexdigest()[:8], 16)).normal(size=384)
    return _WORDS[w]
class SentenceTransformer:
    max_seq_length = 256
    def __init__(self, name, revision=None, device=None):
        self.name, self.revision = name, revision
    def get_sentence_embedding_dimension(self):
        return 384
    def tokenizer(self, texts, verbose=True):
        return {"input_ids": [[0] * (len(re.findall(r"[a-z]+", t.lower())) + 2) for t in texts]}
    def encode(self, texts, batch_size=32, show_progress_bar=False, convert_to_numpy=True, normalize_embeddings=True):
        with open("_encoded.txt", "a") as f:
            f.write(f"{len(texts)}\n")
        out = np.zeros((len(texts), 384))
        for i, t in enumerate(texts):
            for w in re.findall(r"[a-z]+", t.lower()) or [""]:     # like a real model, an empty text has a vector too
                out[i] += _word(w)
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        return out / np.where(norms > 0, norms, 1)
module = types.ModuleType("sentence_transformers")
module.SentenceTransformer, module.__version__ = SentenceTransformer, "stand-in"
sys.modules["sentence_transformers"] = module
'''


def shared_code_matches():
    a, b = definitions(MODEL), definitions(SEALED)
    return [f"{name} differs between 03 and 05" for name in SHARED if a.get(name) != b.get(name)]


def copies_match():
    a, b = nbformat.read(SEALED, as_version=4), nbformat.read(OPENED, as_version=4)
    differ = [i for i, (x, y) in enumerate(zip(a.cells, b.cells)) if x.source != y.source]
    switch = [i for i in differ if "EVALUATE_TEST = True " in b.cells[i].source]
    return len(a.cells) == len(b.cells) and len(differ) == 2 and 0 in differ and len(switch) == 1


def prepare(base, t, hist):
    "A project folder where 03 ran sealed and then opened, with the EPSS benchmark of notebook 01."
    rmt.prepare(base, t)
    for opened in (False, True):
        _, errors, _ = rmt.run_notebook(base, hist, evaluate_test=opened, notebook=MODEL)
        if errors:
            raise RuntimeError(f"03_model.ipynb did not run: {errors[0].get('evalue')}")
    synthetic_epss(t).to_parquet(base / "data" / "processed" / "epss_benchmark.parquet", index=False)


def run_nn(workdir, notebook=SEALED, edit=None):
    "Execute the notebook in workdir with the stand-in language model; return (log, errors, stderr)."
    nb = nbformat.read(notebook, as_version=4)
    for cell in nb.cells:
        if cell.cell_type == "code" and cell.source.lstrip().startswith("%pip"):
            cell.source = "pass  # %pip skipped in the offline test"
    if edit:
        cells = [c for c in nb.cells if c.cell_type == "code" and edit[0] in c.source]
        assert len(cells) == 1, "the planted edit did not match"
        cells[0].source = cells[0].source.replace(*edit)
    nb.cells.insert(0, nbformat.v4.new_code_cell(FAKE))
    try:
        NotebookClient(nb, timeout=3600, kernel_name="python3", resources={"metadata": {"path": str(workdir)}}).execute()
    except Exception as exc:
        if "CellExecutionError" not in type(exc).__name__:
            raise
    errors = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("output_type") == "error"]
    stderr = [o for c in nb.cells if c.cell_type == "code" for o in c.outputs if o.get("name") == "stderr"]
    name = "nn_log_test.json" if notebook == OPENED else "nn_log.json"
    path = workdir / "logs" / name
    log = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"checks": {}}
    return log, errors, stderr


def sealed_problems(w, t):
    "The sealed run: right choices, 03's rows reproduced, coverage matching an independent answer, 2024 untouched."
    problems, res = [], w / "results"
    val = t[t["split"] == "validate"].reset_index(drop=True)
    y = val["label_365"].to_numpy(int)
    grid = pd.read_csv(res / "q5_validation_grid.csv")
    models = pd.read_csv(res / "q5_validation_models.csv", index_col=0)
    sel = json.loads((res / "q5_selection.json").read_text(encoding="utf-8"))
    nn = pd.read_parquet(w / "data" / "processed" / "nn_scores_validate.parquet")
    m03 = pd.read_csv(res / "q2_validation_models.csv", index_col=0)
    final03 = json.loads((res / "q2_selection.json").read_text(encoding="utf-8"))["final_model"]
    if len(grid) != 12:
        problems.append("the grid does not have 3 feature sets x 4 settings")
    for fs, g in grid.groupby("feature_set"):
        best = g.sort_values(["coverage_10", "config"], ascending=[False, True]).iloc[0]
        if sel["candidates"][f"NN · {fs}"]["config"] != best["config"]:
            problems.append(f"the {fs} candidate is not the best setting at 10% effort")
    if sel["final_network"] != models.loc[list(sel["candidates"]), "coverage_10"].idxmax():
        problems.append("the final network is not the best candidate at 10% effort")
    for name in sel["candidates"]:
        for e in (0.05, 0.10, 0.26):
            if abs(models.loc[name, f"coverage_{round(e * 100)}"] - rmt.expected_coverage(nn[name].to_numpy(), y, e)) > 1e-9:
                problems.append(f"{name}: coverage at {e:.0%} differs from the independent answer")
    if abs(models.loc[f"03 · {final03}", "coverage_10"] - m03.loc[final03, "coverage_10"]) > 1e-9:
        problems.append("03's final model is not reproduced on 2023")
    for f in ("logs/test_openings_nn.json", "data/processed/nn_scores_test.parquet", "results/q5_test_results.csv"):
        if (w / f).exists():
            problems.append(f"{f} exists although the test year is sealed")
    for f in ("figures/q5_seed_spread.png", "figures/q5_coverage_validation.png", "data/processed/embeddings/train.npz"):
        if not (w / f).exists():
            problems.append(f"{f} not written")
    return problems


def opened_problems(w, t, encoded_before):
    "The test-year copy: same fingerprint, one opening, the cache reused, 2024 results matching independent answers."
    problems, res = [], w / "results"
    test = t[t["split"] == "test"].reset_index(drop=True)
    y = test["label_365"].to_numpy(int)
    sealed_log = json.loads((w / "logs" / "nn_log.json").read_text(encoding="utf-8"))
    opened_log = json.loads((w / "logs" / "nn_log_test.json").read_text(encoding="utf-8"))
    if sealed_log["checks"]["G1-selection-frozen"]["sha256"] != opened_log["checks"]["G1-selection-frozen"]["sha256"]:
        problems.append("the test-year copy froze different choices from the sealed copy")
    openings = json.loads((w / "logs" / "test_openings_nn.json").read_text(encoding="utf-8"))
    if len(openings) != 1:
        problems.append(f"{len(openings)} openings logged instead of 1")
    encoded = [int(n) for n in (w / "_encoded.txt").read_text().split()][encoded_before:]
    if sum(encoded) != len(test) + 20:              # 2024 once, plus the 20 re-encoded for the check; nothing else
        problems.append(f"the test-year copy encoded {sum(encoded)} texts instead of {len(test) + 20}: cache not reused")
    results = pd.read_csv(res / "q5_test_results.csv", index_col=0)
    nn = pd.read_parquet(w / "data" / "processed" / "nn_scores_test.parquet")
    final = json.loads((res / "q5_selection.json").read_text(encoding="utf-8"))["final_network"]
    for e in (0.05, 0.10, 0.26):
        if abs(results.loc[final, f"coverage_{round(e * 100)}"] - rmt.expected_coverage(nn[final].to_numpy(), y, e)) > 1e-9:
            problems.append(f"2024 coverage at {e:.0%} differs from the independent answer")
    fair = pd.read_csv(res / "q5_test_equal_information.csv")
    epss = pd.read_parquet(w / "data" / "processed" / "epss_benchmark.parquet")
    for h in (1, 7, 30):
        e = epss[epss["horizon_days"] == h].set_index("cve_id").reindex(test["cve_id"])
        day = e["score_day"].fillna(e["target_day"]).to_numpy()
        known = (y == 1) & test["kev_date_added"].notna().to_numpy() & (test["kev_date_added"].to_numpy() <= day)
        if fair.loc[fair["epss_day"] == h, "exploited_kept"].iloc[0] != int(y.sum() - known.sum()):
            problems.append(f"day {h}: wrong number of exploited CVEs kept on equal information")
    return problems


def scenario(name, workdir, expected, notebook=SEALED, edit=None, extra=None, expect_error=None):
    started = time.time()
    log, errors, stderr = run_nn(workdir, notebook, edit)
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
    base = Path(tempfile.mkdtemp(prefix="nn_tests_"))
    failures = shared_code_matches()
    print(f"{'PASS' if not failures else 'FAIL'}  0a. the code shared with 03_model.ipynb is word for word the same")
    for p in failures:
        print(f"      - {p}")
    if not copies_match():
        failures.append("the test-year copy differs from the sealed copy in more than the switch and the title")
    print(f"{'PASS' if copies_match() else 'FAIL'}  0b. the test-year copy differs only in the switch and the title")

    prepare(base / "main", t, hist)
    for folder in ("forbidden", "earlystop"):
        shutil.copytree(base / "main", base / folder)
    sealed = {c: "PASS" for c in CHECKS}
    failures += scenario("1. sealed run: every check passes, results match independent answers, 2024 untouched",
                         base / "main", sealed, extra=lambda w: sealed_problems(w, t))
    shutil.copytree(base / "main", base / "repeat")
    grid_before = pd.read_csv(base / "main" / "results" / "q5_validation_grid.csv")
    encoded_before = len((base / "main" / "_encoded.txt").read_text().split())
    failures += scenario("2. test-year copy: same fingerprint, cache reused, one opening, 2024 matches",
                         base / "main", {**sealed, "G2-test-evaluated": "PASS"}, notebook=OPENED,
                         extra=lambda w: opened_problems(w, t, encoded_before))
    (base / "repeat" / "results" / "q5_validation_grid.csv").unlink()
    def same_grid(w):
        again = pd.read_csv(w / "results" / "q5_validation_grid.csv")
        return [] if again.equals(grid_before) else ["a second run gave different networks"]
    failures += scenario("3. a second sealed run gives exactly the same networks", base / "repeat", sealed,
                         extra=same_grid)
    failures += scenario("4. planted leak: a forbidden column among the inputs: B2 FAIL, stop before training",
                         base / "forbidden", {"B2-inputs-permitted": "FAIL"},
                         edit=('"cvss_version", "cwe_primary"]', '"cvss_version", "cwe_primary", "diag_nvd_score"]'),
                         expect_error="not a permitted input")
    failures += scenario("5. planted bug: early stopping keeps the last epoch, not the best: D1 FAIL",
                         base / "earlystop", {"D1-network-selftest": "FAIL"},
                         edit=("        return net, best[1], history", "        return net, epoch, history"))
    print(f"\n{'ALL SCENARIOS PASSED' if not failures else f'{len(failures)} PROBLEM(S) FOUND'}")
    if failures:
        print(f"the test folders are kept for inspection: {base}")
        sys.exit(1)
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
