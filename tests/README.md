# Offline tests

## The acquisition notebook (01)

These tests run `01_acquire_data.ipynb`, unchanged, against simulated versions of the NVD, KEV and
EPSS services, in eight scenarios. They use no network, take under a minute, and work in temporary folders, so the
project's own `data/` and `logs/` folders are never touched.

### How to run

From the project folder:

```
python tests/run_acquisition_tests.py
```

The runner needs `nbclient`, `nbformat` and `ipykernel`, which are installed with Jupyter. It ends with
`ALL SCENARIOS PASSED`, or lists every problem and keeps the test folders for inspection.

### What is tested

| Scenario | What it shows |
|:--|:--|
| 1. Clean run | Every check gives its expected verdict. A server error is retried, and a window whose total changes mid-download is fetched again. The labels match an independent calculation. Every EPSS value matches its source. Missing EPSS scores are taken from the next day, and are marked as late. No half-written files are left behind. |
| 2. Re-run in the same folder | Finished windows and days are skipped, and the results are unchanged. |
| 3. A window keeps failing | The failure is named, and no incomplete table is saved for a later notebook to pick up. |
| 4. Re-run after the outage | The missing windows are fetched, and the run completes normally. |
| 5. A newer KEV catalogue exists | The pinned snapshot is still used, nothing is downloaded from CISA, and every table's fingerprint is unchanged. |
| 6. Unpinned (`KEV_SNAPSHOT = None`) | Today's catalogue is downloaded; the labels are unchanged, and the fingerprints name exactly the tables that changed (the analysis table and the KEV snapshot). |
| 7. The pinned version's files are missing | Today's catalogue is used instead, and the KEV check is `WARN`. |
| 8. No validation report | Count comparisons become `WARN` instead of passing silently. |

The expected answers are computed in `run_acquisition_tests.py` from the simulated data, not by the
notebook's own code, so a bug in the notebook can't hide by agreeing with itself.

### The simulated data

`fake_services.py` builds 336 synthetic CVEs (12 per download window, one of them withdrawn) and
answers requests the way the real services do. It includes the cases the notebook must handle:

- pagination
- a transient server error
- KEV entries dated to the catalogue's first day
- listings on day 0, 365 and 366, and before publication
- an EPSS file missing on the main host
- a day missing on every host
- a CVE missing from its target day's file

To test a copy of the notebook (for example, after editing it), pass its path:

```
python tests/run_acquisition_tests.py path/to/copy.ipynb
```

### Checking that the tests can fail

Four deliberate bugs were planted in copies of the notebook while these tests were written. All were
caught:

- **Day 365 no longer counted as exploited:** the notebook's label self-test fails, and no table is saved.
- **A KEV-derived column marked as a model input:** the notebook's leakage guard fails, the table is not
  saved, and the runner names the column.
- **The pinned snapshot ignored (always downloading):** scenarios 2 and 5 fail.
- **Fingerprints that ignore the values:** scenario 6 fails, because the changed table is not noticed.

## The descriptive notebook (02)

```
python tests/run_descriptive_tests.py
```

The runner builds a synthetic analysis table of 24,000 CVEs (same columns and types as the real one),
runs `02_descriptive_analysis.ipynb` on it unchanged with a simulated NVD Source API, and compares the
saved tables with answers computed in the runner itself: severity-band counts, Wilson intervals (against
SciPy's `binomtest`), triage coverage and effort, Q3 medians and on-or-before shares, the merging of a
publisher's two identifiers, the late-listing count, that every figure is written, and that every
saved CSV can be read back without any label turning into a missing value. It takes under
a minute and works in temporary folders.

| Scenario | What it shows |
|:--|:--|
| 1. Clean run | Every check passes and every table matches the independent answers. |
| 2. NVD unreachable | Publisher names fall back to domains (`B2` is `WARN`); every number is unchanged. |
| 3. No acquisition log | The comparison with the acquisition run becomes `WARN`. |
| 4. Table differs from the log | `B1` fails, so a stale or edited table is not analysed silently. |

Two deliberate bugs were planted in copies of the notebook: a CVSS score of exactly 7.0 no longer
counted as High, and listings on the publication day no longer counted as "on or before". The runner
caught both. The CSV round-trip check was added on November 13, after a real bug: the label "None"
(no privileges, no user interaction) was read back by pandas as a missing value. The previous version
of the notebook fails it; the current one passes.

## The model notebook (03)

```
python tests/run_model_tests.py
```

The runner builds a synthetic table of 24,000 CVEs whose exploitation depends on the publisher, the
severity, the attack vector and a trait that only the description reveals. It also plants
exploitation sentences in some descriptions: half were there on publication day, and half were added
after the KEV listing. It simulates the NVD change-history API and PyPI, runs `03_model.ipynb`
unchanged, and checks the notebook's saved results against answers computed in the runner. These
include coverage at each effort, computed group by group with pandas (a different method from the
notebook's NumPy code); the selection fingerprint; the audit's count of sentences added after the
listing; and that no exploitation word reaches the model. Some planted histories start 30 days after
publication, as many real ones do, and must be labelled as undatable rather than "at publication".
Before the scenarios, it checks that `03_model_test.ipynb` differs from `03_model.ipynb` only in the
test-year switch and the title, and the opened scenarios check that the sealed run's log and summary
are not overwritten.

| Scenario | What it shows |
|:--|:--|
| 1. Sealed run | Every check passes, the 2023 results match the independent answers, and nothing about 2024 is read or written. |
| 2. Test year opened | The choices are frozen, one opening is logged with the right fingerprint, and the 2024 scores and results are written and match the independent answers. |
| 3. Opened again, same choices | Still `PASS`; two openings logged. |
| 3b. A damaged cache file | A history file cut short (as by an interrupted run) is fetched again. |
| 4. No network, no key | The audit and the PyTorch check are `WARN`, and the models are unaffected. |
| 4b. A key but no network | The history lookups give up after five failed attempts instead of waiting on every CVE; `C2` is `WARN`. |
| 5. A forbidden column among the features | `B2` fails and the run stops before any model is trained. |

Three deliberate bugs were planted in copies of the notebook, and each one was caught:

- the cleaning step switched off: `C1` fails;
- ties in scores ignored: `A1` fails, and the baselines' coverage no longer matches the independent answers;
- the encoders fitted on 2023 as well as the training period: `D1` fails.

The suite also passes on Python 3.10 with pandas 2.3 and scikit-learn 1.7.

## The random-split companion (03b)

```
python tests/run_split_tests.py
```

The runner first checks that every function `03b_random_split_check.ipynb` shares with
`03_model.ipynb` (evaluation, cleaning, features, fitting) is word for word the same. It then runs
`03_model.ipynb` (sealed) on the synthetic table above, and the companion notebook on its outputs.
It checks that the companion used exactly the training and validation CVEs, that the same-size
designs match the training period, that no CVE was scored by a model fitted on it, that the forward
rows equal 03's validation results, that the steps add up to the total, and that nothing about 2024
is written.

| Scenario | What it shows |
|:--|:--|
| 1. After 03 | Every check passes and the results are consistent. |
| 2. Planted bug: the "grouped" split ignores publisher-weeks | `S3` fails. |
| 3. The frozen choices edited after 03 ran | `S1` (fingerprint) and `S2` (the model no longer reproduces 03's scores) fail. |
| 4. 03 not run yet | The notebook stops at once with a message to run `03_model.ipynb` first. |

## The EPSS comparison (04)

```
python tests/run_epss_tests.py
```

The runner first checks that every function `04_epss_comparison.ipynb` shares with `03_model.ipynb`
(records, evaluation, chart style, publisher names, coverage curves) is word for word the same. It
then runs `03_model.ipynb` with the test year opened on the synthetic table above, builds a synthetic
EPSS benchmark with a known structure (a floor score shared by most CVEs, CVEs not yet scored on day 1,
scores from a fallback day, and high scores for exploited CVEs once KEV lists them, as EPSS reads KEV),
and runs the comparison notebook unchanged. Its results are checked against answers computed in the
runner by another method: every coverage (group by group with pandas), the exploited CVEs kept on
equal information, that the four groups of exploited CVEs add up and agree with the coverage, that
every difference is the difference of the coverages, and the scores file for the demo.

| Scenario | What it shows |
|:--|:--|
| 1. Normal run | Every check passes and every result matches the independent answers. |
| 2. Planted bug: "already listed" judged on the publication day instead of EPSS's day | `D1` fails. |
| 3. The frozen choices edited after 03 ran | `B1` fails (fingerprint). |
| 4. Two EPSS model versions, and a score taken 5 days late | `B2` fails. |
| 5. The test year opened twice | `B1` is `WARN`; everything else passes. |
| 6. 03_model_test.ipynb not run | The notebook stops at once with a message naming what to run first. |

The check in Step 13 is written differently from the function it checks, on purpose: an early
version used the same expression in both, and the planted bug of scenario 2 slipped through.

## The PyTorch extension (05)

```
python tests/run_nn_tests.py
```

The language model must be downloaded from Hugging Face, so the runner replaces it with a stand-in that
turns each description into 384 numbers from its words (the synthetic descriptions still carry their
signal); PyTorch itself is real. It first checks that the code 05 shares with `03_model.ipynb` is word
for word the same, and that the test-year copy differs only in the switch and the title. It then runs
03 (sealed, then opened) on the synthetic table, builds the synthetic EPSS benchmark, and runs 05.

| Scenario | What it shows |
|:--|:--|
| 1. Sealed run | Every check passes; the candidates are the best settings at 10% effort; their coverage matches an independent answer; 03's final model is reproduced on 2023; nothing about 2024 is read or written. |
| 2. Test-year copy in the same folder | The same fingerprint as the sealed run; one opening logged; the cached embeddings reused (only 2024 encoded); 2024 coverage and the equal-information counts match independent answers. |
| 3. A second sealed run | Exactly the same networks (deterministic training). |
| 4. Planted leak: a forbidden column among the inputs | `B2` fails and the run stops before any network is trained. |
| 5. Planted bug: early stopping keeps the last epoch | The network self-test `D1` fails. |

Both copies were also run end to end on the real analysis table with the stand-in model (about three
minutes each in the cloud): every check passed and the two fingerprints were equal.

## `run_app_tests.py` (the demo app)
Six scenarios, no network (builds the app's model first if it is missing, about a minute):
1. every block of `app/cve_model.py` marked "copied from 03_model.ipynb" is word for word in the notebook;
2. the app's model reproduces `03_model_test.ipynb`'s 2024 scores (largest difference at most 1e-4);
3. 44 saved 2024 NVD records (`tests/fixtures/nvd_sample_records.json`) are flattened by the live-lookup code exactly
   as `01_acquire_data.ipynb` did (field by field) and scored as 03 scored them;
4. the NVD lookup with a simulated server: found, unknown ID, HTTP refusal, withdrawn CVE, non-JSON answer, no network;
   the key travels only in a header; KEV and EPSS fall back gracefully;
5. for 150 random 2024 CVEs, the explanation's pushes add up exactly to the score;
6. every page runs (Streamlit's AppTest), and the comparison page reproduces `q4_all_cves.csv` and
   `q4_equal_information.csv`.
