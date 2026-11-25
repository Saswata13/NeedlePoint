# NeedlePoint

**Find the needle on day one.** Which new software vulnerabilities will actually get attacked?

DSCI 510 course project (USC, Fall 2026). NeedlePoint ranks new CVEs on the day they are published, using
only what is known that day, by the chance that CISA lists them as exploited (KEV) within a year. It is
compared with the CVSS score, the publisher's past rate and EPSS.

## Folder layout
| Path | Contents |
|---|---|
| `00_*.ipynb` ... `05_*.ipynb` | The project notebooks, run in order from this folder (they read and write the folders below) |
| `Demo/NeedlePoint.ipynb` | The final demo notebook, with its pictures in `Demo/figures/` |
| `app/` | The NeedlePoint Streamlit app; `start_app.bat` starts it on Windows |
| `deploy/cve-triage-app/` | A self-contained, trimmed copy of the app for Streamlit Community Cloud |
| `tests/` | Offline tests for the notebooks and the app |
| `data/` | `raw/` (as downloaded), `interim/` and `processed/` (built by the notebooks) |
| `results/`, `figures/`, `logs/` | Tables, charts and run logs written by the notebooks |
| `auxiliary/` | `docs/` (proposal, charter, study notes, architecture pages, corrections log) and `demo/` (demo script, notebook explorer) |
| `.streamlit/`, `requirements.txt`, `requirements-lock.txt` | App theme; packages; the exact versions of a working run |

## Data sources
| Source | Role | Auth |
|---|---|---|
| NVD CVE API 2.0 (NIST) | Features: description, CWE and CVSS as supplied by the CNA at publication | API key |
| CISA KEV catalog | Label: confirmed exploited in the wild | none |
| EPSS (FIRST) | Benchmark: daily exploitation probability | none |

## Setup
1. `pip install -r requirements.txt`
2. Put your NVD API key in `.env` (replace the placeholder). Request one at
   https://nvd.nist.gov/developers/request-an-api-key
3. Run `00_validate_sources.ipynb` top to bottom (about 10 minutes). It writes `logs/validation_report.json`
   and `requirements-lock.txt` (the exact package versions of that run).
4. Run `01_acquire_data.ipynb` top to bottom (about 45-60 minutes; safe to re-run, it resumes).
   It writes the tables the analysis starts from (see below) and `logs/acquisition_log.json`.
   The data are fixed once downloaded: a re-run reuses the saved NVD windows and EPSS days and the
   **pinned** KEV snapshot (`KEV_SNAPSHOT = "2026.11.10"`), and fingerprints every table to prove it
   rebuilt the same content (check `F1-data-fingerprints`). Back up `data/raw/`: it is the only copy
   of the November 10, 2026 data, and the NVD cannot serve that state again.
5. Run `02_descriptive_analysis.ipynb` top to bottom (about a minute). It writes the tables in
   `results/`, the charts in `figures/`, and `logs/descriptive_log.json`.
6. Run `03_model.ipynb` top to bottom, with the test year **sealed** (about 7 minutes on a laptop;
   the first run also looks up about 150 CVE change histories at the NVD, roughly 10 more minutes,
   cached for later runs). Then, optionally, `03b_random_split_check.ipynb` (about 20 minutes): it
   reads 03's frozen choices and 2023 scores.
7. Once the 2023 results are final, run `03_model_test.ipynb` **once**. It is the same notebook with
   `EVALUATE_TEST = True`: the choices are frozen in `results/q2_selection.json` (its fingerprint must
   equal the sealed run's), 2024 is scored, and the opening is logged in `logs/test_openings.json`.
   It keeps its own run log and summary, so the sealed notebook's outputs stay as they are.
8. Run `04_epss_comparison.ipynb` top to bottom (about a minute; nothing is downloaded or fitted). It
   compares the 2024 scores of step 7 with EPSS 1, 7 and 30 days after publication, and writes the
   `q4_*` tables and charts, `data/processed/q4_scores_test.parquet` and `logs/epss_log.json`.
9. Run `05_pytorch_extension.ipynb` top to bottom, with the test year **sealed**. The first run installs
   PyTorch and sentence-transformers if missing (restart the kernel once afterwards), downloads the
   language model all-MiniLM-L6-v2 from Hugging Face (about 90 MB, once), and encodes the descriptions
   (cached in `data/processed/embeddings/`). Training 60 small networks takes roughly 10-20 minutes on a
   laptop. Once its 2023 results are final, run `05_pytorch_extension_test.ipynb` **once**, on the same
   computer: its selection fingerprint must equal the sealed run's.

10. Run the demo app: `python app/build_model.py` once (about a minute: it refits 03's final model on
   Nov 2021-2023 and checks that it reproduces `03_model_test.ipynb`'s 2024 scores; the app's home page can also
   do this with a button), then `streamlit run app/Home.py` (or double-click `start_app.bat`). It opens in the
   browser. Needs Streamlit 1.36 or later; 1.46 or later shows the pages as a top navigation bar.
11. The demo: open `Demo/NeedlePoint.ipynb` and run it top to bottom. It reads `data/processed/`
   and `results/` from the project folder, whether Jupyter is started in `Demo/` or in the project folder.

## Notebooks
- `00_validate_sources.ipynb` - validates all three sources before any analysis
- `01_acquire_data.ipynb` - downloads every CVE published 2016-2024, a dated KEV snapshot and the EPSS
  benchmark, and builds the analysis table
- `02_descriptive_analysis.ipynb` - Q1 (which publication-time traits go with exploitation, and what
  severity-based triage costs) and Q3 (how quickly exploited CVEs are listed), with 95% intervals
- `03_model.ipynb` - Q2: ranks new CVEs by predicted exploitation from publication-day data
  (baselines, logistic regression, gradient boosting; structured fields vs description text), tuned
  on 2023 with the test year sealed; includes the description leakage audit and the PyTorch go/no-go
  rule
- `03_model_test.ipynb` - the same notebook with the test year opened; run once to score 2024
- `03b_random_split_check.ipynb` - would a random train/test split have reported a different result?
  Refits 03's final model under four designs and compares them on the same 2023 CVEs
- `04_epss_comparison.ipynb` - Q4: our publication-day model against EPSS (days 1, 7 and 30) on the
  same 2024 CVEs, on all CVEs and on equal information (without CVEs KEV had already listed), with
  the disagreements between the two and a simple combination
- `05_pytorch_extension.ipynb` - the PyTorch extension: a small neural network reading frozen sentence
  embeddings of the cleaned descriptions plus 03's structured fields, chosen on 2023, compared with
  03's model; `05_pytorch_extension_test.ipynb` opens 2024 once and adds the comparison with EPSS

## Tests
`python tests/run_acquisition_tests.py` runs `01_acquire_data.ipynb` offline against simulated NVD, KEV
and EPSS services in eight scenarios (under a minute, no network).
`python tests/run_descriptive_tests.py` runs `02_descriptive_analysis.ipynb` on a synthetic table with
known answers in four scenarios (under a minute, no network).
`python tests/run_model_tests.py` runs `03_model.ipynb` on a synthetic table with a known signal and
planted exploitation sentences, in eight scenarios (about ten minutes, no network), after checking that
`03_model_test.ipynb` differs from `03_model.ipynb` only in the switch.
`python tests/run_split_tests.py` runs `03_model.ipynb` and then `03b_random_split_check.ipynb` on the
same synthetic table, in four scenarios (about two minutes), after checking that the code the two
notebooks share is word for word the same.
`python tests/run_epss_tests.py` runs `03_model.ipynb` with the test year opened and then
`04_epss_comparison.ipynb` on a synthetic EPSS benchmark, in six scenarios (about two minutes), after
checking that the code it shares with 03 is word for word the same.
`python tests/run_nn_tests.py` runs 03 and then both copies of `05_pytorch_extension.ipynb` with a
stand-in for the language model (no download), in five scenarios plus two code checks (about four
minutes). See `tests/README.md`.
`python tests/run_app_tests.py` checks the demo app in six scenarios (under a minute after the model is built, no
network): the code it copies from 03 is word for word the notebook's, its model reproduces 03's 2024 scores, live NVD
records are flattened as 01 did, the lookup survives every kind of failure, every explanation adds up to its score,
and every page runs and reproduces notebook 04.

## Data produced by 01_acquire_data.ipynb
| File | Contents |
|---|---|
| `data/processed/analysis_table.parquet` | One row per live CVE: CNA-supplied fields, the 365-day label, the split |
| `data/processed/analysis_table_columns.csv` | The role of every column; only `input` columns may feed a model |
| `data/processed/epss_benchmark.parquet` | Each 2024 CVE's EPSS score 1, 7 and 30 days after publication |
| `data/interim/nvd_2016_2024.parquet` | All NVD records 2016-2024, flattened |
| `data/raw/` | Raw NVD records per window, KEV snapshots, EPSS rows per day |

## Outputs of 02_descriptive_analysis.ipynb
| Folder | Contents |
|---|---|
| `results/` | 11 CSV tables (rates by period, severity, CVSS component, weakness and publisher; unseen publishers; triage rules; Q3 timing, change since 2022, late listings) and `descriptive_summary.json` |
| `figures/` | 7 charts at 200 dpi (`q1_*` for Q1, `q3_*` for Q3) |

## Outputs of 03_model.ipynb and 03_model_test.ipynb
| File | Contents |
|---|---|
| `results/q2_*.csv`, `results/q2_*.json` | Validation grid, models and differences, text ablation, sensitivity checks, top features, description audit, PyTorch decision, frozen selection, summary (and the 2024 results once opened) |
| `figures/q2_*.png` | Coverage curves (2023, and 2024 once opened), text ablation, top features |
| `results/q2_split_check*`, `figures/q2_split_check.png`, `logs/split_check_log.json` | From `03b_random_split_check.ipynb`: coverage of each design, the steps between them, details, summary, chart and run log |
| `data/processed/model_scores_validate.parquet` | 2023 scores of every ranking |
| `data/processed/model_scores_test.parquet` | 2024 scores of every ranking (written only when the test year is opened), for the EPSS comparison |
| `results/q2_summary.json`, `results/q2_summary_test.json` | Headline findings of the sealed run and of the test-year run |
| `logs/model_log.json`, `logs/model_log_test.json`, `logs/test_openings.json` | Run log of each copy; every opening of the test year with its selection fingerprint |

## Outputs of 04_epss_comparison.ipynb
| File | Contents |
|---|---|
| `results/q4_all_cves.csv`, `results/q4_differences.csv` | Coverage of every ranking on all 2024 CVEs; paired differences |
| `results/q4_equal_information.csv` | Final model against each EPSS day without the exploited CVEs KEV had already listed |
| `results/q4_listing_timing.csv`, `results/q4_epss_shape.csv`, `results/q4_sensitivity.csv` | When exploited CVEs reach KEV; how tied EPSS's scores are; sensitivity checks |
| `results/q4_overlap.csv`, `results/q4_disagreement_publishers.csv` | Exploited CVEs caught by both, one or neither; by publisher |
| `results/q4_summary.json` | Headline findings |
| `figures/q4_coverage.png`, `figures/q4_listing_timing.png`, `figures/q4_disagreement.png` | The three charts |
| `data/processed/q4_scores_test.parquet` | Every ranking's 2024 scores in one table, for the demo app |
| `logs/epss_log.json` | Run log |

## Outputs of 05_pytorch_extension.ipynb and its test-year copy
| File | Contents |
|---|---|
| `results/q5_validation_*.csv`, `results/q5_seed_spread.csv` | The grid, the candidates beside 03's models, the differences, and the five single networks per candidate (2023) |
| `results/q5_selection.json` | The frozen choices and their fingerprint |
| `results/q5_test_*.csv` | 2024 results, differences, and the comparison with EPSS on equal information (test-year copy) |
| `results/q5_summary.json`, `results/q5_summary_test.json` | Headline findings of each copy |
| `figures/q5_*.png` | Seed spread, coverage curves for 2023 (and 2024 once opened) |
| `data/processed/embeddings/*.npz` | The cached sentence embeddings, one file per period |
| `data/processed/nn_scores_validate.parquet`, `nn_scores_test.parquet` | The networks' scores |
| `logs/nn_log.json`, `logs/nn_log_test.json`, `logs/test_openings_nn.json` | Run logs; every opening of the test year for the networks |

## The demo app (`app/`)
| Page | What it does |
|---|---|
| The problem (`app/views/problem.py`) | The story for readers new to the topic: the flood of new CVEs, the few that get attacked, and how a ranked list helps |
| Overview (`app/views/overview.py`) | The 2024 result in one picture, the model, and notes on the data |
| Triage (`app/views/triage.py`) | Paste CVE IDs: ranked with "handle now" for a chosen capacity, where each would rank among 2024's CVEs, and the reasons behind each score; CVEs published after 2024 are looked up live at the NVD (CNA-only fields, as in 01). Or replay any month of 2024: the to-do list and how each ranking would have done |
| Model vs EPSS (`app/views/model_vs_epss.py`) | Coverage curves for every ranking on 2024 at any effort, on all CVEs or on equal information, plus the notebooks' intervals and differences |
| What we learned (`app/views/what_we_learned.py`) | The Q1 and Q3 findings of notebook 02, interactive |

`app/Home.py` sets up the navigation; `app/ui.py` and `app/story.py` hold the look and the illustrations.
`app/cve_model.py` holds the code shared with the notebooks (copied word for word from 03, checked by the tests),
the live lookup and the explanations; `app/model/final_model.joblib` is written by `app/build_model.py` and is
specific to the installed scikit-learn version (rebuild after upgrading). The NVD key in `.env` is used for live
lookups if present (never shown); without it, lookups are paced 6 s apart.
