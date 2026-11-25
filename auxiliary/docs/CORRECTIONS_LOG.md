# Corrections Log — DSCI 510 Project

**Purpose:** a single, complete record of every known error, unverified claim, and open design question, so nothing is rediscovered downstream. **No build step starts while a Critical item that affects it is open.**

**Last full audit:** October 9, 2026 · **Walkthrough additions:** snippets 6–16, walkthrough complete (Oct 9) · **Code fixes:** v3 notebook built, tested offline, and run by you (Oct 9; section I) — every artifact searched line by line; every claim below re-checked against a primary source or against the sample data on disk.

| Severity | Meaning |
|:--|:--|
| **Critical** | Would silently corrupt results (leakage, wrong labels, wrong arithmetic) |
| **High** | A wrong factual claim in a graded or shared document, or a defect that breaks a later stage |
| **Medium** | Robustness gap, or an imprecise claim that a careful reader could challenge |
| **Low** | Cosmetic, cleanup, or wording |

| Status | Meaning |
|:--|:--|
| **Open** | Known, not yet fixed |
| **Decision** | Needs Saswata's call before it can be fixed |
| **Verified** | Checked against data or a primary source on the date shown |
| **Fixed** | Corrected and re-tested |
| **Accepted** | Known limitation, deliberately not fixed, with reason |

---

## A. Code defects — `00_validate_sources.ipynb`

| ID | Sev. | Defect | Evidence | Fix | Status |
|:--|:--|:--|:--|:--|:--|
| **A1** | **Critical** | `flatten()` picks "any CVSS score not from `nvd@nist.gov`", assuming that means the vendor's CNA at publication. It doesn't: it also picks **CISA-ADP** scores, which are added after publication. | In the 9,302 live sample records, the chosen score came from: CNA **51.8%**, CISA-ADP **35.2%** (3,271), NVD analyst **13.0%**. CISA's ADP programme began May 8, 2024, so all 3,271 scores on these early-2023 CVEs were added over a year later. | Select the metric whose `source` equals the CVE's `sourceIdentifier` (the CNA); otherwise `None`. Add a diagnostic `cvss_source_kind` column (CNA / NVD / CISA-ADP / other), never used as a feature. | Verified by your run (Oct 9) |
| **A2** | **Critical** | `days_to_kev` is off by one day. KEV `dateAdded` is a date (read as midnight); NVD `published` is a timestamp. A same-day listing becomes a negative fraction, which `.dt.days` floors to **−1**. | 9 of the 13 "listed before publication" cases are same-day listings (e.g. CVE-2023-21715: published 20:15, listed the same day). Corrected: **4/50 (8%)** listed before the publication day; **13/50 (26%)** on or before it; median **16** days, not 15. | Compare calendar dates: `(dateAdded.normalize() - published.normalize()).dt.days`. Note in limitations: `published` is UTC, while KEV dates are US calendar dates. | Verified by your run (Oct 9) |
| **A3** | **High** | `flatten()` pools every CWE regardless of who assigned it. Weakness entries carry a `source` field, just like CVSS, so NVD- or ADP-added CWEs may be post-publication. | Same mechanism as A1. Not yet measured — the saved data no longer holds the CWE source. | Keep CNA-sourced CWEs separately and record the source. Quantify via V13. | Verified by your run (Oct 9) |
| **A4** | Medium | `http_get` sleeps on the final failed attempt (up to 48 s), then gives up without retrying. | Code reading, snippet 4. | Skip the sleep on the last attempt. | Verified by your run (Oct 9) |
| **A5** | Medium | `http_get` doesn't retry 500 / 502 / 504, which are often transient. | Code reading, snippet 4. | Add them to the retry set. | Verified by your run (Oct 9) |
| **A6** | Medium | Cells that catch only `ApiError` crash, instead of recording a FAIL, if the body isn't valid JSON (`ValueError`) or a field is missing (`KeyError`). | Code reading, snippets 5 and 11; snippet 13 catches `KeyError` but not the `ValueError` from `.json()`. Snippet 7 already does this correctly. | Catch `(ApiError, ValueError, KeyError)` consistently. | Verified by your run (Oct 9) |
| **A7** | Low | The join cell prints `has EPSS score: 4.0% (of the 500 queried)`, but the denominator is all 10,182 rows. | Walkthrough PDF §5, Defect 1. | Compute over the queried rows, and fix the label. | Verified by your run (Oct 9) |
| **A8** | Low | `traceback` is imported but never used. | Code reading, snippet 2. | Remove it. | Verified by your run (Oct 9) |
| **A9** | Low | `retries=4` actually means four *attempts* in total. | Code reading, snippet 4. | Rename to `max_attempts`. | Verified by your run (Oct 9) |
| **A10** | Medium | Each date window starts at the exact timestamp the previous one ended. If NVD treats both ends as inclusive, a CVE published exactly on a boundary is fetched twice. | Code reading, snippet 9. Inclusivity not yet tested (V15). | Deduplicate on `cve_id` after the full pull, and assert there are no duplicates. | Verified by your run (Oct 9) |
| **A11** | Low | The `.env` parser doesn't handle inline comments (`KEY=abc # note`) or an `export` prefix. | Code reading, snippet 3. | None — your `.env` doesn't use either. Documented. | Accepted |
| **A12** | Medium | The key test (snippet 6) has **never been seen to fail**. The expected failure pattern — 403s from about the 6th request — comes from documentation and third-party sources, not observation. A test that has never failed can't prove it would. | Found in snippet 6 walkthrough. | Add a one-off **negative-control** cell: the same burst *without* the key, expecting throttling. Also resolves V18. | Ran Oct 9 — inconclusive: 10/10 anonymous requests succeeded. Accepted: the 6 s pacing stays within even the anonymous limit, so the key doesn't matter to the results |
| **A13** | Low | Snippet 6's failure hint blames the key for **any** non-200, including a 503 during NVD maintenance. | Code reading, snippet 6. | Tailor the hint to the status codes actually seen; print a count of each. | Verified by your run (Oct 9) |
| **A14** | Low | Durations are timed with `time.time()`, which can jump if the system clock is adjusted. | Code reading, snippet 6. | Use `time.perf_counter()`, the clock intended for measuring intervals. | Verified by your run (Oct 9) |
| **A15** | Low | Comment `# documented floor with a key` on `time.sleep(0.6)`. It isn't a documented floor — it's arithmetic: 30 s ÷ 50 requests. | V17. | Correct the comment. | Verified by your run (Oct 9) |
| **A16** | Medium | Full-pull pacing: `http_get` pauses 1.0 s between requests. That's within the hard limit (50 per rolling 30 s), but NIST recommends sleeping "several seconds" between requests (NVDLib's docs say "at least 6"). | V17. | Use a 6 s pause for the full pull. Cost: roughly 10–20 extra minutes in total. | Verified by your run (Oct 9) |
| **A17** | Low | The Log4Shell probe prints `descriptions[0]` whatever its language, while `flatten()` correctly selects `lang == "en"`. | Code reading, snippet 7. | Use the same English-selection logic in both. | Verified by your run (Oct 9) |
| **A18** | Medium | The probe **discards provenance**: it prints CWE values without their `source`, shows only CVSS v3.1 entries, and omits each entry's `type`. That's exactly the information needed to resolve A1, A3, V13 and V14 — and it was in the response all along. | Code reading, snippet 7. | Print every metric version and every weakness entry with its `source` and `type`. | Verified by your run (Oct 9) |
| **A19** | Medium | The "known-answer" probe **asserts no answers**. `record(..., True, ...)` is hard-coded: PASS means "the fields parsed", not "the facts matched". A wrong record would still pass unless someone spotted it by eye. | Code reading, snippet 7. | Assert facts visible in the output itself: the ID matches the request; published in 2021; the description mentions Log4j; at least one CVSS v3.1 base score is 10.0. Once KEV is loaded, assert CVE-2021-44228 is in it. | Verified by your run (Oct 9) |
| **A20** | Medium | Snippet 8 passes on **any** non-200 — including 403 (throttled) or 503 (NVD down). A false PASS is possible: "date limit understood" while NVD was simply unavailable. | Code reading, snippet 8. | Pass only if the status is 404 **and** the `message` header mentions the 120-day limit; record that message as evidence. | Verified by your run (Oct 9) |
| **A21** | Low | Code comment `# 365 days: too wide`. The test range is **366 days** — 2024 is a leap year. | Computed: 365 days 23:59:59.999. | Correct the comment, or say "a full calendar year". | Verified by your run (Oct 9) |
| **A22** | Medium | `http_get`'s non-retryable branch reports only the response **body**. For NVD the explanation is in the `message` **header** and the body is empty — so a real 404 during the full pull would say `HTTP 404 from …:` with no reason given. The retry branch already reads the header; this branch doesn't. | Snippet 8 output (empty body, reason in header) + code reading of snippet 4. | Use the same header-then-body logic in both branches. | Verified by your run (Oct 9) |
| **A23** | Medium | `iter_cves` never reconciles counts. If `totalResults` changes between pages, or NVD returns an empty page early, paging stops or continues **silently** — a window could come back incomplete with no warning. | Code reading, snippet 9. | Remember the first page's total; warn if it changes; after the loop, compare records collected against the total and record any shortfall. | Verified by your run (Oct 9) |
| **A24** | Medium | The window check tests **width only**. A gap between windows passes. | **Demonstrated:** injecting a 1-day gap at each boundary skips 27 days of CVEs, and the check still reports PASS. It also measures in floored whole days. | Also check contiguity (each start equals the previous end) and coverage (first start = Jan 1 of the first year; last end = Jan 1 after the last), measuring width in exact seconds. | Verified by your run (Oct 9) |
| **A25** | Medium | Shared code (`http_get`, `NVDClient`, `flatten`) lives in notebook cells and depends on notebook globals (`SESSION`, `http_get`). The next notebook would need **copies**, and copies drift apart. The URL constant is also already defined twice (`NVD_URL`, `NVDClient.URL`). | Code reading, snippet 9. | Move shared code into one importable module (e.g. `cve_pipeline.py`) that every notebook imports. | Deferred to Stage 1 (plan step 8) — code kept in cells for readability; URL now defined once |
| **A26** | **High** | A trap in the **A1 fix**. `flatten()`'s loop walks CVSS versions in order (3.1 → 3.0 → 4.0 → 2.0) and **stops at the first version that has any entry**, whoever supplied it. Swapping in "match the CNA" without changing the loop would return `None` whenever the CNA scored only in v4.0 (or v2.0) but NVD or ADP had added a v3.1 score — losing a real CNA score. | **All 9,302** live chosen scores are v3.1 (CNA 4,820 · ADP 3,271 · NVD 1,211): v3.1 always wins because it is checked first. The saved data can't show how many CNAs scored only in another version — needs V13/V14. | Search **every** version for an entry whose `source` equals `sourceIdentifier`; take the first match in priority order; record its version. Unit-test with a hand-made record (CNA v4.0 only + ADP v3.1 → must return the CNA v4.0). | Verified by your run (Oct 9) |
| **A27** | Medium | `cwe_primary` is the **alphabetically first** CWE string, not the primary weakness. `sorted()` on strings also puts `CWE-1021` before `CWE-79`. | 933 live rows have ≥2 CWEs. ~~Example: CVE-2022-42475 gets CWE-197 instead of CWE-787~~ — **withdrawn Oct 9**: the v3 run shows Fortinet itself lists CWE-197 first, so this example did not illustrate the bug. 94 rows differ even from the numerically smallest ID. | After A3, take the CNA's CWEs **in the order the CNA listed them**. Don't rely on NVD's `type: Primary` label without checking what it means (V13) — it may simply mark NVD's own entry. | Verified by your run (Oct 9) |
| **A28** | Low | `startswith("CWE-")` silently drops NVD's placeholders `NVD-CWE-noinfo` and `NVD-CWE-Other`, so "no CWE" merges *never classified* with *classified as unknown*. | 740 live rows (8.0%) have no CWE; the split between the two cases isn't recoverable from saved data. | Keep the placeholder in a separate diagnostic column (with its source). | Verified by your run (Oct 9) |
| **A29** | Low | `to_naive_utc` uses `errors="coerce"`: an unparseable date becomes `NaT` **silently**, and the row would vanish from any time-based split. | 0 of 10,182 `published` values are NaT today — fine now, unguarded later. | After parsing, assert zero NaT in `published` (and report the count for KEV `dateAdded`). | Verified by your run (Oct 9) |
| **A30** | Low | Snippet 11 passes if the window returned **more than 1,000 rows** — an arbitrary floor. A window that silently stopped at 8,000 of 10,182 (the A23 failure) would still PASS. | Code reading, snippet 11. | Pass only if rows == `totalResults` (after A23's reconciliation) and every `published` falls inside the window. | Verified by your run (Oct 9) |
| **A31** | Medium | Snippet 12's sanity statistics are computed over **all** rows, Rejected included, and the CVSS-source table shows raw identifiers, top 5 only. Both misled us: the 8.6% / 15.9% figures went into the proposal (C5), and an unlabelled UUID in that table is how CISA-ADP got misread as a CNA (C13). | Live rows only: missing CVSS **0%**, missing CWE **8.0%**. The top-5 cut hides **2,921** live rows spread over 117 other sources. | Report on live rows, with the Rejected count on its own line; label each source by kind (CNA / NVD / CISA-ADP / other) and show the full kind breakdown. Same fix for snippet 15's `has CVSS vector` / `has CWE` lines, which also count Rejected rows. | Verified by your run (Oct 9) |
| **A32** | Low | The KEV cell passes if the catalog has **more than 1,000** entries, though the file states its own `count`. It also doesn't check for duplicate IDs or unparseable dates. | All three are fine today: 1,730 = `count`, 0 duplicate `cveID`s, 0 NaT `dateAdded`. | Pass only if rows == `count`, `cveID` unique, zero NaT. | Verified by your run (Oct 9) |
| **A33** | Low | The EPSS cell prints "**82% coverage**" (409 of 500). The 500 are simply the first 500 rows (Jan 1–7, 2023), and 91 of them are Rejected — which EPSS never scores (V2). | First 500 rows: 91 Rejected, 409 live; **409 of 409 live CVEs scored = 100%**. | Query live rows only and report coverage over them; if a sample is wanted, draw it at random across the window, not `head()`. | Verified by your run (Oct 9) |
| **A34** | Low | `fetch_epss` sends 100 IDs per request and trusts the response to hold all of them. If the API caps each response at a default page size (I believe 100 — V22), raising `chunk` later would **silently drop** scores. | Code reading, snippet 14. | Pass `limit` explicitly, and check returned + known-Rejected = requested for each chunk. | Verified by your run (Oct 9) |
| **A35** | **High** | **The join brings a label-side column into the analysis table**: `keep = ["cveID", "dateAdded", "knownRansomwareCampaignUse"]`. Ransomware use is known only *after* exploitation (B14), and it is now saved in `sample_merged.parquet`. | `sample_merged.parquet` has the column: 13 "Known", 37 "Unknown" — all 50 on KEV rows, none elsewhere. | Join `cveID` + `dateAdded` only; keep ransomware use in a separate KEV table for descriptive Q1 use. Regenerate the file on re-run, and add an assertion that no KEV column besides `dateAdded` is in the analysis table. | Verified by your run (Oct 9) |
| **A36** | Medium | Neither `merge` uses `validate=`. A duplicate key in KEV or EPSS would **silently duplicate NVD rows** and inflate every count. | Fine today: 10,182 rows in, 10,182 out; KEV has 0 duplicate IDs. Unguarded later. | `validate="many_to_one"` on both merges, plus an assert that the row count is unchanged. Strip and upper-case IDs on both sides before joining (all 1,730 KEV IDs are clean today). | Verified by your run (Oct 9) |
| **A37** | Low | The join's PASS condition is `rows > 0`, but its own markdown says PASS means a **non-zero KEV count near 0.5%** and warns that "thousands" means a wrong key. Neither is checked. | Code reading, snippet 15. | Pass if row count is unchanged and 0 < KEV share < ~2%; a zero count is a WARN (a quiet window is possible), not a PASS. | Verified by your run (Oct 9) |
| **A38** | Medium | **My checks don't run on your library versions.** Your notebook ran on Python **3.14.6 / pandas 3.0.3 / NumPy 2.4.6**; the shell I use on your computer has Python 3.10 / pandas **2.3.3**, and pandas 3 can't be installed there (it needs Python ≥ 3.11). *Update Oct 9: my cloud workspace already has pandas 3.0.2 on Python 3.11, so v3 was tested there; it cannot install packages.* pandas 3.0 changed defaults (string dtype, copy-on-write), so a check I run could behave differently from your run. `requirements.txt` only says `pandas>=2.0`, so a fresh install would pick yet another version. | `logs/validation_report.json` "versions"; `pip index versions pandas` on the VM tops out at 2.3.3. | Pin exact versions from your environment (`pip freeze` → `requirements-lock.txt`). During the fix phase, try a matching Python on the VM (e.g. via `uv`); where that fails, version-sensitive checks become cells **you** run. Make `pyarrow` required and drop the CSV fallback (it's installed; CSV loses date types and list columns). | Verified by your run (Oct 9) |
| **A39** | Medium | **Access dates are all the notebook's start time**, not when each source was actually fetched; NVD's is tied to the reachability ping (step 5), not the data pull; a failed source records `false` instead of nothing. Access dates are a graded requirement. | Report: all three = `2026-10-01T11:41:12-07:00`. | Stamp each source at the moment its data is fetched, plus the source's own version marker: KEV `dateReleased`, EPSS score `date`, NVD response `timestamp`. | Verified by your run (Oct 9) |
| **A40** | Medium | "**10/10 checks passed**" counts only steps that recorded a result. A step whose cell never ran (or was skipped) simply isn't in the denominator, so a partial run can still print N/N. | Code reading, snippet 16. | Define the expected step list up front; any missing step counts as FAIL. | Verified by your run (Oct 9) |
| **A41** | Medium | *Found while fixing.* `http_get` caught `ConnectionError` before `Timeout`. In `requests`, a **connect-timeout is both**, so a momentary network stall aborted the run instead of being retried. | `requests.exceptions.ConnectTimeout` subclasses both `ConnectionError` and `Timeout`. | Catch `Timeout` before `ConnectionError`. | Verified by your run (Oct 9) |
| **A42** | Medium | *Found by my offline test of the v3 fix for A35.* A name-based leak check ("is any KEV column in the joined table?") fired falsely: KEV and NVD **both** have a column called `cwes`. | Offline test run, Oct 9: the join FAILed on `cwes`. | Compare whole column sets: the join may add exactly `dateAdded`, `epss`, `percentile`. | Fixed and re-tested |
| **A43** | Low | *Found by my offline test.* `explode()` keeps duplicate row labels, which made the who-by-type cross-tab crash. | Offline test run, Oct 9. | Reset the index after `explode()`. | Fixed and re-tested |
| **A44** | Low | Step 06's PASS only shows NVD is answering; with no anonymous throttling observed (06b), it can't show the key is applied. | Your v3 run. | Notebook markdown for steps 06 and 06b now states this (added Oct 9, outputs untouched). | Done |

---

## B. Data-design corrections (leakage and feature rules)

The guiding rule: **a feature is allowed only if it existed at the moment of publication.** Every item below fails, or might fail, that test.

| ID | Sev. | Issue | Evidence | Resolution | Status |
|:--|:--|:--|:--|:--|:--|
| **B1** | **Critical** | Once A1 is fixed, many records may have **no CNA-provided severity score**. Up to ~48% of live sample records currently draw their score from a non-CNA source. The true share is unknown until a re-parse, because a CNA entry may exist but sit later in the list. | V3, V14. | **Decided Oct 9 (Saswata): CNA-only, with a "severity missing" indicator.** Severity features use only the score whose source matches the CVE's CNA; absent that, the score is missing and a binary flag records it. NVD and CISA-ADP scores are kept as diagnostic columns only, never as features. | Verified by your run (Oct 9) |
| **B2** | **Critical** | **Product configurations (CPE)** are NVD's post-publication work, yet the charter lists them as an *allowed* feature. | 2023 sample: present on 100% of live records, exploited or not — no signal *here*. But NVD largely stopped enriching from **Feb 12, 2024**, and since April 2026 has prioritised KEV CVEs. So in 2024 — our *test year* — presence is likely tied to the label. | Blacklist by principle (`n_configurations`, and any CPE-derived feature). | Enforced in v3: `diag_` prefix |
| **B3** | High | Reference counts and tags accumulate after publication. | `Exploit` tag on **42.0%** of exploited vs **32.3%** of other records. | Blacklist `n_references` and `ref_tags`. | Enforced in v3: `diag_` prefix |
| **B4** | High | `vuln_status` and `last_modified` describe NVD's work queue, not the vulnerability. | `Analyzed`: 50/145 exploited (34.5%); `Modified`: 0/9,156. | Blacklist. | Verified |
| **B5** | High | Withdrawn (`Rejected`) records aren't vulnerabilities. | **Verified (V1, V2):** exactly the 880 rows with no CVSS, and exactly the 91 EPSS gaps. | Drop them in Stage 2, logging row counts. | Verified |
| **B6** | High | Today's EPSS scores already "know" which CVEs were exploited. | The 2 exploited sample CVEs with scores read 0.995 and 0.99995. | Use historical scores as of publication (`date` parameter, from Apr 14, 2021). | Verified |
| **B7** | Medium | 2024, our test year, is the NVD backlog year — so any NVD-enrichment field is most distorted exactly where we evaluate. | V10. | Tabulate field coverage *per year* before freezing the feature set. | Open |
| **B8** | Medium | The effort/coverage and severity tables in the proposal and charter were computed on A1-contaminated scores. | V3. | Recompute after A1 is fixed. | Open |
| **B9** | Medium | Everything the API returns is the record **as it is today**, not as it was at publication — including the **description**, which CNAs can edit. A description edited to mention exploitation after the fact would leak the label. | **9,014 of 9,302** live records (96.9%) were last modified on **2026-06-17** — every record has been touched since publication. 13 live descriptions mention exploitation; 3 are in KEV (Apple CVE-2023-23529, -28205, -28206 — Apple states "may have been actively exploited" in its advisories at release, so these look legitimate). Current data can't prove when any text was written. | Test NVD's **CVE Change History API** (`/rest/json/cvehistory/2.0`) on a sample (V19). If it records field-level changes, reconstruct publication-time description, CVSS and CWEs from it — this would also settle A1/A3 directly. Otherwise, document as a limitation and run a sensitivity check excluding exploitation phrases. | Measured Oct 9 (V19): description edits are real and recorded. Plan in section I |
| **B10** | Medium | Once A1/A26 are fixed, CNA scores will arrive in **different CVSS versions** (3.1, 3.0, 4.0, 2.0). v4.0 is a different formula; one `cvss_score` column would mix scales. | Follows from A26. Share per version unknown until V13/V14. | **Stage 2 decision** after the re-pull: e.g. v3.x score as the main feature + a "scored only in another version" flag, or per-version columns. | Decision |
| **B11** | High | The **year in a CVE ID is not the publication year**. It's the year the ID was reserved, and some CNAs (notably VulDB) assign old-year IDs to old bugs disclosed now. The time-based split (train ≤2022 / validate 2023 / test 2024) must use the `published` date, never the ID. | In the Jan–Apr 2023 window, **3,600 of 9,302** live rows (38.7%) have an ID year before 2023, e.g. CVE-2014-125030 published 2023. | Rule: split and window only on `published`; add an assertion in Stage 2; check every document's wording ("CVEs from 2016–2024" must say *published*). | Enforced in v3: window check |
| **B12** | High | **CNA ≠ vendor.** The `cna` column is whoever *assigned* the CVE. Vendors that are their own CNA (Microsoft, Apple, Adobe) map cleanly; but MITRE, VulDB, GitHub, ZDI, WPScan, Patchstack and huntr assign CVEs for thousands of other vendors' products. The proposal's Q1 ("by vendor"), the single-vendor baseline, and the app's vendor breakdown all assume a vendor field we don't have. NVD's vendor field (CPE) is post-publication (B2). | **`cve@mitre.org`** is the largest CNA in the window (**1,960** rows) and the largest KEV contributor (**11 of 50**) — a mix of many vendors. 171 distinct CNA identifiers; all are email-style, none UUIDs. | **Stage 2 decision.** Use CNA as a legitimate publication-time feature under its real name. For vendor, evaluate the CNA-supplied `affected` vendor/product list in the CVE Program's own records (CVE JSON 5 / cvelistV5) — it's written by the CNA, but its edit history needs the same check as B9. Fall back to "CNA" wording if vendor isn't recoverable. | Decision |
| **B13** | **Critical** | **The 365-day label window collides with KEV's launch date.** KEV began on **Nov 3, 2021** (287 entries added that day). Any CVE published before ~Nov 2020 *cannot* be listed within 365 days of publication, so under the proposal's fixed 365-day window every such CVE becomes a **negative** — including the most famous exploited bugs (EternalBlue, CVE-2017-0144). Training on 2016–2020 would teach the model that exploited bugs aren't exploited. KEV's `dateAdded` for those entries reflects the catalog's creation and 2022 catch-up, not exploitation timing. | Your KEV file: **555** entries have ID years ≤2019 (ID year ≈ earliest possible publication year, B11), and essentially all were added 2021–2022: e.g. 2017 IDs → 14 in 2021, 61 in 2022, 11 later; 2013-and-earlier IDs → 96 added in 2022 alone. | **Decision (Saswata), before the proposal is updated.** Options: (a) model only CVEs published on/after Nov 3, 2021 — clean 365-day label; train Nov 2021–2022, validate 2023, test 2024; earlier years used for Q1 description only, labelled "ever listed". (b) Keep 2016–2024 with an "ever listed by snapshot date" label — simpler, but mixes observation times across years. (c) Hybrid. **Recommendation: (a)**; positives in the training span to be counted before deciding. | **Decided Oct 9: option (a)** — 128 / 145 / 149 positives (train / validate / test). See section I |
| **B14** | High | **KEV's own columns are label-side only.** `vendorProject`, `product`, `cwes`, `shortDescription`, `knownRansomwareCampaignUse`, `notes`, `dueDate` exist **only for exploited CVEs**, so any feature built from them is a perfect leak. In particular, KEV's `vendorProject` must not be used to solve B12. | By construction: these fields are filled only when a CVE is listed. | Rule: the join brings in `cveID` and `dateAdded` only; everything else stays in a separate KEV table for descriptive use. Check snippet 15's join. | Enforced in v3: join assertion |
| **B15** | High | **The EPSS benchmark must be defined precisely**, beyond B6's "use historical scores": (1) **which day** — a new CVE's first score appears around publication, so fix a rule such as "first available score on or after the publication date"; (2) **which model** — EPSS has been retrained several times, so 2022, 2023 and 2024 CVEs would be scored by different EPSS versions (dates to confirm, V22); (3) **which target** — EPSS estimates the probability of exploitation *activity in the next 30 days*, while our label is *KEV listing within 365 days*. They aren't the same question, so the comparison must say so. Also: historical EPSS starts **Apr 14, 2021**, so under B13 option (b) the 2016–early-2021 CVEs would have **no benchmark at all** — another point for option (a). | Code reading, snippet 14; B6; B13. | Write the three rules into the Stage 4 spec and the proposal's Q4 text; report EPSS version alongside each comparison. | Updated Oct 9 — see section I (first-day EPSS looks like a generic prior) |
| **B16** | Medium | **CVEs already in KEV when published.** If KEV listed a CVE *before* NVD published it, the outcome was already known at the "moment of prediction". Counting these as ordinary positives flatters any model, and EPSS, which would score them high from day one. | After the A2 fix: **4 of 50** sample KEV CVEs were listed before their NVD publication day. Extreme case: **CVE-2019-8720** (WebKitGTK) — in KEV on **May 23, 2022**, published by NVD (via Red Hat) on **Mar 6, 2023**, 288 days later. | **Stage 2 decision:** keep them labelled positive but report results with and without them; note the count in the report. | Rule: report with and without (numbers in B17) |
| **B17** | High | **For some CNAs, the CVE record is published weeks after the vendor's advisory** — so "at publication" can already be after exploitation is public. This is why many training positives were listed before publication (B16). | Train split: **35 of 128** positives (27%) were in KEV before their record's publication day — median 6 days earlier, up to 290. They're mostly 2022 Chrome, Apple and Mozilla CVEs (e.g. Firefox CVE-2022-26485/6: listed Mar 7, 2022; record published Dec 22, 2022). Validate: 13 of 145; test: 7 of 149. | Keep them as positives (they are real), but report every result **with and without** them (B16). Without them: 93 / 132 / 142 positives. | Rule |
| **B18** | High | **CISA-ADP writes an SSVC block into NVD records containing `"exploitation": "active"`** — the label itself, added after the fact. | Change history of CVE-2023-23529 and CVE-2022-44877: SSVC added by CISA-ADP in 2025–2026. | Blacklist: never parse SSVC, `cisaExploitAdd` or any `cisa*` field. `flatten()` already ignores them; add an assertion in Stage 2. | Rule |

---

## C. Factual errors in documents

### C-I. Proposal — `DSCI510_Proposal_Mukherjee.docx / .pdf` (due Oct 12) — fix first

| ID | Sev. | Location | Wrong | Correct | Status |
|:--|:--|:--|:--|:--|:--|
| **C1** | **High** | §1, "Timing compounds…" | "13 of the 50 (26%) were confirmed exploited before their CVE record was published"; median 15 days | **4 of 50 (8%)** were *listed in KEV* before their publication day; **13 (26%)** on or before it; median **16** days (A2). "Listed", not "confirmed exploited". | Open |
| **C2** | **High** | §1, same paragraph | "An independent industry report places the same measure at 23.4%… 120 days to 80 days" | Not the same measure. VulnCheck's figures cover **VulnCheck's own KEV list**; 23.43% is evidence of exploitation on or before publication day. 120→80 days is publication-to-listing for *that* list, not comparable to our 16-day CISA figure. Attribute it precisely, or drop it. | Open |
| **C3** | **High** | §3, Source 2 limits | "a User-Agent header is required in practice" | Unverified. "None published; we send a descriptive User-Agent as a courtesy." | Open |
| **C4** | **High** | §3, Expected data volume | "Approximately 250,000–300,000 CVE records… 2016 and 2024" | **Unverified estimate.** Measure it (V12) before submitting. | Open |
| **C5** | Medium | §6.1 | "15.9% of sample records lack a weakness classification"; "four mutually incomparable versions" | **8.0%** of live records (15.9% includes withdrawn ones). "Not directly comparable across major versions" — v3.0 and v3.1 score almost identically. | Open |
| **C6** | Medium | §1 table, and "15× Medium" | Built on A1-contaminated scores | Recompute from corrected data (B8). | Open |
| **C7** | Low | §3, Source 3 limits | "~100 CVEs per request" | "100 results per page by default." | Open |
| **C8** | Low | §5(a), §9 | Leakage story covers NVD only | *Optional improvement:* add CISA-ADP as a second post-publication source — it strengthens the finding. | Open |
| **C41** | Low | §4, Date-range cap | "Submitting a 365-day range returns HTTP 404…" | A **366-day** range (2024 is a leap year) — or simply "a full-year range". Same wording in walkthrough §2.2. | Walkthrough fixed (rev. 2); proposal open |

### C-II. Charter PDF — `DSCI510_Project_Charter_and_Methodology.pdf`

| ID | Sev. | Location | Wrong | Correct | Status |
|:--|:--|:--|:--|:--|:--|
| **C9** | **High** | §4.3, EPSS table | CVSS ≥ 7: "~82%" coverage; EPSS v4: "74.6%" coverage | **74.6% is the CVSS ≥ 7 coverage.** The ~82% figure has no source — I introduced it. EPSS v4: 6% effort, 47% efficiency; its coverage isn't stated (described as held roughly steady). | Fixed in revision 2 (Oct 9) |
| **C10** | **High** | §4.2, timing table | 13/50 listed before publication; 25th percentile −1; median 15 | Recompute with calendar days (A2): 4/50 before; median 16. | Fixed in revision 2 (Oct 9) |
| **C11** | **High** | §4.2 | "independently reproduces an industry report… 23.4%" | Different catalogue, different measure. At most "in the same range as". | Fixed in revision 2 (Oct 9) |
| **C12** | **High** | §5.4 | "Median time… fell from 120 days to 80 days" | Attribute to VulnCheck's KEV list. | Fixed in revision 2 (Oct 9) |
| **C13** | **High** | Stage 2(c)–(d); §8.1 | `134c704f…` described as an "opaque CNA UUID"; "prefer vendor-assigned" presented as implemented | It's **CISA-ADP**. Rewrite with the ADP explanation, and the A1 fix. | Fixed in revision 2 (Oct 9) |
| **C14** | **High** | Stage 4, "Allowed" list | Includes "counts of affected product configurations" | Move to the blacklist (B2), and add non-CNA CVSS and CWE. | Fixed in revision 2 (Oct 9) |
| **C15** | Medium | Appendix B | "User-Agent required in practice"; "~100 CVEs per request" | As C3 and C7. | Fixed in revision 2 (Oct 9) |
| **C16** | Medium | Stage 1; §6.3; Stage 2 output | "~250,000–300,000 records", "roughly 250,000 rows" | Replace with the measured figure (V12). | Fixed in revision 2 (Oct 9) |
| **C17** | Low | §2.2 | "roughly four hundred" CNAs | Unverified. Say "hundreds". | Fixed in revision 2 (Oct 9) |
| **C18** | Low | §9.3 | "That wastewater-style causal claims apply" | Leftover from the abandoned topic. Delete. | Fixed in revision 2 (Oct 9) |
| **C19** | Low | §2.3 | "1,470 new records in 48 hours" | About 55 hours; and drop the rate inference (same issue as C26). | Fixed in revision 2 (Oct 9) |
| **C20** | Low | Cover; Appendix C | Proposal due October 9 | October 12. | Fixed in revision 2 (Oct 9) |
| **C21** | Low | §3.1 | Log4Shell vector omits the Scope component | Add "Scope: Changed". | Fixed in revision 2 (Oct 9) |
| **C22** | Medium | §3.2–3.3 tables | Built on A1-contaminated scores | Recompute (B8). | Fixed in revision 2 (Oct 9) |

### C-III. Walkthrough PDF — `DSCI510_Validation_Notebook_Walkthrough.pdf`

Regenerate after the code fixes, since it documents code that is about to change.

| ID | Sev. | Location | Wrong | Correct | Status |
|:--|:--|:--|:--|:--|:--|
| **C23** | **High** | §2.2, §2.4, §3 (snippet 4) | "CISA's CDN rejects requests that do not identify themselves… would likely fail with a 403" | `requests` sends a default User-Agent; the descriptive one is a precaution, untested. | Fixed in revision 2 (Oct 9) |
| **C24** | **High** | §3 (snippets 7, 10) | Two scores described as "NVD + vendor's CNA"; UUID called a CNA; `flatten()` rule presented as correct | NVD + CISA-ADP; and the A1 fix. | Fixed in revision 2 (Oct 9) |
| **C25** | **High** | §3 (snippet 14) | "Thirteen of fifty, 26%… listed before publication… reproduces 23.4%" | As A2 and C11. | Fixed in revision 2 (Oct 9) |
| **C26** | Medium | §3 (snippet 5) | "~735 new vulnerabilities per day… backfilled" | A guess. Two readings close together can't give a rate. Delete. | Fixed in revision 2 (Oct 9) |
| **C27** | Low | §5, Defect 1 | "will be fixed" | Mark as fixed once A7 is done. | Fixed in revision 2 (Oct 9) |
| **C36** | Medium | §3 (snippet 6) | "Anonymously, those ten requests would have taken at least 60 seconds and thrown errors" | Wrong twice. Anonymous requests would come back *quickly* with (expected) 403s; and pacing 10 anonymous requests legally takes about 30 s, not 60. | Fixed in revision 2 (Oct 9) |

### C-IV. Notebook markdown — `00_validate_sources.ipynb`

| ID | Sev. | Cell | Wrong | Correct | Status |
|:--|:--|:--|:--|:--|:--|
| **C28** | **High** | Step 04 table | "CISA's CDN rejects anonymous requests with a bare 403" | Precaution, as C23. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C29** | **High** | Step 07 table | "One from the vendor's CNA, one from an NVD analyst"; "CNA as a UUID" | NVD analyst + CISA-ADP. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C30** | **High** | Note after step 07 | Score sources listed as CNA or NVD only | Add CISA-ADP. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C31** | **High** | Step 14 | "`days_to_kev` can be negative… Roughly a quarter" | As A2: 8% before the publication day; 26% on or before it. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C32** | Low | Step 13 | "~100 CVEs per request" | As C7. Note: "EPSS does not score withdrawn records" is now **verified** (V2) — keep it. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C37** | Low | Step 06 | Failure pattern stated as fact | Mark it as *expected per NVD's documented limits* until A12 confirms it. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C39** | Medium | Walkthrough §2.2 and §3 (snippet 7); notebook step 07 | Described as a known-answer check that would catch contradictions | Overstated until A19 is fixed — it currently checks only that the fields can be read. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C40** | Medium | Walkthrough §3 (snippet 8); notebook step 08 | (1) "would have… retried pointlessly" / "would have made our retry logic treat this as no such endpoint"; (2) "Our helper reads that header, which is why you can see the reason at all" | (1) Wrong: `http_get` never retries a 404 — it raises at once. The real consequence is A22: an error with no reason. (2) Wrong: the *cell* reads the header directly; the helper's error branch ignores it. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C42** | Low | Walkthrough §3 (snippet 9); notebook step 09 | "Keeps 400,000 records out of memory" / "instead of assembling a 400,000-element list" | Overstated: snippet 11 builds a list anyway. The real saving is that raw JSON pages aren't accumulated — only one page (≤ 2,000 raw records) is held at a time, and each is reduced to 17 fields. | Fixed (notebook v3 + walkthrough rev. 2) |
| **C43** | High | Proposal Q1, baselines, app (§§1, 3, 6–7) | "by vendor", "a single-vendor filter", "breakdown by vendor" | Our data identifies the **CNA**, not the vendor (B12). The Microsoft example is valid (Microsoft is its own CNA), but say "single-CNA rule" or define vendor once B12 is decided. | Open |
| **C44** | **High** | Proposal §2 sources, §5 split, §8 risks; charter label section | "Nine years" (2016–2024) as the modelling span; "a fixed 365-day observation window applied uniformly" | Not possible for CVEs published before ~Nov 2020 (B13). Rewrite once B13 is decided. | Open |
| **C45** | Medium | Notebook step 13 markdown *(fixed in v3)*; proposal Q4 / §4.3 *(open)* | "the typical vulnerability has roughly a half-percent chance of exploitation"; EPSS described without its time frame | EPSS is the probability of exploitation activity **in the next 30 days**, not overall. State the 30-day vs 365-day KEV target difference wherever EPSS is compared (B15). | Fixed in v3 (notebook part) |
| **C46** | Medium | Notebook "Next steps" table *(rewritten in v3; numbers come from step 17)* | "Run the full pull over `client.windows(2016, 2024)` — 28 windows, ~200 requests, 15–25 min"; "Build the label — exploited within 365 days" | Span and label depend on B13. Request count depends on V12; duration on A16's 6 s pacing (≈ requests × 6 s + response time). Recompute, don't estimate. | Fixed in v3 (notebook part) |
| **C47** | Medium | Chat summary and log section I (Oct 9) | "Same calendar day for all 23"; "mostly MITRE-assigned"; "half of the exploited CVEs" | Within 24 h for all 23 (22 same day); **half** (12 of 24) MITRE-assigned; **nearly** half (24 of 51) exploited CVEs unscored. Found by an independent fact-check of the revised charter and walkthrough (25 items, all fixed before delivery). | Fixed |

### C-V. Claude project doc — `claude/cve-exploitation-project-brief.md`

| ID | Sev. | Issue | Correct | Status |
|:--|:--|:--|:--|:--|
| **C33** | Medium | Superseded by the charter, and still contains: the "~82%" EPSS table (C9); "Free key (email request)" — **it's a web form**; "VulnCheck observed 495… CISA added only 12" — **actually 12 of the 61** CVEs observed by VulnCheck's own sensor network ("Canaries"); Oct 9 date; KEV "~1,733" (measured: **1,730**). | Replace with a short "superseded" note pointing to the charter. | Open |

### C-VI. Explanation corrections made in chat (nothing to edit; recorded for completeness)

| ID | Where | Correction |
|:--|:--|:--|
| C34 | Snippet 2 walkthrough | I said some checks produce numpy true/false values. In the current notebook, none do — `bool(ok)` in `record()` is purely defensive. |
| C35 | Snippets 4 and 5, and the NVD question | Already corrected in chat: User-Agent overstatement; the 735/day guess; the CISA-ADP identity. |
| C38 | Snippet 4 walkthrough | I stated "NVD also uses 403 for 'you're asking too fast'" as fact. It comes from third-party sources, not NVD's documentation; it's unverified until V18/A12. |

---

## D. Verification register

| ID | Claim | Result | Method | Date |
|:--|:--|:--|:--|:--|
| V1 | Missing CVSS ⇔ withdrawn records | ✅ Exactly 880 = 880 | Crosstab on sample | Oct 9 |
| V2 | EPSS gaps ⇔ withdrawn records | ✅ Exactly 91 = 91 (first 500 rows) | Crosstab on sample | Oct 9 |
| V3 | Where `flatten()` took scores from | ✅ CNA 51.8% · CISA-ADP 35.2% · NVD 13.0% (of 9,302) | Source comparison on sample | Oct 9 |
| V4 | Missing CWE, live records only | ✅ 8.0% (15.9% including withdrawn) | Sample | Oct 9 |
| V5 | Configurations present, 2023 | ✅ 100% of live records, both classes | Sample | Oct 9 |
| V6 | `Exploit` reference tag | ✅ 42.0% exploited vs 32.3% other | Sample | Oct 9 |
| V7 | `days_to_kev` off by one | ✅ 9 same-day listings misread as "before" | Calendar vs timestamp comparison on sample | Oct 9 |
| V8 | EPSS v4 comparison figures | ✅ CVSS ≥ 7: 74.6% coverage, 50.7% effort, ~6% efficiency. EPSS v4: 6% effort, 47% efficiency; coverage not stated. | Re-read the source for verbatim quotes | Oct 9 |
| V9 | VulnCheck definitions | ✅ 80/120 days and 23.43% refer to VulnCheck's KEV; "only 12" = 12 of the 61 CVEs observed by VulnCheck's own sensor network ("Canaries") | Re-read the source for verbatim quotes | Oct 9 |
| V10 | NVD enrichment disruption | ✅ Began **Feb 12, 2024** | Infosecurity Magazine, Mar 15, 2024 | Oct 9 |
| V11 | `134c704f…` identity | ✅ **CISA-ADP (Vulnrichment)**, launched May 8, 2024; fuller analysis for exploited CVEs and those with exploit code | OpenCVE record; SecurityWeek | Oct 9 |
| V12 | CVE count, 2016–2024 | ✅ **200,978** CVEs published 2016–2024 (**187,219** excluding Rejected). Modelling span Nov 3, 2021–2024: 101,969 (97,137 live) | Your v3 run | Oct 9 |
| V13 | CWE source distribution | ✅ NVD's `type: Primary` marks **NVD's own** entry (6,365 NVD-Primary vs 9 CNA-Primary). Only **55.8%** of live records carry a CNA CWE | Your v3 run | Oct 9 |
| V14 | Share of live records with a CNA-provided CVSS | ✅ CNA score on **59.1%** of live records (v3.1 4,820 · v3.0 679 · none 3,803); no unrecognised sources, so CNA matching is clean; 679 A26 cases | Your v3 run | Oct 9 |
| V15 | Window boundary inclusivity | ✅ Window start **inclusive**, end **exclusive**: adjacent windows neither miss nor repeat a record. De-duplication kept as a safeguard | Your v3 run | Oct 9 |
| V16 | Number of CNAs | ⏳ **Unresolved** — primary source fetch failed; use "hundreds" | — | — |
| V17 | NVD rate limits and pacing guidance | ✅ 5 vs 50 requests per rolling 30 s; NIST recommends sleeping "several seconds" between requests (NVDLib: "at least 6"). Both via secondary sources quoting NVD — the primary page isn't machine-readable by my tools. | GitHub issue quoting NVD docs; NVDLib docs | Oct 9 |
| V18 | Status code NVD returns when rate-limited | ⚠️ **Not observable** — NVD didn't throttle 10 anonymous requests in ~6 s. Moot for us (see A12) | Your v3 run | Oct 9 |
| V19 | Does NVD's CVE Change History API record field-level changes (description, CVSS, CWE) with timestamps, so the publication-time record can be rebuilt? | ✅ Yes for *changes*: field-level events with old/new values, timestamp and source (description, CVSS, CWE, SSVC, references). But the initial submission isn't an event, so the publication-time record = today's record with later changes undone. One request per CVE — see B9 | Your v3 run | Oct 9 |
| V20 | How closely NVD's `published` timestamp tracks the CVE Program's own publication time (`datePublished` in the CVE record). We treat NVD's as "the moment of publication". Sharp example: CVE-2019-8720 was in KEV 288 days before NVD's `published` date (B16). | ✅ Within 24 hours for all 23 CVEs checked (one pair straddles midnight UTC, so "same calendar day" holds for 22). Where the CVE Program stores a full timestamp, NVD lags by ≤ 1.2 h; many CVE Program dates are date-only (midnight), which explains gaps up to 23.3 h | Your v3 run | Oct 9 |
| V21 | KEV entries can be **removed** (I recall CISA removing CVE-2022-28958 in 2022; it's absent from your snapshot, consistent with that). If removals happen, a snapshot label isn't permanent. | ⏳ **Open** — confirm from CISA's catalog notes; count removals if a list exists. | — | — |
| V22 | EPSS API facts used in code and docs: (1) default `limit` per response (believed 100); (2) dates of each EPSS model version change (believed v2 Feb 2022, v3 Mar 2023, v4 Mar 2025); (3) whether EPSS's inputs include public exploited lists such as KEV. | ◐ (1) ✅ default page size **100**; (3) the API response carries **no model-version field**; (2) version-change dates still to read from FIRST's site | Your v3 run | Oct 9 |

---

## E. Housekeeping and security

| ID | Sev. | Item | Action | Status |
|:--|:--|:--|:--|:--|
| E1 | Medium | The NVD key in `.env` (fingerprint `…6A30`) is the one pasted into this chat | Optional: request a fresh key; the fingerprint will confirm the swap | Decision |
| E2 | Low | Claude project doc `wastewater-early-warning-background.md` is obsolete | Delete it, or mark it superseded | Decision |
| E3 | Low | `_archive/` holds the v1 notebook and the Oct 1 executed copy | Keep for history; exclude from submission | Accepted |
| E4 | Medium | Your re-run will **overwrite** the Oct 1 files in `data/` and `logs/`, which every verified figure in this log was computed from. KEV will also have grown since, so numbers will shift slightly. | Before the re-run, copy `data/` and `logs/` to `_archive/run_2026-10-01/`. | Done Oct 9: copied to `_archive/run_2026-10-01/` (plus JSON copies used for testing) |
| E5 | Medium | The new notebook is saved as **`00_validate_sources_v3.ipynb`**. My first attempt to replace `00_validate_sources.ipynb` was overwritten within seconds — the old notebook is open in your editor, which auto-saved its copy over mine. | Close the old notebook tab (don't save it), and run the v3 file. After your run I'll make v3 the canonical `00_validate_sources.ipynb` (the old one is archived in `_archive/run_2026-10-01/`). | Done Oct 9: v3 renamed to `00_validate_sources.ipynb`; the reverted copy is archived |

---

## F. Resolved

| ID | Item | Resolution | Date |
|:--|:--|:--|:--|
| R1 | v1 notebook failed: commented-out install, `python-dotenv` dependency | Rebuilt as v2; executed under four test conditions | Oct 1 |
| R2 | v2 crashed offline at the 120-day test | Wrapped in `try`; re-tested | Oct 1 |
| R3 | Notebook markdown hard to read | Restyled; code cells verified byte-identical | Oct 2 |

---

## G. How I'm working from here

Each rule targets a specific root cause behind the errors above.

| # | Rule | Root cause it addresses |
|:--|:--|:--|
| 1 | **Every number gets a provenance tag** — *verified source*, *our data*, or *inference* — and inferences are either labelled as such in the text or removed. | 735/day, ~82%, "required in practice" |
| 2 | **Summaries are not sources.** When a fetched page comes back paraphrased, I re-query for verbatim quotes, and confirm *what population and measure* a number refers to, before using it. | EPSS table, VulnCheck figures |
| 3 | **Never label an identifier by guesswork** — look it up. | CISA-ADP called a CNA |
| 4 | **Execute, don't just parse — and test data logic against your real data**, including edge cases such as same-day timestamps and boundaries. | v1 notebook, `days_to_kev` |
| 5 | **Leakage gate:** every field entering a feature set is checked for *who produced it, and when*, and recorded in the blacklist with evidence. | A1, A3, B2, B3 |
| 6 | **Propagate corrections everywhere at once** — search every artifact, as done today, and update all copies in one pass. | Errors repeated across 3–4 documents |
| 7 | **This log is the gate.** No new build starts while a Critical item affecting it is open. | Downstream rework |
| 8 | **Verify in the environment that produces the results.** A check whose answer could depend on library versions is run on matching versions — or written as a cell you run. | A38 |

---

---

## I. Results of your v3 run — October 9, 2026

**Run:** 00:00–00:17 PT · Python 3.14.6, pandas 3.0.3, pyarrow 23.0.1 · **17 of 18 checks PASS**; the one FAIL is 06b (a finding, see A12).
**Snapshots:** NVD 403,391 CVEs · KEV catalog 2026.10.08, 1,739 entries · EPSS scores dated 2026-10-08, 384,534 CVEs.

### I-1. Decision on B13 — proceed with option (a)

| Split (by `published`) | Records (excl. Rejected) | Listed in KEV within 365 days | Base rate | …of which listed before publication |
|:--|--:|--:|--:|--:|
| pre-KEV, 2016 – Nov 2, 2021 (description only) | 90,082 | 159 *(of 683 ever listed)* | — | — |
| **train**, Nov 3, 2021 – 2022 | 28,368 | **128** | 0.451% | 35 |
| **validate**, 2023 | 28,816 | **145** | 0.503% | 13 |
| **test**, 2024 | 39,953 | **149** | 0.373% | 7 |

**Judgement: enough to proceed.** 128 training positives clears the working threshold (100). Two safeguards come with it:

1. **Parsimonious models.** A regularised logistic regression is the primary model, with about 10–15 predictors. Any boosted model is heavily constrained.
2. **Refit before testing.** Tune on validate, then refit on train + validate (**273** positives) before the single, final evaluation on 2024.

The sensitivity run without pre-publication listings (B16/B17) has 93 / 132 / 142 positives. That is just under the threshold for training alone, which is fine for a robustness check.

**B13 confirmed empirically:** of 683 pre-KEV CVEs eventually listed, only 159 were listed within 365 days of publication.

### I-2. Figures for the proposal (B8, C1, C4, C5, C6) — Jan–Apr 2023 window, CNA-only scores

| Figure | Old (contaminated or estimated) | **Corrected** |
|:--|:--|:--|
| CVEs published 2016–2024 | "250,000–300,000" | **200,978** (187,219 excl. Rejected) |
| KEV listings in the window | 50 | **51** (catalog grew) |
| Listed before publication day / on or before it / median | 13 (26%) before; median 15 | **4 / 13 / 20 days** |
| Records with a CNA severity score | (treated as ~100%) | **59.1%** — and **24 of 51 exploited CVEs had none** |
| Records with a CNA CWE | "84%" | **55.8%** (8.0% have no CWE from anyone) |
| Exploitation rate: Critical / High / Medium / Low / no CNA score | Critical 1.37%, Medium 0.09% | **1.85% / 0.85% / 0.11% / 0% / 0.63%** (Critical ≈ 16× Medium) |
| Rule "CVSS ≥ 7" | 42.6% effort, 90% coverage, 1.04% precision | **25.6% effort, 47.1% coverage, 1.01% precision** |
| Rule "CNA is Microsoft" | 3.5% effort, 2.52% precision | **3.8% effort, 17.6% coverage, 2.52% precision** |

**New headline finding:** at publication, nearly half of the exploited CVEs (24 of 51) carried no vendor severity score at all. Half of them (12) were MITRE-assigned. A severity-based triage rule can't see them. The missing-score group's exploitation rate, 0.63%, is *above* the overall 0.55%.

### I-3. Other results

- **EPSS (B6, B15).** Historical scores work. The first score is available the day after publication, and it looks nothing like today's: CVE-2022-42475 was **0.0116 then and 0.9947 now**. **Caveat:** 4 of 5 first-day scores were identical (0.00885), which suggests a generic prior for brand-new CVEs. Stage 4 will therefore benchmark EPSS at **day 1, day 7 and day 30** after publication, and say so.
- **Change history (B9, V19).** Description edits are real.
  - Apple's CVE-2023-23529 text was rewritten twice in July 2023.
  - CVE-2022-44877's text changed 3 days after publication.
  - CISA-ADP added CVSS and CWE about 2 years after publication, confirming A1.
  - **Plan for Stage 1:** rebuild the publication-time description for every positive in the modelling span (~420) plus 1,000 random negatives, about 1,420 requests ≈ 2.4 h at 6 s. Then measure how often edits happen, and whether they add exploitation language, before choosing current vs reconstructed text.
- **CNA matching is clean.** No score came from an unrecognised source. Two big CNAs supply no scores: WPScan (0%) and Android (0%). MITRE is at 3.8%.

## H. Proposed order of operations

*Revised Oct 9 to match the agreed sequence: walkthrough first, then code fixes, then your re-run, then the proposal.*

**Before October 12 — the proposal:**

1. ~~Finish the line-by-line walkthrough~~ — **done Oct 9** (snippets 1–16).
2. ~~**Your decision on B13**~~ — **decided Oct 9: option (a)**, conditional on step 17's training-positive count. Originally: (modelling span vs the 365-day label). It changes the proposal's split, data scope and risk section, so it comes before any rewriting. B12 (CNA vs vendor wording) can be settled at the same time.
3. ~~Fix the code~~ — **done Oct 9** (`00_validate_sources_v3.ipynb`, tested offline in 5 failure modes): A1 + A26 together, then A2, A6, A7, A4, A5, A8, A9, A27–A40, the B1 missing-score flag, and the assertions (A19, A20, A23, A24). Add the V12 count cell and the V13/V14 source-aware re-pull.
4. ~~Archive and run~~ — **done Oct 9**: 17/18 PASS; results in section I. I read the results from your folder; no pasting needed.
5. ~~Recompute every proposal figure~~ — **done** (section I-2).
6. Correct the proposal (C1–C8, C41, C43–C46; B15 wording), regenerate both formats, and re-run this audit against it.

**Then:**

7. ~~Batch-correct the charter and walkthrough~~ — **done Oct 9** (revision 2 of both, fact-checked by an independent pass; 25 issues found and fixed). The project brief (C33) remains.
8. Move shared code into `cve_pipeline.py` (A25). (The 6 s pacing, A16, is already in v3.)
9. Close the verification checks the notebook can't run: V16 (CNA count), V21 (KEV removals), V22's model-version dates. The rest are cells in v3.
