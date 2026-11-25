# Demo script: Tuesday Nov 24, 4:50 PM (10 minutes)

Notebook: `Demo/06_demo_v2.ipynb`. App: double-click `start_app.bat` in the project folder.
Cell numbers are the `In [n]` labels after a fresh **Restart & Run All** (about 40 seconds).

What the grader checks (guidelines, section 14): API acquisition, processing and DataFrames, meaningful pandas,
at least one meaningful NumPy computation, questions and results, visualizations and the app. Section 17: the
quality of the Python matters more than the interface. So the 10 minutes go mostly to code decisions, with one
sentence per result.

---

## Before the demo

**Tonight or tomorrow morning**

1. Open `Demo/06_demo_v2.ipynb`, run **Kernel → Restart & Run All**.
   - In[3] prints `NVD API key found: True`.
   - In[4] and In[10] say "live", In[5] says "live answer", and In[7] shows page lines with no "request failed".
     If not, the network is the problem; the numbers are the same either way.
   - No red output anywhere.
2. **File → Save and Export Notebook As → HTML**, into `Demo/`. This is the backup if Jupyter fails.
3. Double-click `start_app.bat`. The app opens on http://localhost:8501 in the light theme. On **Triage**, paste the
   IDs below once.
4. From the project folder: `python tests/run_app_tests.py` → 6/6 PASS.

**30 minutes before the slot**

- Laptop plugged in, notifications off, other apps closed.
- App running, Triage tab open with the IDs pasted.
- Notebook freshly run, scrolled to the top, zoom 110–125%.
- Do not open `.env` or print `api_key`.

**IDs for the app (all 2024)**

```
CVE-2024-3400, CVE-2024-21413, CVE-2024-21762, CVE-2024-4577, CVE-2024-3094, CVE-2024-6387
```

The first four were exploited and the model puts them in its top 2%. The last two are famous (the xz backdoor and
regreSSHion) but never made it into KEV; they sit around the top 7–9%: famous doesn't mean listed.

---

## Run sheet

"Live" = re-run in front of the grader (Shift+Enter). Everything else is already run: scroll and say one line per
cell: **what it does → the Python reason → the result.**

| Time | Part | Cells | Live | What to show and say |
|---|---|---|---|---|
| 0:00–0:50 | **1. Problem** | figure, In[2] | – | Panel A: the decision is made on publication day, before anyone knows. Panel B: 39,953 CVEs in 2024, 149 exploited; the CVSS 7.0+ rule fixes 32% and catches 62%. Goal: a ranked list. The four questions; the pipeline figure follows the course's acquire → present chain. |
| 0:50–1:20 | **2. Building blocks** | In[3] | – | Key from `.env`, sent only in a header. `ApiError` is my own exception. `get_json`: timeout, retries on 403/429/5xx, reads the NVD's `message` header. `iter_cves`: a generator, `yield from` one page at a time, paced. |
| 1:20–1:45 | One live query | In[4] | **yes** | Pages print as they arrive: 129 records, each a dict with 16 keys. |
| 1:45–2:00 | The API's limit | In[5] | **yes** | The NVD's real answer: "Date range cannot exceed 120 days"; `iter_cves` refuses before sending anything. |
| 2:00–2:25 | Scaling up | In[6]–In[8] | – | `windows_between` (another generator): 28 windows; the 400-day test shows the checker works. Same method on 5 days. Download record: 200,978 expected = 200,978 received, 117 pages. Point at the "Accessed" column of the sources table. |
| 2:25–2:55 | Nested JSON, KEV, EPSS | In[9], In[10] | **In[10]** | Three sources inside one record. KEV listed CVE-2024-3400 the day it was published; EPSS a day later: 2.7%. |
| 2:55–3:35 | **3. Cleaning** | In[11]–In[13] | – | `flatten`: comprehensions, publisher-only fields, so nothing added later leaks in. Regex masking of "has been exploited" sentences; tests on made-up sentences. |
| 3:35–4:25 | **4. pandas table** | In[14], In[15] | – | `merge(validate="one_to_one")`, `.dt.normalize()` for calendar days, nullable `Int64`, `le(365)` label, `pd.cut` time split, `groupby().agg`. Missing scores by period: kept as information, not filled. |
| 4:25–5:35 | **5. Q1, Q3** | In[16]–In[19] | **In[16]** | Wilson on whole NumPy arrays, `np.select`, `groupby`. Critical 2.14% (1.76–2.60%), 4.9× average; 41% have no publisher score. Five publishers: 28% of CVEs, 53% of the exploited. Q3: bootstrap median from a 1,000-row array; a third were in KEV on or before publication. |
| 5:35–7:15 | **6. Q2** | split figure, coverage figure, In[20], In[22], In[23], In[25], In[27] | **In[20]** | Split by date, not random (figure). Coverage on 10 made-up CVEs. `Ranking` is a class: sort once, reuse 1,000 times. Scroll In[22] (encoders, two classes), point at the CVE-2024-3400 row. In[23]: 57,184 × 44,897 sparse matrix. **In[25]: coverage 76.5% (68.8–83.5%) vs 36.7% (CVSS) and 64.5% (publisher); precision 2.9% vs 0.37% at random; both gaps clear.** In[27]: the words add +21.5 points. |
| 7:15–8:00 | **7. Q4 EPSS** | figure, In[29] | – | The figure: what "equal information" drops. Table: clearly ahead of EPSS one day and one week later, level a month later; on equal information clearly ahead on all three days. |
| 8:00–8:25 | **8. Conclusion** | – | – | Three bullets in your own words, one limitation (KEV is conservative). |
| 8:25–9:40 | **App** | – | live | **Triage → Rank your CVEs**: the six IDs; turn on "Show what happened (KEV)"; "Why this score?" for CVE-2024-3400. **Replay 2024**: one month. **Model vs EPSS**: switch "Which CVEs" to equal information. |
| 9:40–10:00 | buffer | | | |

**Running late? Cut in this order:** In[7]–In[8]; In[18]; In[26]–In[28]; conclusion to one sentence.
**Never cut:** In[4], In[10], In[14], In[16], In[20], In[25], In[29], the app.

---

## If something breaks

| Problem | What to do |
|---|---|
| Wi-Fi down or slow | Nothing: every API cell falls back to the saved copy and says so in one line. Say: "it falls back to the copy saved by the full download." |
| A live cell seems stuck | Keep talking; don't interrupt (it leaves a red error). Each request gives up after 15 s and falls back by itself. |
| Kernel dies | Restart & Run All (about 40 s) while you talk about the problem. |
| Jupyter won't open | The HTML export in `Demo/`. |
| App won't start | Use the notebook's charts; show `app/pages/` to show the code exists. |

---

## Q&A crib

### Where each Python construct is

| Construct | Where |
|---|---|
| Functions, docstrings, defaults | `load_api_key`, `get_json`, `flatten`, `mask_exploitation`, `wilson_interval`, `with_interval`, `bootstrap_median`, `coverage`, `replay_coverage`, `vector_components`, `structured_inputs` |
| Own exception | `ApiError` (In[3]); caught in In[4], In[5], In[7], In[10] |
| Generators | `iter_cves` (In[3]), `windows_between` (In[6]) |
| Comprehensions | `flatten`, `listed_on` and `PUBLISHER_NAMES` dicts, the `ranked` dict (In[24]) |
| Dicts, sets, unpacking | `{**AGENT, "apiKey": ...}`, duplicate check with `set` (In[7]) |
| Classes | `Ranking` (In[20]); `StructuredEncoder`, `TextEncoder` (In[22]), `fit` returns `self` |
| Regular expressions | `EXPLOITATION_PHRASES`, the sentence splitter (In[12]) |
| pandas | `merge(validate=...)`, `.dt`, `pd.cut`, `groupby().agg` with named aggregations, `sort_values`, `map`, `fillna`, `isin`, `pivot`, `join` |
| NumPy | Wilson on arrays (In[16]); bootstrap median, 2-D array + `np.median(axis=1)` (In[19]); `argsort`, `cumsum`, `bincount`, `searchsorted`, `clip` in `coverage` (In[20]); bootstrap percentiles (In[25]) |
| Sparse matrices | `scipy.sparse.hstack` of structured and word columns (In[23]) |
| Testing | checks on made-up inputs after key steps (400-day windows, masking sentences, Wilson 0 of 10, the 10 toy CVEs); `tests/` for the app |

### Likely questions

**Why not `raise_for_status()`?** It treats every error the same. I need to retry on 403/429/5xx, and the NVD gives
its reason in a header called `message`, which I want in the error.

**Why a generator?** The NVD sends a page at a time. The caller gets CVEs as they arrive, nothing is held twice, and
the pacing lives in one place.

**Why classes for the encoders?** They learn something from the past (which publishers and words get a column) and
must apply exactly that to 2024. That state belongs in an object: `fit`, then `sparse`.

**Why sparse matrices?** 44,897 columns, almost all zero for any one CVE; a dense matrix would be huge.

**Rate limits?** 50 requests per 30 s with a key, 5 without; 6 s between requests for the bulk download, and retries
when throttled.

**Missing values?** Kept, not filled: a missing score becomes its own category, because a publisher that doesn't
score its CVEs is informative.

**Why split by date?** That's how it would be used, and related CVEs (same vendor, same week, near-identical text)
would leak across a random split. A random split overstates coverage by about 7.6 points at 10% effort.

**Why Wilson / why bootstrap?** Rates near zero with small counts: Wilson stays inside 0–1 and behaves. A median has
no formula for its interval, so it is resampled (seed 510, so it's the same every run).

**What is `C = 0.1`?** How strongly the weights are held towards zero. It's a sample modelling approach; the
project's focus is the data pipeline and the analysis.

**Is KEV the truth?** The best public record, but conservative: some exploited CVEs are never listed. It affects
every ranking the same way.

**Isn't comparing with EPSS unfair?** EPSS uses more data, but it also reads KEV. That's why there are two views;
equal information removes what KEV had already made public.

**How is the API key handled?** Read from `.env` (in `.gitignore`), sent only to the NVD in a header, never printed.

**Did you use PyTorch?** No; it's optional, and the guidelines say it doesn't replace the core requirements.

### Numbers to remember

| | |
|---|---|
| Study (Nov 2021–2024) | 97,137 CVEs, 422 exploited; 2024: 39,953 CVEs, 149 exploited |
| Download | 28 windows, 117 pages, 200,978 records (187,219 live), Nov 10, 2026 |
| Q2 at 10% effort | model 76.5% (68.8–83.5%), publisher 64.5%, CVSS 36.7%; precision 2.9% vs 0.37% |
| Gaps | vs CVSS +39.8 (+30.8 to +48.0); vs publisher +12.0 (+3.1 to +20.7); words +21.5 (+14.5 to +27.2) |
| Q4 all CVEs (day 1 / 7 / 30) | EPSS 34.6% / 56.4% / 74.5%; gaps +41.9 / +20.1 / +2.0 (day 30 not clear) |
| Q4 equal information | EPSS 15.2% / 26.8% / 46.3% vs model 74.0% / 74.6% / 75.9%; all clear |
| Q3 | about a third in KEV on or before publication; 2024 median 7 days (3–19) |
