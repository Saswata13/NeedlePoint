"""Shared code for the demo app.

Three parts:
1. The final model of 03_model.ipynb (logistic regression on the structured fields and the cleaned description),
   refitted on Nov 2021-2023 exactly as 03_model_test.ipynb did, saved once and reloaded by the app. The blocks
   marked "copied from 03_model.ipynb" are word for word the notebook's code (tests/run_app_tests.py checks it).
2. A live lookup of a CVE at the NVD, flattened with the CNA-only rules of 01_acquire_data.ipynb.
3. The explanation of a score: how much each input pushed it up or down, compared with an average CVE.
"""
import json
import math
import re
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
import scipy.sparse as sp
import sklearn
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# ---------------------------------------------------------------- folders (the project root is app/..)
ROOT = Path(__file__).resolve().parent.parent
PROCESSED, RAW, RESULTS, LOGS = ROOT / "data" / "processed", ROOT / "data" / "raw", ROOT / "results", ROOT / "logs"
MODEL_FILE = Path(__file__).resolve().parent / "model" / "final_model.joblib"

# ---------------------------------------------------------------- settings (copied from 03_model.ipynb, Step 2)
LABEL = "label_365"                       # listed in KEV within 365 calendar days of publication
SEED = 510
MIN_CATEGORY = 20                         # CVEs a publisher or CWE needs in the fitting data to get its own column
MAX_CATEGORIES = 250                      # gradient boosting accepts at most 255 categories per column
TFIDF = {"ngram_range": (1, 2), "min_df": 5, "max_df": 0.5, "max_features": 50_000,
         "sublinear_tf": True, "stop_words": "english"}
SVD_COMPONENTS = 100                      # dense summary of the text for gradient boosting
FEATURE_COLUMNS = ["cna", "description", "cvss_score", "cvss_vector", "cvss_version", "cwe_primary"]

# ---------------------------------------------------------------- publisher names (03_model.ipynb, Step 7)
SOURCES_CACHE = RAW / "nvd_sources.json"
try:
    _sources = json.loads(SOURCES_CACHE.read_text(encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    _sources = []
PUBLISHER_NAMES = {identifier: s["name"].strip() for s in _sources if s.get("name")
                   for identifier in s.get("sourceIdentifiers", [])}
WORDPRESS = re.compile(r"wordfence|patchstack|wpscan", re.IGNORECASE)

# copied from 03_model.ipynb: begin publisher
def publisher_of(df):
    "The publisher's name where known, otherwise its identifier."
    return df["cna"].map(PUBLISHER_NAMES).fillna(df["cna"])

def is_wordpress(df):
    "True for CVEs issued by the WordPress plug-in publishers."
    return publisher_of(df).str.contains(WORDPRESS) | df["cna"].str.contains(WORDPRESS)
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin cleaning
EXPLOITATION_PHRASES = [
    r"\bexploited in the wild\b", r"\bin the wild\b", r"\bactively exploited\b",
    r"\b(?:has|have|had|may have) been (?:actively )?exploited\b", r"\b(?:was|were) (?:actively )?exploited\b",
    r"\bis being (?:actively )?exploited\b", r"\btargeted exploitation\b",
    r"\bexploitation (?:has been |was )?(?:observed|detected|reported)\b",
    r"\bknown exploited vulnerabilit", r"\baware of (?:a |an )?(?:report|reports|exploit)",
]
PHRASE = re.compile("|".join(EXPLOITATION_PHRASES), re.IGNORECASE)
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin mask
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")

def mask_exploitation(text):
    "The description without any sentence that says the flaw is or was exploited."
    if not isinstance(text, str):
        return ""
    if not PHRASE.search(text):
        return text                                    # untouched, spacing included
    return " ".join(s for s in SENTENCE_END.split(text) if not PHRASE.search(s))
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin vector
COMPONENTS = ["AV", "AC", "PR", "UI", "S", "AT", "C", "I", "A"]
V4_NAMES = {"VC": "C", "VI": "I", "VA": "A"}                  # version 4's names for the impact metrics

def vector_components(vectors):
    "One column per CVSS 3.x/4.0 base component (codes such as N, L, H); 'missing' where absent."
    modern = vectors.where(vectors.str.startswith("CVSS:3", na=False) | vectors.str.startswith("CVSS:4", na=False))
    pairs = modern.str.findall(r"/([A-Z]+):([A-Z])")
    rows = [{V4_NAMES.get(k, k): v for k, v in p} if isinstance(p, list) else {} for p in pairs]
    parsed = pd.DataFrame(rows, index=vectors.index).reindex(columns=COMPONENTS)
    parsed["UI"] = parsed["UI"].replace({"P": "R", "A": "R"})   # passive or active: required either way
    return parsed.fillna("missing")
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin structured
CATEGORICAL = ["publisher", "cwe", "cvss_version"] + COMPONENTS
NUMERIC = ["cvss_score", "log_description_len"]

def structured_inputs(df):
    "The structured inputs of each CVE, as readable columns (categories as text, two numbers)."
    raw = pd.DataFrame({"publisher": publisher_of(df), "cwe": df["cwe_primary"].fillna("missing"),
                        "cvss_version": df["cvss_version"].fillna("missing").astype(str)}, index=df.index)
    raw = raw.join(vector_components(df["cvss_vector"]))
    raw["cvss_score"] = df["cvss_score"].astype(float).fillna(0.0)
    raw["log_description_len"] = np.log1p(df["text"].str.len().astype(float))
    return raw
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin encoders
class StructuredEncoder:
    "Keeps the categories common in the fitting data (the rest become 'other'); encodes for both model families."
    def fit(self, raw):
        self.keep, self.n_fit = {}, len(raw)
        for col in CATEGORICAL:
            counts = raw[col].value_counts()
            common = counts[counts >= MIN_CATEGORY].index[:MAX_CATEGORIES - 1]
            self.keep[col] = sorted(set(common) | {"other"})
        lumped = self.lump(raw)
        self.onehot = OneHotEncoder(categories=[self.keep[c] for c in CATEGORICAL], handle_unknown="ignore",
                                    sparse_output=True).fit(lumped[CATEGORICAL])
        self.scaler = StandardScaler().fit(raw[NUMERIC])
        return self

    def lump(self, raw):
        "Categories not kept at fitting time (rare, or never seen) become 'other'."
        out = raw.copy()
        for col in CATEGORICAL:
            out[col] = out[col].where(out[col].isin(self.keep[col]), "other")
        return out

    def sparse(self, raw):
        "0/1 columns for each kept category, plus the standardised numbers (logistic regression)."
        lumped = self.lump(raw)
        return sp.hstack([self.onehot.transform(lumped[CATEGORICAL]),
                          sp.csr_matrix(self.scaler.transform(raw[NUMERIC]))]).tocsr()

    def dense(self, raw):
        "Category codes plus the raw numbers (gradient boosting)."
        lumped = self.lump(raw)
        codes = [pd.Categorical(lumped[c], categories=self.keep[c]).codes for c in CATEGORICAL]
        return np.column_stack(codes + [raw[c].to_numpy(float) for c in NUMERIC])

    def names(self):
        "Column names of the sparse form, in order (the one-hot columns follow self.keep)."
        return [f"{col}: {cat}" for col in CATEGORICAL for cat in self.keep[col]] + NUMERIC
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin text
class TextEncoder:
    "TF-IDF of the cleaned descriptions, learned from the fitting data, plus a dense SVD summary."
    def fit(self, texts, svd=True):
        "Learn the vocabulary; also the SVD summary unless svd=False (only gradient boosting needs it)."
        self.n_fit = len(texts)
        self.tfidf = TfidfVectorizer(dtype=np.float32, **TFIDF).fit(texts)
        if svd:
            tfidf = self.tfidf.transform(texts)
            n_components = min(SVD_COMPONENTS, tfidf.shape[1] - 1)
            self.svd = TruncatedSVD(n_components=n_components, random_state=SEED).fit(tfidf)
        return self

    def sparse(self, texts):
        return self.tfidf.transform(texts)

    def dense(self, texts):
        return self.svd.transform(self.tfidf.transform(texts))

    def names(self):
        return [f"word: {w}" for w in self.tfidf.get_feature_names_out()]
# copied from 03_model.ipynb: end

# copied from 03_model.ipynb: begin evaluation
class Ranking:
    "CVEs sorted by score, highest first, with equal scores grouped. Computed once per model, reused."
    def __init__(self, score):
        score = np.asarray(score, dtype=float)
        if score.size == 0 or not np.isfinite(score).all():
            raise ValueError("scores must be finite and not empty")
        self.order = np.argsort(-score, kind="stable")
        ranked = score[self.order]
        self.group = np.cumsum(np.r_[True, ranked[1:] != ranked[:-1]]) - 1   # tie-group number, in rank order
        self.n_groups, self.n = int(self.group[-1]) + 1, score.size

def coverage(ranking, y, efforts, weights=None):
    "Expected (coverage, precision) when the top `effort` share is handled, ties split evenly."
    y = np.asarray(y, dtype=float)[ranking.order]
    w = np.ones(ranking.n) if weights is None else np.asarray(weights, dtype=float)[ranking.order]
    size = np.bincount(ranking.group, weights=w, minlength=ranking.n_groups)       # CVEs per tie group
    hits = np.bincount(ranking.group, weights=w * y, minlength=ranking.n_groups)   # exploited per group
    cum_size, cum_hits = np.cumsum(size), np.cumsum(hits)
    k = np.asarray(efforts, dtype=float) * cum_size[-1]                           # CVEs handled
    g = np.minimum(np.searchsorted(cum_size, k, side="left"), ranking.n_groups - 1)  # group holding the cut
    taken = np.divide(k - (cum_size[g] - size[g]), size[g], out=np.zeros_like(k), where=size[g] > 0)
    found = cum_hits[g] - hits[g] + hits[g] * np.clip(taken, 0, 1)
    total = cum_hits[-1]
    cov = found / total if total > 0 else np.full_like(k, np.nan)
    return cov, np.divide(found, k, out=np.full_like(k, np.nan), where=k > 0)
# copied from 03_model.ipynb: end



# ================================================================ the final model, refitted and saved
FINAL_NAME = "LR · structured + text"


def model_frame(df):
    "The columns the model reads, plus the cleaned description in `text` (what the model actually reads)."
    out = df[["cve_id"] + FEATURE_COLUMNS].copy()
    out["text"] = out["description"].map(mask_exploitation)
    return out


def build_final_model(progress=print):
    """Refit 03's final model on Nov 2021-2023 with its frozen settings (as 03_model_test.ipynb did), check it
    reproduces the saved 2024 scores, and save it. Returns the bundle."""
    t0 = time.perf_counter()
    selection = json.loads((RESULTS / "q2_selection.json").read_text(encoding="utf-8"))
    final = selection["final_model"]
    spec = selection["candidates"][final]
    if (final, spec["family"], spec["feature_set"]) != (FINAL_NAME, "logistic regression", "structured + text"):
        raise RuntimeError(f"the app expects a logistic regression on structured + text, found {final}")
    table = pd.read_parquet(PROCESSED / "analysis_table.parquet", columns=["cve_id", "split", LABEL] + FEATURE_COLUMNS)
    fit_df = model_frame(table[table["split"].isin(["train", "validate"])].reset_index(drop=True))
    y_fit = table.loc[table["split"].isin(["train", "validate"]), LABEL].to_numpy(int)
    test = model_frame(table[table["split"] == "test"].reset_index(drop=True))
    progress(f"fitting on {len(fit_df):,} CVEs (Nov 2021–2023, {y_fit.sum()} exploited)…")
    # 03's build_features with families=("lr",), then design(...) for "structured + text":
    s_enc = StructuredEncoder().fit(structured_inputs(fit_df))
    t_enc = TextEncoder().fit(fit_df["text"], svd=False)
    X_fit = sp.hstack([s_enc.sparse(structured_inputs(fit_df)), t_enc.sparse(fit_df["text"])]).tocsr()
    # 03's fit_model for "logistic regression":
    model = LogisticRegression(C=spec["params"]["C"], class_weight="balanced", solver="liblinear", max_iter=2000)
    model.fit(X_fit, y_fit)
    bundle = {"s_enc": s_enc, "t_enc": t_enc, "model": model, "selection_sha256": selection["sha256"],
              "C": spec["params"]["C"], "sklearn": sklearn.__version__, "built": pd.Timestamp.now().isoformat(),
              "mean_x": np.asarray(X_fit.mean(axis=0)).ravel()}
    fm = FinalModel(bundle)
    # Check against 03_model_test.ipynb's own 2024 scores.
    saved = pd.read_parquet(PROCESSED / "model_scores_test.parquet")
    if not saved["cve_id"].equals(test["cve_id"]):
        raise RuntimeError("model_scores_test.parquet is not aligned with the 2024 CVEs")
    mine, theirs = fm.score(test), saved[FINAL_NAME].to_numpy()
    diff = float(np.abs(mine - theirs).max())
    rank_corr = float(pd.Series(mine).rank().corr(pd.Series(theirs).rank()))
    bundle["check"] = {"max_abs_difference": diff, "rank_correlation": rank_corr, "cves": len(test)}
    if diff > 1e-4 or rank_corr < 0.99999:
        raise RuntimeError(f"the refitted model does not match the saved 2024 scores (max difference {diff:.2g}, "
                           f"rank correlation {rank_corr:.6f})")
    bundle["reference_2024"] = np.sort(theirs)          # 2024's scores, for "top x% of 2024"
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    part = MODEL_FILE.with_suffix(".part")
    joblib.dump(bundle, part)
    part.replace(MODEL_FILE)
    progress(f"saved {MODEL_FILE.name} in {time.perf_counter() - t0:.0f} s | matches the saved 2024 scores: "
             f"max difference {diff:.1e}, rank correlation {rank_corr:.6f}")
    return FinalModel(bundle)


def load_final_model():
    "The saved model, or None if it has not been built (or was built by another scikit-learn version)."
    if not MODEL_FILE.exists():
        return None
    bundle = joblib.load(MODEL_FILE)
    if bundle.get("sklearn") != sklearn.__version__:
        return None
    return FinalModel(bundle)


class FinalModel:
    "03's final model: scores, rank within 2024, and the reasons behind a score."
    def __init__(self, bundle):
        self.b = bundle
        self.s_enc, self.t_enc, self.model = bundle["s_enc"], bundle["t_enc"], bundle["model"]
        self.coef = self.model.coef_.ravel()
        self.names = self.s_enc.names() + self.t_enc.names()
        self.mean_x = bundle["mean_x"]
        self.mean_logit = float(self.model.intercept_[0] + self.coef @ self.mean_x)
        self.n_structured = len(self.s_enc.names())

    def matrix(self, frame):
        "The model's input matrix for a frame from model_frame()."
        return sp.hstack([self.s_enc.sparse(structured_inputs(frame)), self.t_enc.sparse(frame["text"])]).tocsr()

    def score(self, frame):
        return self.model.predict_proba(self.matrix(frame))[:, 1]

    def top_share(self, scores):
        "The share of 2024 CVEs scored at least as high (0.01 = in the top 1% of 2024)."
        ref = self.b["reference_2024"]
        return 1.0 - np.searchsorted(ref, np.asarray(scores, float), side="left") / len(ref)

    def explain(self, frame_row):
        """For one CVE (a one-row frame): each input group's push, compared with an average CVE of Nov 2021-2023
        (log-odds; the pushes add up exactly to the CVE's logit minus the average logit), and the words."""
        x = self.matrix(frame_row).toarray().ravel()
        push = self.coef * (x - self.mean_x)
        raw = structured_inputs(frame_row).iloc[0]
        lumped = self.s_enc.lump(structured_inputs(frame_row)).iloc[0]
        groups, start = [], 0
        for col in CATEGORICAL:
            n = len(self.s_enc.keep[col])
            groups.append({"group": col, "value": raw[col], "kept_as": lumped[col],
                           "push": float(push[start:start + n].sum())})
            start += n
        for col in NUMERIC:
            groups.append({"group": col, "value": float(raw[col]), "kept_as": None, "push": float(push[start])})
            start += 1
        groups.append({"group": "words", "value": None, "kept_as": None, "push": float(push[start:].sum())})
        present = np.flatnonzero(x[self.n_structured:]) + self.n_structured
        words = sorted(({"word": self.names[j][6:], "push": float(self.coef[j] * x[j])} for j in present),
                       key=lambda w: -abs(w["push"]))
        logit = float(self.model.intercept_[0] + self.coef @ x)
        return {"groups": groups, "words": words, "logit": logit, "average_logit": self.mean_logit,
                "score": 1 / (1 + math.exp(-logit))}


# ================================================================ plain-language labels for the reasons
CVSS_WORDS = {
    "AV": ("Attack vector", {"N": "network", "A": "adjacent network", "L": "local", "P": "physical"}),
    "AC": ("Attack complexity", {"L": "low", "H": "high"}),
    "PR": ("Privileges required", {"N": "none", "L": "low", "H": "high"}),
    "UI": ("User interaction", {"N": "none", "R": "required"}),
    "S": ("Scope", {"U": "unchanged", "C": "changed"}),
    "AT": ("Attack requirements", {"N": "none", "P": "present"}),
    "C": ("Confidentiality impact", {"H": "high", "L": "low", "N": "none"}),
    "I": ("Integrity impact", {"H": "high", "L": "low", "N": "none"}),
    "A": ("Availability impact", {"H": "high", "L": "low", "N": "none"}),
}


def label_group(g, cwe_names=None):
    "A short, plain description of one input group of explain()."
    col, value, kept = g["group"], g["value"], g["kept_as"]
    if col == "publisher":
        return f"Publisher: {value}" + (" (few CVEs in 2021–2023: treated as 'other')" if kept == "other" else "")
    if col == "cwe":
        if value == "missing":
            return "No weakness type from the publisher"
        name = (cwe_names or {}).get(value, value)
        return f"Weakness: {name}" + (" (uncommon: treated as 'other')" if kept == "other" else "")
    if col == "cvss_version":
        return "No severity score from the publisher" if value == "missing" else f"CVSS version {value}"
    if col in CVSS_WORDS:
        title, words = CVSS_WORDS[col]
        return f"{title}: not given" if value == "missing" else f"{title}: {words.get(value, value)}"
    if col == "cvss_score":
        return "Severity score: none" if value == 0 else f"Severity score {value:g}"
    if col == "log_description_len":
        return f"Description length: {round(math.expm1(value)):,} characters"
    return "Words of the description"


# ================================================================ live lookup at the NVD (01_acquire_data.ipynb's rules)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
HEADERS = {"User-Agent": "DSCI510-course-project/1.0 (academic research)", "Accept": "application/json"}
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ADP_CISA = "134c704f-9b21-4f2e-91b3-4a467353bcc0"     # CISA's Authorized Data Publisher (not a CNA)
CVSS_VERSIONS = [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                 ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")]
_LAST_NVD_REQUEST = [0.0]


class LookupError_(RuntimeError):
    "A lookup that failed for a reason we can explain."


def parse_ids(text):
    "Every CVE ID in a pasted text, upper-cased, in order, without repeats."
    return list(dict.fromkeys(m.upper() for m in CVE_ID.findall(text or "")))


def load_api_key(var="NVD_API_KEY", env_file=ROOT / ".env"):
    "The NVD API key from the environment or the .env file, or None. The key is never printed or shown."
    import os
    if os.environ.get(var):
        return os.environ[var].strip()
    path = Path(env_file)
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.strip().partition("=")
            value = value.strip().strip('"').strip("'")
            if sep and name.strip() == var and value and "your-key" not in value:
                return value
    return None


def source_kind(source, cna):
    "Who produced a score or CWE: the CVE's own CNA, NVD's analysts, CISA-ADP, or another party."
    if not source:
        return None
    if source == cna:
        return "CNA"
    return {"nvd@nist.gov": "NVD", ADP_CISA: "CISA-ADP"}.get(source, "other")


def first_score(metrics, cna, kind):
    "The first score supplied by `kind` (CNA, NVD, CISA-ADP), searching every CVSS version in order."
    for key, label in CVSS_VERSIONS:
        for m in metrics.get(key, []):
            if source_kind(m.get("source"), cna) == kind:
                data = m.get("cvssData", {})
                return (data.get("baseScore"), data.get("vectorString"),
                        data.get("baseSeverity") or m.get("baseSeverity"), label)
    return (None, None, None, None)


def cna_cwes(cve, cna):
    "The CNA's own CWEs, in the order the CNA listed them."
    out = []
    for w in cve.get("weaknesses", []):
        if source_kind(w.get("source"), cna) == "CNA":
            for d in w.get("description", []):
                value = str(d.get("value", ""))
                if value.startswith("CWE-") and value not in out:
                    out.append(value)
    return out


def flatten_live(cve):
    "One NVD record -> the model's inputs, using only what the CVE's own CNA supplied (as 01 does)."
    cna, metrics = cve.get("sourceIdentifier"), cve.get("metrics", {})
    score, vector, severity, version = first_score(metrics, cna, "CNA")
    cwes = cna_cwes(cve, cna)
    text = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"cve_id": cve.get("id"), "published": pd.to_datetime(cve.get("published"), errors="coerce"),
            "last_modified": pd.to_datetime(cve.get("lastModified"), errors="coerce"),
            "status": cve.get("vulnStatus"), "cna": cna, "description": text, "cvss_score": score,
            "cvss_severity": severity, "cvss_vector": vector, "cvss_version": version,
            "cwe_primary": cwes[0] if cwes else None}


def fetch_nvd(cve_id, api_key=None, timeout=30, session=requests):
    "Today's NVD record for one CVE (paced as NIST asks: 6 s apart without a key, 0.6 s with one)."
    pause = 0.6 if api_key else 6.0
    wait = _LAST_NVD_REQUEST[0] + pause - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    headers = dict(HEADERS, **({"apiKey": api_key} if api_key else {}))
    try:
        resp = session.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise LookupError_(f"the NVD could not be reached ({type(exc).__name__}); check the internet connection") from exc
    finally:
        _LAST_NVD_REQUEST[0] = time.monotonic()
    if resp.status_code != 200:
        why = resp.headers.get("message") or resp.text[:120].strip() or "no reason given"
        raise LookupError_(f"the NVD answered HTTP {resp.status_code} ({why})")
    try:
        items = resp.json().get("vulnerabilities", [])
    except ValueError as exc:
        raise LookupError_("the NVD sent an answer that is not JSON") from exc
    if not items:
        raise LookupError_("the NVD has no record with this ID")
    cve = items[0]["cve"]
    if cve.get("vulnStatus") == "Rejected":
        raise LookupError_("this CVE was withdrawn (status Rejected)")
    return cve


def fetch_kev(timeout=30, session=requests):
    "Today's KEV catalogue as {cve_id: date added}, or None if CISA cannot be reached."
    try:
        resp = session.get(KEV_URL, headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
        return {v["cveID"].upper(): v["dateAdded"] for v in resp.json()["vulnerabilities"]}, "today's catalogue"
    except (requests.RequestException, ValueError, KeyError):
        files = sorted((RAW / "kev").glob("kev_*.json"))
        if not files:
            return None, None
        data = json.loads(files[-1].read_text(encoding="utf-8"))
        return ({v["cveID"].upper(): v["dateAdded"] for v in data["vulnerabilities"]},
                f"saved snapshot {files[-1].stem.replace('kev_', '')}")


def fetch_epss(cve_ids, timeout=30, session=requests):
    "Today's EPSS scores {cve_id: score} for up to 100 CVEs, or {} if FIRST cannot be reached."
    if not cve_ids:
        return {}
    try:
        resp = session.get(EPSS_URL, params={"cve": ",".join(cve_ids[:100]), "limit": 100}, headers=HEADERS,
                           timeout=timeout)
        resp.raise_for_status()
        return {d["cve"].upper(): float(d["epss"]) for d in resp.json().get("data", [])}
    except (requests.RequestException, ValueError, KeyError):
        return {}
