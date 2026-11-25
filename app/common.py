"""Data loading (cached) and small display helpers shared by the app's pages."""
import inspect
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cve_model as cm  # noqa: E402

EFFORTS = [0.05, 0.10, 0.26]
OUR = "Model"
RANKINGS = {                       # app name -> column in the 2024 score table
    OUR: "final model",
    "EPSS, day 1": "EPSS, day 1", "EPSS, day 7": "EPSS, day 7", "EPSS, day 30": "EPSS, day 30",
    "CVSS score": "CVSS score, unscored slotted in",
    "Publisher's past rate": "Publisher's past rate",
}
COLORS = {OUR: "#1baf7a", "EPSS, day 1": "#c9bdf0", "EPSS, day 7": "#9b85de", "EPSS, day 30": "#5b43a8",
          "CVSS score": "#898781", "Publisher's past rate": "#2a78d6",
          "Random order": "#c3c2b7"}


STREAMLIT_VERSION = tuple(int(p) for p in st.__version__.split(".")[:2] if p.isdigit())


def _takes_width(fn):
    try:
        return "width" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


# Full-width tables and charts. Newer Streamlit uses width="stretch"; older versions only know use_container_width,
# and charts learnt width="stretch" later than tables did, so ask the installed version rather than guess.
WIDE = ({"width": "stretch"} if _takes_width(st.altair_chart) and _takes_width(st.dataframe)
        else {"use_container_width": True})


def setup(title):
    "Kept for older page files: the layout and the look are now set once, in Home.py."


@st.cache_data(show_spinner="Loading the analysis table…")
def table():
    "Every CVE of the analysis table (2016-2024), with the columns the app uses."
    cols = ["cve_id", "published", "split", "cna", "description", "cvss_score", "cvss_severity", "cvss_vector",
            "cvss_version", "cwe_primary", "kev_date_added", "days_to_kev", cm.LABEL, "kev_before_publication"]
    t = pd.read_parquet(cm.PROCESSED / "analysis_table.parquet", columns=cols)
    t["publisher"] = cm.publisher_of(t)
    t["wordpress"] = cm.is_wordpress(t)
    return t


@st.cache_data
def study_counts():
    "CVEs and exploited CVEs of Nov 2021-2024 (the study period), from the analysis table."
    t = table()
    study = t[t["split"].isin(["train", "validate", "test"])]
    n, k = len(study), int(study[cm.LABEL].sum())
    return {"cves": n, "exploited": k, "rate": k / n}


@st.cache_data(show_spinner="Loading the 2024 scores…")
def scores_2024():
    "One row per 2024 CVE: every ranking's score, the label, and when KEV listed it and EPSS scored it."
    q4 = pd.read_parquet(cm.PROCESSED / "q4_scores_test.parquet")
    t = table()
    t = t[t["split"] == "test"]
    df = q4.merge(t, on="cve_id", how="left", validate="one_to_one")
    epss = pd.read_parquet(cm.PROCESSED / "epss_benchmark.parquet")
    for h in (1, 7, 30):
        part = epss.loc[epss["horizon_days"] == h].set_index("cve_id")
        day = part["score_day"].fillna(part["target_day"])
        df[f"epss_day_{h}"] = pd.to_datetime(df["cve_id"].map(day))
    assert len(df) == len(q4) and df[cm.LABEL].notna().all()
    return df


@st.cache_data
def result(name, **kw):
    path = cm.RESULTS / f"{name}.csv"
    return pd.read_csv(path, **kw) if path.exists() else None


@st.cache_data
def cwe_names():
    "CWE-79 -> 'CWE-79 Cross-site scripting' etc., from the saved weakness table."
    w = result("q1_rate_by_weakness")
    if w is None:
        return {}
    return {g.split(" ", 1)[0]: g for g in w["weakness"] if g.startswith("CWE-")}


@st.cache_resource(show_spinner="Loading the model (the first start after an update builds it, about a minute)…")
def model():
    "The saved model; if it is missing or was saved by another scikit-learn version, it is rebuilt once."
    fm = cm.load_final_model()
    needed = [cm.PROCESSED / "analysis_table.parquet", cm.PROCESSED / "model_scores_test.parquet",
              cm.RESULTS / "q2_selection.json"]
    if fm is None and all(p.exists() for p in needed):
        try:
            fm = cm.build_final_model(progress=lambda *_: None)
        except (RuntimeError, OSError, ValueError, KeyError):
            fm = None                                   # the pages then explain how to build it by hand
    return fm


def curve(y, score, efforts):
    "Coverage at each effort, ties split evenly."
    return cm.coverage(cm.Ranking(score), y, efforts)[0]


def pct(v, d=1):
    return "–" if v is None or pd.isna(v) else f"{100 * v:.{d}f}%"


def odds_factor(push):
    "A push in log-odds as a multiplication of the odds: +0.69 -> ×2.0, −0.69 -> ×0.5."
    f = float(np.exp(push))
    return f"×{f:.1f}" if f >= 1 else f"×{f:.2f}"


def model_missing_notice():
    st.warning("The model file has not been built yet (or was built with another scikit-learn version). Build "
               "it once from the home page, or run `python app/build_model.py` in the project folder (about a "
               "minute).")
