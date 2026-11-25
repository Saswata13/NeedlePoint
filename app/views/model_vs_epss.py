"""Model vs EPSS vs CVSS: every ranking on the 2024 CVEs, at any effort, on all CVEs or on equal information."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # the app folder, for `common`

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from common import COLORS, OUR, RANKINGS, WIDE, cm, curve, pct, result, scores_2024
import ui  # noqa: E402

ui.hero("Model vs EPSS vs CVSS · 2024", "A publication-day ranking against the industry's daily score",
        "The model scores each CVE on the day it is published. EPSS keeps updating as evidence arrives, and it "
        "reads KEV itself. Here every ranking is measured on the same 2024 CVEs.")
s = scores_2024()
y_all = s[cm.LABEL].to_numpy().astype(bool)
st.markdown(
    f"All {len(s):,} CVEs published in 2024, ranked by each method. **Effort** is the share a team handles, from the "
    f"top; **coverage** is the share of the {int(y_all.sum())} CVEs listed in KEV within a year that it catches. "
    "The model and the "
    "baselines score each CVE on its publication day; EPSS gives its score 1, 7 or 30 days later (CVEs it had not "
    "scored yet are placed last).")

chosen = st.multiselect("Rankings", list(RANKINGS) + ["Random order"],
                        default=[OUR, "EPSS, day 1", "EPSS, day 7", "EPSS, day 30", "CVSS score",
                                 "Publisher's past rate", "Random order"])
c1, c2 = st.columns([3, 2])
view = c1.radio("Which CVEs", ["All 2024 CVEs", "Equal information: EPSS day 1", "Equal information: EPSS day 7",
                               "Equal information: EPSS day 30"], horizontal=True,
                help="EPSS reads KEV itself. 'Equal information' removes, for both sides, the exploited CVEs that KEV "
                     "had already listed by the day of that EPSS score.")
effort = c2.slider("Effort: share of 2024 CVEs handled", 1, 50, 10, format="%d%%") / 100

keep = np.ones(len(s), bool)
if view != "All 2024 CVEs":
    h = int(view.rsplit(" ", 1)[1])
    listed = s["kev_date_added"].notna() & (pd.to_datetime(s["kev_date_added"]) <= s[f"epss_day_{h}"])
    keep = ~(listed.to_numpy() & y_all)
d = s[keep]
y = d[cm.LABEL].to_numpy()
k = int(y.sum())

grid = np.round(np.linspace(0, 0.5, 101), 4)
lines = []
for name in chosen:
    cov = grid if name == "Random order" else curve(y, d[RANKINGS[name]].to_numpy(), grid)
    lines.append(pd.DataFrame({"ranking": name, "effort": grid, "coverage": cov}))
if not lines:
    st.info("Choose at least one ranking.")
    st.stop()
lines = pd.concat(lines)
order = [n for n in COLORS if n in chosen]
color = alt.Color("ranking:N", scale=alt.Scale(domain=order, range=[COLORS[n] for n in order]),
                  legend=alt.Legend(orient="bottom", title=None, columns=4))
base = alt.Chart(lines).encode(
    x=alt.X("effort:Q", title="effort: share of 2024 CVEs handled", axis=alt.Axis(format="%")),
    y=alt.Y("coverage:Q", title="coverage: share of exploited CVEs caught", axis=alt.Axis(format="%"),
            scale=alt.Scale(domain=[0, 1])),
    color=color, tooltip=["ranking", alt.Tooltip("effort:Q", format=".1%"), alt.Tooltip("coverage:Q", format=".1%")])
chart = base.mark_line(strokeWidth=2.2) + alt.Chart(pd.DataFrame({"effort": [effort]})).mark_rule(
    strokeDash=[4, 3], color="#555").encode(x="effort:Q")
st.altair_chart(chart.properties(height=420), **WIDE)

at = pd.DataFrame([{"ranking": n, "coverage": (effort if n == "Random order" else
                                               curve(y, d[RANKINGS[n]].to_numpy(), [effort])[0])} for n in chosen])
at["exploited caught"] = [f"{c * k:.1f} of {k}" for c in at["coverage"]]
at["precision"] = at["coverage"] * k / (effort * len(d))
at = at.sort_values("coverage", ascending=False)
st.markdown(f"**At {effort:.0%} effort** ({effort * len(d):,.0f} of {len(d):,} CVEs handled; {k} exploited):")
st.dataframe(pd.DataFrame({"ranking": at["ranking"], "coverage": at["coverage"].map(pct),
                           "exploited caught": at["exploited caught"],
                           "precision (share of handled that were exploited)": at["precision"].map(lambda v: pct(v, 2))}),
             hide_index=True, **WIDE)
if view != "All 2024 CVEs":
    st.caption(f"{int(y_all.sum()) - k} exploited CVEs already listed in KEV by that EPSS day are left out, for every "
               "ranking; all other CVEs stay. The comparison is on equal terms for the EPSS day chosen; the other EPSS "
               "days are shown for reference.")

st.divider()
st.subheader("With uncertainty")
st.markdown("Every comparison was also measured on 1,000 resampled versions of 2024 (a paired bootstrap). A "
            "difference is **clear** when its 95% interval excludes zero. These numbers are read from the "
            "project's saved results.")
names = {"final model": OUR, "EPSS, day 1": "EPSS, day 1", "EPSS, day 7": "EPSS, day 7", "EPSS, day 30": "EPSS, day 30",
         "CVSS score, unscored slotted in": "CVSS score", "Publisher's past rate": "Publisher's past rate"}
t1, t2, t3 = st.tabs(["Coverage, all CVEs", "Differences", "Equal information"])
with t1:
    a4 = result("q4_all_cves")
    if a4 is not None:
        both = a4[a4["model"].isin(names)]
        st.dataframe(pd.DataFrame({"ranking": both["model"].map(names), **{
            f"{e}% effort": [f"{pct(c)} ({pct(lo)}–{pct(hi)})" for c, lo, hi in
                             zip(both[f"coverage_{e}"], both[f"coverage_{e}_low"], both[f"coverage_{e}_high"])]
            for e in (5, 10, 26)}}), hide_index=True, **WIDE)
with t2:
    rows = []
    diff4 = result("q4_differences")
    if diff4 is not None:
        for r in diff4[diff4["ranking"] == "final model"].itertuples():      # the model against each EPSS day
            rows.append((names.get(r.ranking, r.ranking), names.get(r.minus, r.minus), r.effort, r.change, r.low,
                         r.high, r.clear))
    dd = pd.DataFrame(rows, columns=["ranking", "minus", "effort", "change", "low", "high", "clear"])
    if len(dd):
        pick = st.selectbox("Effort", [0.05, 0.10, 0.26], index=1, format_func=lambda v: f"{v:.0%}")
        dd = dd[np.isclose(dd["effort"], pick)].reset_index(drop=True)
        dd["comparison"] = dd["ranking"] + " − " + dd["minus"]
        bars = alt.Chart(dd).encode(y=alt.Y("comparison:N", sort=None, title=None, axis=alt.Axis(labelLimit=420)))
        forest = (bars.mark_rule(strokeWidth=3).encode(
                      x=alt.X("low:Q", title="difference in coverage (points)", axis=alt.Axis(format="+%")),
                      x2="high:Q", color=alt.Color("clear:N", scale=alt.Scale(domain=[True, False],
                                                   range=["#1baf7a", "#d9930d"]), title="clear"))
                  + bars.mark_point(filled=True, size=70, color="#222").encode(
                      x="change:Q", tooltip=["comparison", alt.Tooltip("change:Q", format="+.1%"),
                                             alt.Tooltip("low:Q", format="+.1%"), alt.Tooltip("high:Q", format="+.1%")])
                  + alt.Chart(pd.DataFrame({"x": [0]})).mark_rule(color="#222").encode(x="x:Q"))
        st.altair_chart(forest.properties(height=34 * len(dd) + 40), **WIDE)
with t3:
    m = result("q4_equal_information")
    if m is not None:
        st.dataframe(pd.DataFrame({
            "EPSS day": m["epss_day"], "effort": m["effort"].map(lambda v: f"{v:.0%}"),
            "exploited kept": m["exploited_kept"], "model": m["final_model"].map(pct), "EPSS": m["epss"].map(pct),
            "model − EPSS (points, 95% interval)": [f"{100 * c:+.1f} ({100 * lo:+.1f} to {100 * hi:+.1f})" for c, lo, hi in
                                 zip(m["change"], m["low"], m["high"])],
            "clear": m["clear"].map({True: "yes", False: "no"})}), hide_index=True, **WIDE)

listed_30 = (s["kev_date_added"].notna() & (pd.to_datetime(s["kev_date_added"]) <= s["epss_day_30"])).to_numpy()
day1 = s["EPSS, day 1"].value_counts()                     # how many CVEs share each day-1 EPSS score
with st.expander("Reading the comparison"):
    st.markdown(
        "- **Different questions.** EPSS estimates the chance of exploitation *activity in the next 30 days*; the label "
        "is a *KEV listing within a year*.\n"
        f"- **EPSS reads KEV.** By day 30 KEV had already listed {(listed_30 & y_all).sum() / y_all.sum():.0%} of 2024's "
        "exploited CVEs, so part of what EPSS "
        "'predicts' later is already known. The equal-information view removes those CVEs for both sides.\n"
        f"- **Early EPSS scores are mostly tied:** on day 1, {day1.iloc[0] / len(s):.0%} of 2024's CVEs share one and "
        f"the same EPSS score ({day1.index[0]:g}), so EPSS cannot order them yet.\n")
