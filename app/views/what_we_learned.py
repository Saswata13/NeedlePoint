"""What we learned: the descriptive findings (questions A and C), interactive."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # the app folder, for `common`

import json

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from common import WIDE, cm, curve, pct, result, scores_2024, study_counts, table
import ui  # noqa: E402

ui.hero("What we learned · Questions A and C", "What exploited CVEs have in common, and how fast they are listed",
        "Severity, weakness type, publisher and the parts of the CVSS vector (question A), and the time from publication to "
        "a KEV listing (question C). Every rate comes with a 95% interval.")
counts = study_counts()
OVERALL = counts["rate"]
st.markdown(f"CVEs published Nov 2021–2024 ({counts['cves']:,}), of which **{counts['exploited']}** were listed in KEV "
            f"within a year of publication ({OVERALL:.2%}, about 1 in {round(1 / OVERALL, -1):.0f}). Rates come with "
            "95% intervals; **lift** is the rate divided by the overall rate (2.0 = twice as likely as an average CVE).")

summary_path = cm.RESULTS / "descriptive_summary.json"
if summary_path.exists():
    with st.expander("Summary of the findings", expanded=False):
        for key, text in json.loads(summary_path.read_text(encoding="utf-8")).items():
            st.markdown(f"- **{key}:** {text}")


def rate_chart(df, label, sort=None, height=None):
    "Rate with its 95% interval per group, against the overall rate."
    df = df.assign(rate_pct=df["rate"], lo=df["rate_low"], hi=df["rate_high"],
                   text=[f"{r:.2%} ({e:,} of {c:,})" for r, e, c in zip(df["rate"], df["exploited"], df["cves"])])
    enc_y = alt.Y(f"{label}:N", sort=sort or "-x", title=None, axis=alt.Axis(labelLimit=340, labelOverlap=False))
    bars = alt.Chart(df).mark_bar(color="#7b9fd6").encode(
        x=alt.X("rate_pct:Q", title="share listed in KEV within a year", axis=alt.Axis(format="%")), y=enc_y,
        tooltip=[label, alt.Tooltip("text:N", title="rate"), alt.Tooltip("lift:Q", format=".1f"),
                 alt.Tooltip("lo:Q", title="95% low", format=".2%"), alt.Tooltip("hi:Q", title="95% high", format=".2%")])
    err = alt.Chart(df).mark_rule(color="#333").encode(x="lo:Q", x2="hi:Q", y=enc_y)
    ref = alt.Chart(pd.DataFrame({"x": [OVERALL]})).mark_rule(strokeDash=[4, 3], color="#e0574f").encode(x="x:Q")
    return (bars + err + ref).properties(height=alt.Step(30))


tabs = st.tabs(["Severity", "Weakness types", "Publishers", "CVSS details", "Triage rules", "How fast (C)"])

with tabs[0]:
    sev = result("q1_rate_by_severity")
    st.altair_chart(rate_chart(sev, "severity", sort=list(sev["severity"])), **WIDE)
    crit, none = sev.set_index("severity").loc["Critical"], sev.set_index("severity").loc["No publisher score"]
    st.markdown(f"Critical CVEs are exploited about **{crit['lift']:.0f} times** as often as average, but they are only "
                f"{crit['share_of_exploited']:.0%} of the exploited ones. **{none['share_of_cves']:.0%} of CVEs carry no "
                "severity score from their publisher** on publication day, and they are exploited at about the average "
                f"rate (lift {none['lift']:.1f}): a severity-based rule cannot see them. Dashed line: overall rate.")
    st.dataframe(pd.DataFrame({"severity (publisher's score)": sev["severity"], "CVEs": sev["cves"].map("{:,}".format),
                               "exploited": sev["exploited"], "rate": sev["rate"].map(lambda v: pct(v, 2)),
                               "lift": sev["lift"].round(1), "share of all exploited": sev["share_of_exploited"].map(pct)}),
                 hide_index=True, **WIDE)

with tabs[1]:
    w = result("q1_rate_by_weakness")
    c1, c2 = st.columns(2)
    min_n = c1.select_slider("Only weakness types with at least … CVEs", [50, 100, 200, 500, 1000], value=200)
    top = c2.radio("Show", ["Highest rates", "Most exploited CVEs"], horizontal=True)
    sub = w[w["cves"] >= min_n]
    sub = sub.nlargest(15, "rate" if top == "Highest rates" else "exploited")
    st.altair_chart(rate_chart(sub, "weakness"), **WIDE)
    st.markdown("Missing authentication, code and command injection, deserialization and hard-coded credentials stand "
                "out; SQL injection and cross-site scripting, though very common, are rarely exploited. "
                f"{w.set_index('weakness').loc['No publisher CWE', 'share_of_exploited']:.0%} of all exploited CVEs had "
                "**no weakness type from their publisher**.")
    q = st.text_input("Search a weakness type (e.g. CWE-787 or 'injection')")
    if q:
        hit = w[w["weakness"].str.contains(q, case=False, regex=False)]
        st.dataframe(pd.DataFrame({"weakness": hit["weakness"], "CVEs": hit["cves"], "exploited": hit["exploited"],
                                   "rate": hit["rate"].map(lambda v: pct(v, 2)), "lift": hit["lift"].round(1)}),
                     hide_index=True, **WIDE)

with tabs[2]:
    p = result("q1_rate_by_publisher")
    by = st.radio("Rank publishers by", ["Most exploited CVEs", "Highest rate (at least 50 CVEs)"], horizontal=True)
    sub = (p.nlargest(15, "exploited") if by.startswith("Most") else p[p["cves"] >= 50].nlargest(15, "rate"))
    st.altair_chart(rate_chart(sub, "publisher", sort=list(sub["publisher"])), **WIDE)
    if by.startswith("Most"):
        st.caption("Ordered by the number of exploited CVEs; bars show each publisher's rate.")
    top5 = p.nlargest(5, "exploited")
    st.markdown(f"Exploitation is concentrated: the 5 publishers with the most exploited CVEs hold "
                f"**{top5['exploited'].sum() / counts['exploited']:.0%}** of them but only "
                f"{top5['cves'].sum() / counts['cves']:.0%} of all CVEs. "
                "MITRE assigns IDs for many vendors, so its rate mixes many products. Publisher identity is the "
                "strongest single signal the model uses.")
    unseen = result("q1_unseen_publishers")
    if unseen is not None:
        t = unseen[unseen["period"] == "test"].iloc[0]
        st.caption(f"In 2024, {int(t['new_publishers'])} publishers absent from Nov 2021–2023 issued "
                   f"{t['cves_from_new_share']:.0%} of CVEs and {int(t['exploited_from_new'])} of the {int(t['exploited'])} "
                   "exploited ones: "
                   "a model must handle publishers it has never seen.")

with tabs[3]:
    comp = result("q1_rate_by_cvss_component")
    comp["part"] = comp["component"].str.replace("_", " ").str.capitalize() + ": " + comp["value"]
    st.altair_chart(rate_chart(comp, "part", sort=list(comp["part"])), **WIDE)
    phys = comp[(comp["component"] == "attack_vector") & (comp["value"] == "Physical")].iloc[0]
    st.markdown("Among CVEs with a CVSS 3.x or 4.0 vector: flaws needing **no privileges** and **no user interaction** "
                "are exploited more often; "
                + (f"none of the {int(phys['cves']):,} physical-access flaws was exploited"
                   if phys["exploited"] == 0 else
                   f"only {int(phys['exploited'])} of the {int(phys['cves']):,} physical-access flaws were exploited")
                + ". The parts of the vector carry "
                "information the single score hides.")

with tabs[4]:
    rules = result("q1_triage_rules")
    per = st.radio("Period", ["all", "train", "validate", "test"], horizontal=True,
                   format_func={"all": "Nov 2021–2024", "train": "Nov 2021–2022", "validate": "2023",
                                "test": "2024"}.get)
    r = rules[(rules["period"] == per) & (rules["rule"] != "Patch everything")]
    enc = dict(
        x=alt.X("effort:Q", title="effort: share of CVEs flagged", axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
        y=alt.Y("coverage:Q", title="coverage: share of exploited caught", axis=alt.Axis(format="%"),
                scale=alt.Scale(domain=[0, 1])),
        tooltip=["rule", alt.Tooltip("effort:Q", format=".1%"), alt.Tooltip("coverage:Q", format=".1%"),
                 alt.Tooltip("precision:Q", format=".2%")])
    pts = (alt.Chart(r).mark_circle(size=170, color="#2a78d6", opacity=0.9).encode(**enc)
           + alt.Chart(r).mark_text(align="left", dx=10, fontSize=12, color="#333").encode(text="rule:N", **enc))
    diag = alt.Chart(pd.DataFrame({"effort": [0, 1], "coverage": [0, 1]})).mark_line(color="#bbb").encode(
        x="effort:Q", y="coverage:Q")
    st.altair_chart((diag + pts).properties(height=380), **WIDE)
    by_rule = r.set_index("rule")
    r7, r7u = by_rule.loc["Publisher score 7.0+"], by_rule.loc["Score 7.0+, or no publisher score"]
    s24 = scores_2024()
    model_10 = curve(s24[cm.LABEL].to_numpy(), s24["final model"].to_numpy(), [0.10])[0]
    st.markdown(f"Each rule flags a fixed set of CVEs. The diagonal is a random choice. 'Score 7.0+' flags "
                f"{r7['effort']:.0%} of CVEs and catches {r7['coverage']:.0%} of the exploited ones; adding the unscored "
                f"CVEs catches {r7u['coverage']:.0%} but flags {r7u['effort']:.0%} of everything. For comparison, the "
                f"model reaches {model_10:.1%} of 2024's exploited CVEs at 10% effort (see the Model vs EPSS page).")

with tabs[5]:
    tm = result("q3_timing_by_year")
    on_before = tm.set_index("publication year").loc["all", "on_or_before_share"]
    st.markdown(f"How long after publication did KEV list the exploited CVEs? {on_before:.0%} were listed **on or "
                "before** the day of publication: for them, a publication-day ranking cannot give early warning.")
    t = table()
    ex = t[t["split"].isin(["train", "validate", "test"]) & t[cm.LABEL].astype(bool)].copy()
    ex["year"] = ex["published"].dt.year.astype(str).replace({"2021": "2021 (Nov–Dec)"})
    max_days = st.slider("Show the first … days", 30, 365, 120)
    rows = []
    for yr, g in ex.groupby("year"):
        d = np.sort(g["days_to_kev"].clip(lower=-1).to_numpy())
        xs = np.arange(-1, max_days + 1)
        rows.append(pd.DataFrame({"year": yr, "days": xs, "share": np.searchsorted(d, xs, side="right") / len(d)}))
    ecdf = alt.Chart(pd.concat(rows)).mark_line(interpolate="step-after").encode(
        x=alt.X("days:Q", title="days from publication to KEV listing (−1 = before publication)"),
        y=alt.Y("share:Q", title="share of the year's exploited CVEs listed", axis=alt.Axis(format="%"),
                scale=alt.Scale(domain=[0, 1])),
        color=alt.Color("year:N", title=None, legend=alt.Legend(orient="bottom-right")),
        tooltip=["year", "days", alt.Tooltip("share:Q", format=".0%")])
    st.altair_chart(ecdf.properties(height=360), **WIDE)
    show = pd.DataFrame({"publication year": tm["publication year"], "exploited": tm["exploited"],
                         "listed on or before publication": [f"{pct(v, 0)} ({pct(lo, 0)}–{pct(hi, 0)})" for v, lo, hi in
                                                             zip(tm["on_or_before_share"], tm["on_or_before_low"],
                                                                 tm["on_or_before_high"])],
                         "within 30 days": tm["within_30_days_share"].map(lambda v: pct(v, 0)),
                         "median days (95% interval)": [f"{m:g} ({lo:g}–{hi:g})" for m, lo, hi in
                                                         zip(tm["median_days"], tm["median_low"], tm["median_high"])]})
    st.dataframe(show, hide_index=True, **WIDE)
    med = tm.set_index("publication year")["median_days"]
    change = result("q3_change_vs_2022")
    clear = bool(change.loc[change["measure"] == "median delay (days)", "clear_change"].any())
    st.markdown(f"The median delay was {med['2022']:g} days in 2022, {med['2023']:g} in 2023 and {med['2024']:g} in "
                "2024. " + ("At least one change from 2022 is clear." if clear else "The intervals overlap: the "
                "change cannot be told apart from chance with these numbers."))
