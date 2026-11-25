"""The problem, for readers new to the topic: what a CVE is, how many appear, how few are attacked, and why a
ranked to-do list helps. Every number on this page is computed from the project's data."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # the app folder

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

import story
import ui
from common import WIDE, cm, curve, cwe_names, scores_2024, table

EXAMPLE_ID = "CVE-2024-3400"


@st.cache_data(show_spinner="Preparing the story…")
def facts():
    s = scores_2024()
    y = s[cm.LABEL].astype(bool).to_numpy()
    n, k = len(s), int(y.sum())
    day = s["published"].dt.normalize()
    sev = (s["cvss_score"] >= 7).to_numpy()
    n_top = int(round(0.10 * n))
    top = np.zeros(n, bool)
    top[np.argsort(-s["final model"].to_numpy(), kind="stable")[:n_top]] = True
    d = s.loc[y, "days_to_kev"].astype(float)
    crit = (s["cvss_score"] >= 9).to_numpy()
    per_day = day.value_counts().sort_index()
    weekday = day.dt.dayofweek
    return {
        "n": n, "k": k, "one_in": round(n / k), "per_day": n / day.dt.dayofyear.max(),
        "busiest_day": per_day.idxmax(), "busiest_n": int(per_day.max()),
        "weekday_avg": float(per_day[per_day.index.dayofweek < 5].mean()),
        "weekend_avg": float(per_day[per_day.index.dayofweek >= 5].mean()),
        "sev_n": int(sev.sum()), "sev_share": sev.mean(), "sev_caught": int((sev & y).sum()),
        "unscored_share": float(s["cvss_score"].isna().mean()), "unscored_attacked": int((s["cvss_score"].isna() & y).sum()),
        "crit_n": int(crit.sum()), "crit_attacked": int((crit & y).sum()),
        "top_n": n_top, "top_caught": int((top & y).sum()),
        "before": int((d <= 0).sum()), "week": int((d <= 7).sum()), "month": int((d <= 30).sum()),
        "median_days": float(d.median()), "weekday_counts": weekday.value_counts().sort_index().tolist(),
        "codes": "".join(chr(48 + a + 2 * b + 4 * c) for a, b, c in zip(y.astype(int), sev.astype(int), top.astype(int))),
    }


@st.cache_data(show_spinner=False)
def replay_days():
    "Per day of 2024: flaws published, how many were later attacked, a few IDs."
    s = scores_2024().sort_values(["published", "cve_id"])
    s = s.assign(day=s["published"].dt.strftime("%Y-%m-%d"))
    out = []
    for d in pd.date_range("2024-01-01", "2024-12-31").strftime("%Y-%m-%d"):
        g = s[s["day"] == d]
        out.append({"d": d, "n": int(len(g)), "x": int(g[cm.LABEL].sum()), "ids": g["cve_id"].head(8).tolist(),
                    "xi": g.loc[g[cm.LABEL].astype(bool), "cve_id"].tolist()})
    return out


@st.cache_data(show_spinner=False)
def example():
    t = table()
    r = t[t["cve_id"] == EXAMPLE_ID].iloc[0]
    name = cwe_names().get(r["cwe_primary"], r["cwe_primary"])
    plain = name.split(" ", 1)[1] if isinstance(name, str) and " " in name else str(name)
    pub = r["published"]
    return {"id": EXAMPLE_ID, "published": f"{pub:%B} {pub.day}, {pub.year}",
            "publisher": r["publisher"], "score": f"{r['cvss_score']:g}", "severity": str(r["cvss_severity"]).title(),
            "weakness": name, "weakness_plain": f"Here: {plain.lower()}.",
            "description": cm.mask_exploitation(r["description"]).split("\n")[0],
            "kev": r["kev_date_added"], "days": int(r["days_to_kev"]) if pd.notna(r["days_to_kev"]) else None}


f = facts()
n, k = f["n"], f["k"]
fmt = lambda v: f"{v:,}"                                          # noqa: E731

# ------------------------------------------------------------------------------------------------- opening
ui.hero("The problem, in plain words",
        f"Every day, about {f['per_day']:.0f} new software flaws are made public. Which ones will attackers use?",
        f"In 2024, {fmt(n)} flaws in software and devices were published. Only {k} of them were later confirmed as "
        "used in real attacks. Security teams cannot fix everything at once, so they have to guess, on the day each "
        "flaw appears, which ones matter. This page explains that problem step by step; the other pages show how the "
        "project tackles it.")
ui.embed(story.timelapse_html(replay_days()), height=392)

# ------------------------------------------------------------------------------------------------- 1. what is a CVE
ui.section("01", "The basics", "What is a software flaw, and what is a CVE?",
           "A flaw (a <i>vulnerability</i>) is a mistake in software that lets someone do what they should not: read "
           "private data, take over a device, stop a service. When a flaw becomes public it gets an ID, a <b>CVE</b> "
           "number, much like a product recall notice gets a reference number. Here is a real one, exactly as it was "
           "known on the day it was published:")
ex = example()
ui.svg(story.anatomy_svg(ex))
listed = "the same day" if ex["days"] == 0 else f"{ex['days']} days later"
ui.callout(f"<b>What happened next.</b> Attackers were already using {ex['id']}: the US cybersecurity agency CISA added "
           f"it to its list of flaws known to be attacked {listed}. Most CVEs are never attacked at all. The hard part is "
           "telling the two kinds apart on day one.", "red")

# ------------------------------------------------------------------------------------------------- 2. the flood
ui.section("02", "The flood", f"{fmt(n)} flaws in one year",
           f"That is about {f['per_day']:.0f} a day, every day, including holidays. Each square below is one day of "
           "2024; darker means more flaws published.")
s24 = scores_2024()
days = s24["published"].dt.normalize().value_counts().rename_axis("date").reset_index(name="flaws")
days = (pd.DataFrame({"date": pd.date_range("2024-01-01", "2024-12-31")}).merge(days, on="date", how="left")
        .fillna({"flaws": 0}))
days["week"] = ((days["date"].dt.dayofyear - 1 + days["date"].iloc[0].dayofweek) // 7).astype(int)
days["weekday"] = days["date"].dt.day_name().str[:3]
days["label"] = days["date"].dt.strftime("%a %b %d, %Y")
heat = alt.Chart(days).mark_rect(cornerRadius=2, stroke="white", strokeWidth=1.5).encode(
    x=alt.X("week:O", axis=None),
    y=alt.Y("weekday:O", sort=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], title=None,
            axis=alt.Axis(labelFontSize=11, ticks=False, domain=False)),
    color=alt.Color("flaws:Q", scale=alt.Scale(scheme="blues", type="sqrt"), legend=alt.Legend(
        title="flaws that day", orient="bottom", gradientLength=220, titleFontSize=11)),
    tooltip=[alt.Tooltip("label:N", title="day"), alt.Tooltip("flaws:Q", title="flaws published")])
firsts = days[days["date"].dt.day == 1]
months = alt.Chart(firsts.assign(m=firsts["date"].dt.strftime("%b"))).mark_text(
    align="left", dy=-4, fontSize=11, color="#5b6470").encode(x=alt.X("week:O", axis=None), y=alt.value(-6), text="m:N")
st.altair_chart((heat + months).properties(height=190), **WIDE)
c1, c2, c3 = st.columns(3)
with c1:
    ui.big_number(f"{f['per_day']:.0f}", "flaws published on an average day of 2024", "blue")
with c2:
    ui.big_number(fmt(f["busiest_n"]), f"on the busiest day, {f['busiest_day']:%B} {f['busiest_day'].day}", "blue")
with c3:
    ui.big_number(f"{f['weekday_avg'] / max(f['weekend_avg'], 1):.0f}×",
                  f"more on a weekday ({f['weekday_avg']:.0f}) than on a weekend day ({f['weekend_avg']:.0f})", "blue")

# ------------------------------------------------------------------------------------------------- 3. the needle
ui.section("03", "The needle in the haystack", f"Only {k} of them were used in attacks",
           f"Below, every one of the {fmt(n)} flaws of 2024 is a square. Use the buttons to see which were attacked, what "
           "a common rule of thumb would fix, and what NeedlePoint's ranked list would fix.")
stats = {"n_fmt": fmt(n), "k_fmt": str(k), "one_in": str(f["one_in"]), "per_day": f"{f['per_day']:.0f}",
         "sev_n": fmt(f["sev_n"]), "sev_share": f"{f['sev_share']:.0%}", "sev_caught": str(f["sev_caught"]),
         "sev_missed": str(k - f["sev_caught"]), "top_n": fmt(f["top_n"]), "top_caught": str(f["top_caught"])}
ui.embed(story.dotfield_html(f["codes"], stats, height=440), height=640)
st.caption("“Attacked” means listed in CISA's Known Exploited Vulnerabilities catalogue within a year of publication: "
           "the best public record of real attacks, though some attacks are never reported.")

# ------------------------------------------------------------------------------------------------- 4. the race
ui.section("04", "A race against time", "When does the world find out?",
           "For the attacked flaws, the moment that matters is when CISA confirms the attacks and lists them. Each dot "
           f"below is one of the {k} attacked flaws of 2024, placed by how long after publication it was listed.")
d = s24.loc[s24[cm.LABEL].astype(bool), ["cve_id", "days_to_kev"]].copy()
bins = [(-10**6, -1, "before\npublication"), (0, 0, "the same\nday"), (1, 7, "within\na week"),
        (8, 30, "within\na month"), (31, 90, "within\n3 months"), (91, 365, "within\na year")]
d["when"] = [next(lab for lo, hi, lab in bins if lo <= v <= hi) for v in d["days_to_kev"]]
d["order"] = d["when"].map({lab: i for i, (_, _, lab) in enumerate(bins)})
d = d.sort_values(["order", "days_to_kev", "cve_id"])
d["stack"] = d.groupby("when").cumcount()
d["known"] = np.where(d["order"] <= 1, "already public by publication day", "listed later")
d["tip"] = [f"{c}: listed {int(v)} days after publication" if v > 0 else (f"{c}: listed the same day" if v == 0 else
            f"{c}: listed {-int(v)} days before publication") for c, v in zip(d["cve_id"], d["days_to_kev"])]
labels = [lab for _, _, lab in bins]
PER_ROW, GAP = 6, 2.5
d["col"] = d["stack"] % PER_ROW
d["row"] = d["stack"] // PER_ROW
d["x"] = d["order"] * (PER_ROW + GAP) + d["col"]
rows_max = int(d["row"].max()) + 1
dots = alt.Chart(d).mark_circle(size=105, opacity=0.95).encode(
    x=alt.X("x:Q", axis=None, scale=alt.Scale(domain=[-1, len(bins) * (PER_ROW + GAP) - GAP])),
    y=alt.Y("row:Q", axis=None, scale=alt.Scale(domain=[-3.6, rows_max + 0.6])),
    color=alt.Color("known:N", scale=alt.Scale(domain=["already public by publication day", "listed later"],
                                               range=["#c8372d", "#1f5fa8"]),
                    legend=alt.Legend(title=None, orient="top", labelFontSize=12, labelLimit=320)),
    tooltip=[alt.Tooltip("tip:N", title="flaw")])
counts = d.groupby("when").size().reindex(labels).fillna(0).astype(int).reset_index(name="count")
counts["x"] = [i * (PER_ROW + GAP) + (PER_ROW - 1) / 2 for i in range(len(labels))]
counts["name"] = counts["when"]
counts["n"] = counts["count"].map(lambda c: f"{c} flaw" + ("" if c == 1 else "s"))
names = alt.Chart(counts).mark_text(fontSize=12.5, fontWeight=600, color="#14181f", baseline="top", lineBreak="\n").encode(
    x="x:Q", y=alt.Y("y:Q", scale=alt.Scale(domain=[-3.6, rows_max + 0.6])), text="name:N").transform_calculate(y="-1.1")
num = alt.Chart(counts).mark_text(fontSize=12, color="#5b6470", baseline="top").encode(
    x="x:Q", y=alt.Y("y:Q", scale=alt.Scale(domain=[-3.6, rows_max + 0.6])), text="n:N").transform_calculate(y="-2.6")
c1, c2 = st.columns([3, 1.25])
with c1:
    st.altair_chart(alt.layer(dots, names, num).resolve_scale(y="shared").properties(height=300), **WIDE)
with c2:
    ui.big_number(f"{f['before'] / k:.0%}", f"were listed on or before the day they were published: too late for any "
                  "prediction made that day.", "red")
    st.write("")
    ui.big_number(f"{f['median_days']:g} days", "was the typical wait (the median) between publication and listing.")
    st.write("")
    ui.big_number(f"{f['month'] / k:.0%}", "were listed within a month. A team that guesses right on day one gets "
                  "days or weeks of head start.", "blue")

# ------------------------------------------------------------------------------------------------- 5. the rule of thumb
ui.section("05", "What teams do today", "The usual rule: fix everything rated “high” or “critical”",
           "Each published flaw comes with a severity score from 0 to 10 set by its maker. A common rule is to fix "
           "everything scored 7.0 or more. Here is what that rule would have meant in 2024:")
sev_share, caught = f["sev_share"], f["sev_caught"]
ui.html(f"""
<div style="display:grid;gap:18px;margin:.6rem 0 1.2rem">
 <div><div style="display:flex;justify-content:space-between;font-size:.92rem;margin-bottom:6px">
   <span><b>The work</b>: share of all {fmt(n)} flaws the rule says to fix</span><span class="x-num">{sev_share:.0%}</span></div>
  <div style="height:30px;border-radius:8px;background:#eef1f4;overflow:hidden;display:flex">
   <div style="width:{sev_share * 100:.1f}%;background:#a9c4e6;color:#14181f;font:600 13px/30px var(--mono);padding-left:10px;white-space:nowrap;overflow:visible">
   {fmt(f['sev_n'])} flaws to fix</div></div></div>
 <div><div style="display:flex;justify-content:space-between;font-size:.92rem;margin-bottom:6px">
   <span><b>The result</b>: share of the {k} attacked flaws it catches</span><span class="x-num">{caught / k:.0%}</span></div>
  <div style="height:30px;border-radius:8px;background:repeating-linear-gradient(45deg,#fbeceb,#fbeceb 6px,#f6dcd9 6px,#f6dcd9 12px);overflow:hidden;display:flex">
   <div style="width:{caught / k * 100:.1f}%;background:#c8372d;color:#fff;font:600 13px/30px var(--mono);padding-left:10px;white-space:nowrap">
   {caught} caught</div><div style="padding-left:10px;font:600 13px/30px var(--mono);color:#c8372d">{k - caught} missed</div></div></div>
</div>""")
c1, c2 = st.columns(2)
with c1:
    ui.callout(f"<b>Why it misses so many.</b> The score says how bad a flaw <i>would be</i> if attacked, not how "
               f"<i>likely</i> an attack is. In 2024, {fmt(f['crit_n'])} flaws were rated critical (9.0 or more); "
               f"only {f['crit_attacked']} of them were attacked.")
with c2:
    ui.callout(f"<b>And some have no score at all.</b> {f['unscored_share']:.0%} of 2024's flaws arrived without a "
               f"severity score from their maker. {f['unscored_attacked']} of the attacked flaws were among them, "
               "invisible to a rule based on the score.", "red")

# ------------------------------------------------------------------------------------------------- 6. the idea
ui.section("06", "The idea", "Sort the list, then start at the top",
           "Hospitals face the same problem every night: more patients than doctors. They do not treat everyone the "
           "same way; a triage nurse sorts patients by urgency, using only what can be seen when they arrive.")
ui.svg(story.triage_svg(f["per_day"]))
st.markdown(f"**NeedlePoint** is that nurse for software flaws: a model that reads what is known on the day a flaw is "
            f"published (who made it, the kind of mistake, its severity parts, the words of its description) and "
            f"puts all {fmt(n)} flaws of 2024 in order. It learned only from flaws published before 2024, so 2024 "
            "is a fair test. **Try it:** choose how much your team can handle and compare three ways of choosing.")
effort = st.select_slider("Your team has time for …", options=[0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.26, 0.30, 0.40, 0.50],
                          value=0.10, format_func=lambda v: f"{v:.0%} of new flaws", key="problem_effort")
y = s24[cm.LABEL].to_numpy()
rows = [("Random order", "no information at all", effort * k, "#b9c6d4"),
        ("Highest severity first", "the maker's 0–10 score; unscored flaws placed with the “high” ones",
         curve(y, s24["CVSS score, unscored slotted in"].to_numpy(), [effort])[0] * k, "#6f9bd1"),
        ("NeedlePoint", "the model, using only day-one information",
         curve(y, s24["final model"].to_numpy(), [effort])[0] * k, "#14946a")]
bars = "".join(
    f"""<div class="x-board-row">
<div><div style="font-weight:600">{name}</div><div style="font-size:.82rem;color:var(--muted);line-height:1.35">{sub}</div></div>
<div style="position:relative;height:38px;border-radius:9px;background:#f0f3f6;overflow:hidden">
<div style="position:absolute;inset:0 auto 0 0;width:{c / k * 100:.2f}%;background:{col};border-radius:9px;transition:width .6s cubic-bezier(.2,.8,.2,1)"></div>
<div style="position:absolute;left:12px;top:0;bottom:0;display:flex;align-items:center;font:600 14px var(--mono);color:#14181f;white-space:nowrap">{c:.0f} of {k} · {c / k:.0%}</div>
</div></div>""" for name, sub, c, col in rows)
per_week = effort * n / 52.18
ui.html(f'<div style="margin:.4rem 0 .2rem"><div class="x-kicker" style="text-align:right">attacked flaws caught, of {k}</div>{bars}</div>')
ui.callout(f"At {effort:.0%}, a team handles about <b>{per_week:,.0f} flaws a week</b> instead of all "
           f"{n / 52.18:,.0f}. With the ranked list, those are the ones most likely to be attacked.", "green")
st.caption("Counts can be fractional because flaws with exactly the same score are split evenly. The model never saw any "
           "2024 flaw while it was being built.")

# ------------------------------------------------------------------------------------------------- 7. how
ui.section("07", "How the project works", "From three public sources to one ranked list",
           "Everything comes from free, public data collected with Python: the US National Vulnerability Database "
           "(NVD) lists every flaw, CISA's catalogue says which were attacked, and FIRST's EPSS is the industry's own "
           "prediction score, used as a benchmark.")
ui.svg(story.pipeline_svg())

# ------------------------------------------------------------------------------------------------- 8. questions
ui.section("08", "The four questions", "What the project sets out to answer")
qs = [("A", "What do attacked flaws have in common on day one?", "Severity, kind of mistake, publisher.",
       "views/what_we_learned.py", "What we learned"),
      ("B", "Can those traits put new flaws in a better order than severity alone?", "The ranked list above.",
       "views/triage.py", "Triage"),
      ("C", "How long after publication are attacks confirmed?", "The race against time.",
       "views/what_we_learned.py", "What we learned"),
      ("D", "How does the ranking compare with the industry's daily score (EPSS)?", "Day-one ranking vs a score "
       "that keeps learning.", "views/model_vs_epss.py", "Model vs EPSS")]
for code, q, hint, page, label in qs:
    a, b = st.columns([5, 1.4])
    with a:
        ui.html(f'<div style="display:flex;gap:16px;align-items:baseline;padding:10px 0;border-top:1px solid var(--line)">'
                f'<span class="x-chip">{code}</span><div><div style="font:600 1.08rem/1.35 var(--serif)">{q}</div>'
                f'<div style="color:var(--muted);font-size:.9rem;margin-top:2px">{hint}</div></div></div>')
    with b:
        st.write("")
        ui.link(page, f"Open {label} →")

# ------------------------------------------------------------------------------------------------- glossary
ui.section("09", "Words used in this app", "A short glossary")
terms = [("CVE", "The public ID of a software flaw, for example CVE-2024-3400."),
         ("Publisher", "The organisation that published the CVE, usually the maker of the product."),
         ("Severity (CVSS)", "A 0–10 score of how bad a flaw would be if attacked: 7.0+ is “high”, 9.0+ “critical”."),
         ("Attacked (KEV)", "Listed in CISA's Known Exploited Vulnerabilities catalogue within a year of publication."),
         ("EPSS", "FIRST's daily estimate of the chance a flaw will be attacked soon; it keeps updating as news comes in."),
         ("Effort", "The share of new flaws a team handles, starting from the top of a list."),
         ("Coverage", "The share of the attacked flaws that falls inside the handled part of the list.")]
g1, g2 = st.columns(2)
for i, (term, text) in enumerate(terms):
    with (g1 if i % 2 == 0 else g2):
        ui.html(f'<div style="padding:10px 0;border-top:1px solid var(--line)"><div style="font-weight:600">{term}</div>'
                f'<div style="color:#3a434e;font-size:.95rem;line-height:1.5">{text}</div></div>')
