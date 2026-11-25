"""Triage: rank a list of CVEs with the reasons behind each score, or replay a stretch of 2024."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # the app folder, for `common`

import io

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from common import (WIDE, COLORS, RANKINGS, cm, curve, cwe_names, model, model_missing_notice, odds_factor,
                    scores_2024, table)
import ui  # noqa: E402

ui.hero("Triage", "Which of these CVEs should a team handle first?",
        "Rank your own list of CVEs with the reasons behind each score, or replay any month of 2024 and see which "
        "exploited CVEs each ranking would have caught.")
EXAMPLE = ("CVE-2024-3400  CVE-2024-21413  CVE-2024-23897  CVE-2024-21732  CVE-2024-6387\n"
           "CVE-2024-9474  CVE-2024-0012  CVE-2023-5877  CVE-2024-27198")
BUDGETS = [0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.26, 0.30, 0.50]
SOURCE = {"test": "2024 (test year)", "train": "Nov 2021–2022 (model learned from it)",
          "validate": "2023 (model learned from it)", "pre-KEV": "2016–Nov 2021 (before KEV began)"}
fm = model()
t = table()
s24 = scores_2024()
REF = np.sort(s24["final model"].to_numpy())


def top_share(scores):
    "Share of 2024 CVEs scored at least as high by the model (0.01 = top 1% of 2024)."
    return 1.0 - np.searchsorted(REF, np.asarray(scores, float), side="left") / len(REF)


@st.cache_data(ttl=3600, show_spinner=False)
def live_record(cve_id):
    "Today's NVD record, flattened with the publisher-only rules; or an error message."
    try:
        return cm.flatten_live(cm.fetch_nvd(cve_id, cm.load_api_key())), None
    except cm.LookupError_ as exc:
        return None, str(exc)


@st.cache_data(ttl=6 * 3600, show_spinner="Reading today's KEV catalogue…")
def kev_today():
    return cm.fetch_kev()


def reasons(row_frame):
    "The model's explanation of one CVE, or None without the model."
    return fm.explain(row_frame) if fm is not None else None


def short_reasons(expl, n=3):
    "The n strongest upward pushes, as a short text."
    if expl is None:
        return ""
    ups = sorted((g for g in expl["groups"] if g["push"] > 0.05), key=lambda g: -g["push"])[:n]
    names = cwe_names()
    return "; ".join(f"{cm.label_group(g, names)} {odds_factor(g['push'])}" for g in ups)


def explain_chart(expl):
    names = cwe_names()
    rows = pd.DataFrame([{"input": cm.label_group(g, names), "push": g["push"], "factor": odds_factor(g["push"])}
                         for g in expl["groups"] if abs(g["push"]) >= 0.02])
    rows["direction"] = np.where(rows["push"] > 0, "raises", "lowers")
    rows = rows.sort_values("push", ascending=False)
    return (alt.Chart(rows).mark_bar().encode(
        x=alt.X("push:Q", title="effect on the odds, compared with an average CVE of 2021–2023",
                axis=alt.Axis(labelExpr="'×' + format(exp(datum.value), '.2~f')")),
        y=alt.Y("input:N", sort=list(rows["input"]), title=None, axis=alt.Axis(labelLimit=380, labelOverlap=False)),
        color=alt.Color("direction:N", scale=alt.Scale(domain=["raises", "lowers"], range=["#e0574f", "#2a78d6"]),
                        legend=None),
        tooltip=["input", alt.Tooltip("factor:N", title="odds ×")])
        .properties(height=alt.Step(26)))


def lookup(ids, allow_live, max_live=25):
    "One row per ID: the model's inputs, where they came from, and what is known about the outcome."
    known = t.set_index("cve_id")
    rows, live_used = [], 0
    for cve_id in ids:
        if cve_id in known.index:
            r = known.loc[cve_id]
            rows.append({"cve_id": cve_id, "where": SOURCE.get(r["split"], r["split"]), "split": r["split"],
                         **{c: r[c] for c in ["published", *cm.FEATURE_COLUMNS, "cvss_severity", "publisher"]},
                         "exploited": bool(r[cm.LABEL]) if r["split"] != "pre-KEV" else None,
                         "kev_date": r["kev_date_added"], "error": None})
        elif allow_live and live_used < max_live:
            live_used += 1
            rec, err = live_record(cve_id)
            if rec is None:
                rows.append({"cve_id": cve_id, "where": "not found", "error": err})
                continue
            rows.append({**rec, "where": "NVD today (live)", "split": "live",
                         "publisher": cm.publisher_of(pd.DataFrame({"cna": [rec["cna"]]})).iloc[0],
                         "exploited": None, "kev_date": None, "error": None})
        else:
            rows.append({"cve_id": cve_id, "where": "not found",
                         "error": "not in our data (published 2016–2024); live lookup is off or the limit was reached"})
    return pd.DataFrame(rows)


tab_rank, tab_replay = st.tabs(["Rank your CVEs", "Replay 2024"])

# ====================================================================== Rank your CVEs
with tab_rank:
    st.markdown("Paste CVE IDs (any separator). CVEs published 2016–2024 come from the project's data, exactly as the "
                "model saw them; newer ones are looked up at the NVD and scored live.")
    if "ids_text" not in st.session_state:
        st.session_state["ids_text"] = ""
    c1, c2 = st.columns([4, 1])
    with c2:
        if st.button("Load an example"):
            st.session_state["ids_text"] = EXAMPLE
    with c1:
        text = st.text_area("CVE IDs", key="ids_text", height=110, placeholder="CVE-2024-3400, CVE-2025-…")
    o1, o2, o3 = st.columns(3)
    budget = o1.select_slider("Your team can handle the top …", BUDGETS, value=0.10, format_func=lambda v: f"{v:.0%}",
                              help="Effort: the share of all new CVEs a team can deal with. A CVE that would rank "
                                   "within that share of 2024's CVEs is marked 'handle now'.")
    allow_live = o2.toggle("Look up newer CVEs at the NVD", value=True, help="Up to 25 per list. About 6 s each "
                           "without an NVD API key in .env, under a second with one.")
    reveal = o3.toggle("Show what happened (KEV)", value=False,
                       help="For CVEs of 2016–2024: was it listed in KEV within a year? Off by default, so you can "
                            "judge the ranking first.")
    ids = cm.parse_ids(text)
    if not ids:
        st.info("Paste some CVE IDs, or load the example.")
    else:
        with st.spinner(f"Looking up {len(ids)} CVEs…"):
            found = lookup(ids, allow_live)
        ok = found[found["error"].isna()].reset_index(drop=True)
        bad = found[found["error"].notna()]
        if len(ok):
            frame = cm.model_frame(ok)
            if fm is not None:
                ok["score"] = fm.score(frame)
            else:
                ok["score"] = np.nan
            saved = s24.set_index("cve_id")["final model"]
            in24 = ok["cve_id"].isin(saved.index)
            ok.loc[in24, "score"] = ok.loc[in24, "cve_id"].map(saved)        # the saved 2024 scores, where they exist
            ok = ok[ok["score"].notna()].reset_index(drop=True)
            if fm is None and (~in24).any():
                model_missing_notice()
        if len(ok):
            ok["top"] = top_share(ok["score"])
            ok = ok.sort_values("score", ascending=False).reset_index(drop=True)
            expl = {r.cve_id: reasons(cm.model_frame(ok.iloc[[i]])) for i, r in enumerate(ok.itertuples())}
            cols = {
                "rank": np.arange(1, len(ok) + 1),
                "CVE": ok["cve_id"],
                "handle now": np.where(ok["top"] <= budget, "handle now", "later"),
                "rank among 2024 CVEs": ["top " + (f"{v:.2%}" if v < 0.01 else f"{v:.1%}") for v in ok["top"]],
            }
            if reveal:
                cols["in KEV within a year"] = [("–" if e is None else ("yes, listed " + str(d)[:10]) if e else "no")
                                                for e, d in zip(ok["exploited"], ok["kev_date"])]
            cols.update({
                "main reasons (odds vs an average CVE)": [short_reasons(expl[c]) for c in ok["cve_id"]],
                "publisher": ok["publisher"],
                "severity": [("–" if pd.isna(sc) else f"{sc:g} ({str(sev).title()})" if sev else f"{sc:g}")
                             for sc, sev in zip(ok["cvss_score"], ok.get("cvss_severity", [None] * len(ok)))],
                "weakness": [cwe_names().get(c, c) if isinstance(c, str) else "–" for c in ok["cwe_primary"]],
                "data from": ok["where"],
            })
            view = pd.DataFrame(cols)
            st.dataframe(view, hide_index=True, **WIDE)
            st.caption(f"{int((ok['top'] <= budget).sum())} of {len(ok)} would be handled now at {budget:.0%} effort. "
                       f"'Rank among 2024 CVEs' places each score among the {len(s24):,} CVEs of 2024 scored by the same model.")
            buf = io.StringIO()
            view.to_csv(buf, index=False)
            st.download_button("Download this list (CSV)", buf.getvalue(), "triage_list.csv", "text/csv")
            if (ok["split"].isin(["train", "validate"])).any():
                st.caption("CVEs of Nov 2021–2023 were part of the model's training data, so their scores are not "
                           "fair predictions.")
            if (ok["split"] == "live").any():
                st.caption("Live lookups read today's NVD record, which may have been edited since publication.")

            st.subheader("Why this score?")
            pick = st.selectbox("CVE", list(ok["cve_id"]), format_func=lambda c: f"{c} · rank "
                                f"{int(ok.index[ok['cve_id'] == c][0]) + 1}")
            r = ok[ok["cve_id"] == pick].iloc[0]
            e = expl[pick]
            left, right = st.columns([3, 2])
            with left:
                if e is None:
                    model_missing_notice()
                else:
                    st.markdown(f"Compared with an average CVE of 2021–2023, the inputs of **{pick}** multiply the "
                                f"odds of a KEV listing by **{odds_factor(e['logit'] - e['average_logit'])}** in "
                                "total. Red bars raise the odds, blue bars lower them.")
                    st.altair_chart(explain_chart(e), **WIDE)
            with right:
                st.markdown(f"**{r['publisher']}** · published {str(r['published'])[:10]} · {r['where']}")
                cleaned = cm.mask_exploitation(r["description"])
                quoted = (cleaned or "(no description)").replace("\n", "\n> ")
                st.markdown(f"> {quoted}")
                if cleaned != (r["description"] or ""):
                    st.caption("A sentence stating exploitation was removed before scoring.")
                if e is not None and e["words"]:
                    words = pd.DataFrame(e["words"][:12])
                    words["odds"] = words["push"].map(odds_factor)
                    st.markdown("**Strongest words and word pairs**")
                    st.dataframe(words[["word", "odds"]], hide_index=True, **WIDE)

            with st.expander("Today's KEV and EPSS for this list"):
                st.caption("Live data, for context only: today's EPSS reads KEV and much more, so it is not a "
                           "publication-day prediction.")
                if st.button("Check now"):
                    kev, src = kev_today()
                    epss = cm.fetch_epss(list(ok["cve_id"]))
                    st.dataframe(pd.DataFrame({
                        "CVE": ok["cve_id"],
                        f"in KEV ({src or 'unavailable'})": [kev.get(c, "no") if kev else "?" for c in ok["cve_id"]],
                        "EPSS today": [f"{epss[c]:.3f}" if c in epss else "?" for c in ok["cve_id"]]}),
                        hide_index=True)
        for row in bad.itertuples():
            st.warning(f"{row.cve_id}: {row.error}")

# ====================================================================== Replay 2024
with tab_replay:
    st.markdown("Pick a stretch of 2024 and a team's capacity. The CVEs published then are ranked as on publication "
                "day; then we reveal which were listed in KEV within a year, and how each ranking would have done.")
    months = ["All of 2024"] + [pd.Timestamp(2024, m, 1).strftime("%B 2024") for m in range(1, 13)]
    c1, c2, c3 = st.columns(3)
    period = c1.selectbox("Period", months, index=0)
    effort = c2.select_slider("Capacity: top …", BUDGETS, value=0.10, format_func=lambda v: f"{v:.0%}",
                              key="replay_effort")
    ranking = c3.selectbox("Ranking for the to-do list", list(RANKINGS), index=0)
    w = s24.copy()
    if period != "All of 2024":
        m = pd.Timestamp(period)
        w = w[(w["published"] >= m) & (w["published"] < m + pd.offsets.MonthBegin(1))]
    y = w[cm.LABEL].to_numpy()
    k_ex, n = int(y.sum()), len(w)
    handled = int(round(effort * n))
    st.markdown(f"**{n:,} CVEs** published in {period.replace('All of ', '')}; **{k_ex}** were listed in KEV within a "
                f"year. A team handling the top {effort:.0%} looks at **{handled:,}** of them.")
    if k_ex == 0:
        st.info("No exploited CVEs in this period: every ranking catches 0 of 0.")
    else:
        board = pd.DataFrame([{"ranking": name, "caught": curve(y, w[col].to_numpy(), [effort])[0] * k_ex}
                              for name, col in RANKINGS.items()] +
                             [{"ranking": "Random order", "caught": effort * k_ex}])
        board["share"] = board["caught"] / k_ex
        board["label"] = [f"{c:.1f} of {k_ex} ({s:.0%})" for c, s in zip(board["caught"], board["share"])]
        chart = alt.Chart(board).mark_bar().encode(
            x=alt.X("caught:Q", title=f"exploited CVEs caught (of {k_ex})", scale=alt.Scale(domain=[0, k_ex])),
            y=alt.Y("ranking:N", sort=list(board.sort_values("caught", ascending=False)["ranking"]), title=None,
                    axis=alt.Axis(labelLimit=220)),
            color=alt.Color("ranking:N", scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values())), legend=None),
            tooltip=["ranking", "label"])
        text = chart.mark_text(align="left", dx=4, fontSize=12).encode(text="label:N", color=alt.value("#333"))
        st.altair_chart((chart + text).properties(height=290), **WIDE)
        st.caption("Caught = exploited CVEs inside the handled share (ties split evenly, so counts can be fractional). "
                   "EPSS scores arrive 1, 7 or 30 days after publication; CVEs it had not scored yet are placed last. "
                   "In short periods the counts are small and luck plays a large part.")

        col = RANKINGS[ranking]
        order = w.sort_values(col, ascending=False, kind="stable").reset_index(drop=True)
        order["position"] = np.arange(1, len(order) + 1)
        todo = order.head(handled)
        st.subheader(f"The to-do list by {ranking}: {handled:,} CVEs")
        show = pd.DataFrame({"#": todo["position"], "CVE": todo["cve_id"], "published": todo["published"].dt.date,
                             "publisher": todo["publisher"],
                             "severity": [("–" if pd.isna(v) else f"{v:g}") for v in todo["cvss_score"]],
                             "exploited": np.where(todo[cm.LABEL], "yes", ""),
                             "KEV listing (days after publication)": [str(int(d)) if ex and pd.notna(d) else ""
                                                                      for d, ex in zip(todo["days_to_kev"], todo[cm.LABEL])]})
        st.dataframe(show, hide_index=True, **WIDE, height=320)
        missed = order[(order["position"] > handled) & order[cm.LABEL].astype(bool)]
        with st.expander(f"Exploited CVEs this ranking left for later: {len(missed)}"):
            st.dataframe(pd.DataFrame({"position in the list": missed["position"], "CVE": missed["cve_id"],
                                       "publisher": missed["publisher"],
                                       "severity": [("–" if pd.isna(v) else f"{v:g}") for v in missed["cvss_score"]],
                                       "listed in KEV before publication": missed["kev_before_publication"]
                                       .map({True: "yes", False: ""})}),
                         hide_index=True, **WIDE)
