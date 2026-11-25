"""Overview: the 2024 result in one picture, the model, and notes on the data."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # the app folder

import altair as alt
import pandas as pd
import streamlit as st

import ui
from common import COLORS, OUR, WIDE, cm, curve, model, scores_2024

s = scores_2024()
per_day = len(s) / 366                                   # 2024 is a leap year
y = s[cm.LABEL].to_numpy()
k = int(y.sum())

ui.hero("Overview", "Rank new CVEs on the day they appear",
        f"About {round(per_day, -1):.0f} CVEs were published per day in 2024, and 1 in {round(len(s) / k)} of them "
        "ended up in CISA's Known Exploited Vulnerabilities (KEV) catalogue within a year. NeedlePoint ranks new CVEs using only what is known on the day they are published, so a security team "
        "can decide which ones to handle first. It was fitted on CVEs published from November 2021 to the end of 2023 "
        "and tested on all of 2024.")

ui.section("2024", "The result in one picture", "How many exploited CVEs land in the top 10%?",
           f"{len(s):,} CVEs were published in 2024 and {k} of them were listed in KEV within a year. Each bar shows how "
           f"many of those {k} a team would have reached by handling the top 10% of the list "
           f"({round(0.10 * len(s)):,} CVEs).")
rows = []
for name, col in [(OUR, "final model"), ("Publisher's past rate", "Publisher's past rate"),
                  ("EPSS, day 7", "EPSS, day 7"), ("CVSS score", "CVSS score, unscored slotted in")]:
    share = curve(y, s[col].to_numpy(), [0.10])[0]
    label = "EPSS, 7 days after publication" if name == "EPSS, day 7" else name
    rows.append({"ranking": label, "key": name, "caught": share * k, "share": share,
                 "exploited CVEs in its top 10%": f"{share * k:.0f} of {k} ({share:.1%})"})
rows.append({"ranking": "Random order", "key": "Random order", "caught": 0.10 * k, "share": 0.10,
             "exploited CVEs in its top 10%": f"{0.10 * k:.0f} of {k} (10.0%)"})
board = pd.DataFrame(rows)
order = list(board["ranking"])
bars = alt.Chart(board).mark_bar(cornerRadiusEnd=6, height=26).encode(
    x=alt.X("caught:Q", title=f"exploited CVEs caught in the top 10% (of {k})", scale=alt.Scale(domain=[0, k])),
    y=alt.Y("ranking:N", sort=order, title=None, axis=alt.Axis(labelLimit=260, labelFontSize=13)),
    color=alt.Color("key:N", scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values())), legend=None),
    tooltip=["ranking", alt.Tooltip("exploited CVEs in its top 10%:N", title="caught")])
text = bars.mark_text(align="left", dx=8, fontSize=13, fontWeight=600, color="#14181f").encode(
    text="exploited CVEs in its top 10%:N")
st.altair_chart((bars + text).properties(height=270), **WIDE)
with st.expander("The same numbers as a table"):
    st.dataframe(board[["ranking", "exploited CVEs in its top 10%"]], hide_index=True, **WIDE)

ui.section("Next", "Where to go from here", "Four ways into the project")
links = [("views/problem.py", "The problem", "The story behind the project, for readers new to the topic."),
         ("views/triage.py", "Triage", "Paste CVE IDs and get them ranked, with the reasons behind each score. Or replay "
                                       "a month of 2024 and see which exploited CVEs a team would have caught."),
         ("views/model_vs_epss.py", "Model vs EPSS", "Compare the model with EPSS, CVSS and the publisher's past rate "
                                                     "on 2024, at any level of effort, on all CVEs or on equal information."),
         ("views/what_we_learned.py", "What we learned", "Which traits go with exploitation (severity, weakness type, "
                                                         "publisher), what severity rules cost, and how quickly KEV lists "
                                                         "exploited CVEs.")]
for page, label, text in links:
    a, b = st.columns([1.3, 4])
    with a:
        ui.link(page, f"{label} →")
    with b:
        st.markdown(f"<span style='color:#3a434e'>{text}</span>", unsafe_allow_html=True)

ui.section("Model", "Under the hood", "The model")
fm = model()
if fm is None:
    st.info("The model file has not been built yet. Building it fits the model on Nov 2021–2023 "
            "(about a minute, once).")
    if st.button("Build the model"):
        log = st.empty()
        with st.spinner("Fitting the model…"):
            try:
                cm.build_final_model(progress=log.write)
            except (RuntimeError, FileNotFoundError) as exc:
                st.error(f"Could not build the model: {exc}")
            else:
                model.clear()
                st.success("Model built.")
                st.rerun()
else:
    st.write(f"A logistic regression (C = {fm.b['C']}) on the publisher, the weakness type (CWE), the parts of the "
             "CVSS vector and the score, and the words of the cleaned description. Its scores are used to rank, "
             "not as probabilities.")

with st.expander("Notes on the data"):
    st.markdown(
        "- **Sources:** NVD CVE API 2.0 (only the fields the CVE's own publisher supplied), the CISA KEV catalogue "
        "(snapshot of 10 Nov 2026), and EPSS scores 1, 7 and 30 days after publication.\n"
        "- **Label:** listed in KEV within 365 days of publication. KEV is conservative: some exploited CVEs are "
        "never listed.\n"
        "- **Effort and coverage:** a team that handles the top 10% of new CVEs (the effort) reaches this share of "
        "the exploited ones (the coverage). CVEs with equal scores are split evenly.\n"
        "- **Ranks, not probabilities:** exploited CVEs get extra weight in training, so the raw scores overstate "
        "the chance of exploitation. The app shows where a CVE would rank among 2024's CVEs instead.\n"
        "- **Live lookups** read today's NVD record, which may have been edited since publication.")
