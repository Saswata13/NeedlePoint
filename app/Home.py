"""Entry point of the demo app.   Run from the project folder:   streamlit run app/Home.py

Sets the page layout and the look, then hands over to the page the reader picked in the top navigation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # the app folder

import streamlit as st  # noqa: E402

import ui  # noqa: E402
from common import STREAMLIT_VERSION  # noqa: E402

st.set_page_config(page_title="NeedlePoint", layout="wide", initial_sidebar_state="collapsed")
ui.style()
PAGES = [
    st.Page("views/problem.py", title="The problem", default=True, url_path="problem"),
    st.Page("views/overview.py", title="Overview", url_path="overview"),
    st.Page("views/triage.py", title="Triage", url_path="triage"),
    st.Page("views/model_vs_epss.py", title="Model vs EPSS", url_path="model-vs-epss"),
    st.Page("views/what_we_learned.py", title="What we learned", url_path="what-we-learned"),
]
nav = st.navigation(PAGES, position="top") if STREAMLIT_VERSION >= (1, 46) else st.navigation(PAGES)
ui.brand()
nav.run()
ui.footer()
