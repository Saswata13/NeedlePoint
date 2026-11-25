"""The app's look: one stylesheet, page headers, section headers and small HTML helpers shared by every page."""
import re

import streamlit as st

INK, MUTED, LINE, PAPER = "#14181f", "#5b6470", "#e3e7ec", "#f5f6f8"
BLUE, RED, GREEN, AMBER = "#1f5fa8", "#c8372d", "#14946a", "#b7791f"

CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&family=Source+Serif+4:opsz,wght@8..60,500;8..60,600;8..60,700&display=swap');
:root { --ink:#14181f; --muted:#5b6470; --line:#e3e7ec; --paper:#f5f6f8; --blue:#1f5fa8; --blue-soft:#e8f0fa;
        --red:#c8372d; --red-soft:#fbeceb; --green:#14946a; --green-soft:#e4f4ee; --amber:#b7791f;
        --serif:'Source Serif 4', Georgia, 'Times New Roman', serif;
        --sans:'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
        --mono:'IBM Plex Mono', ui-monospace, Consolas, monospace; }
html, body, .stApp { font-family: var(--sans); color: var(--ink); }
.stApp { background: #ffffff; }
.block-container, [data-testid="stMainBlockContainer"] { max-width: 1180px; padding-top: 4.6rem; padding-bottom: 4rem; }
.stApp h1, .stApp h2, .stApp h3 { font-family: var(--serif); letter-spacing: -0.012em; color: var(--ink); }
.stApp h2 { font-weight: 600; }
.stMarkdown p, .stMarkdown li { line-height: 1.62; }
[data-testid="stAppDeployButton"], .stDeployButton { display: none; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }

/* buttons, tabs, inputs */
.stButton > button, .stDownloadButton > button, [data-testid="stBaseButton-secondary"] {
  border-radius: 999px; border: 1px solid #cfd6de; font-weight: 500; padding: .38rem 1.1rem;
  transition: background .15s ease, border-color .15s ease, transform .15s ease; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: var(--blue); color: var(--blue); transform: translateY(-1px); }
.stTabs [data-baseweb="tab-list"] { gap: .3rem; border-bottom: 1px solid var(--line); }
.stTabs [data-baseweb="tab"] { font-weight: 500; padding: .55rem .95rem; border-radius: 8px 8px 0 0; }
.stTabs [data-baseweb="tab"]:hover { background: var(--paper); }
.stTabs [aria-selected="true"] { color: var(--blue); }
[data-testid="stExpander"] details, [data-testid="stExpander"] { border-radius: 12px; }
[data-testid="stDataFrame"], [data-testid="stTable"] { border-radius: 10px; overflow: hidden; }
[data-testid="stVegaLiteChart"] { border-radius: 12px; }
textarea, input { border-radius: 10px !important; }
[data-testid="stCaptionContainer"] { color: var(--muted); }

/* page header */
.x-hero { position: relative; padding: 1.5rem 0 1.4rem; margin-bottom: 1.2rem; border-bottom: 1px solid var(--line);
          animation: x-rise .55s ease both; }
.x-eyebrow { font: 600 .74rem/1 var(--mono); letter-spacing: .14em; text-transform: uppercase; color: var(--blue);
             display: flex; align-items: center; gap: .6rem; margin-bottom: .9rem; }
.x-eyebrow::before { content: ""; width: 26px; height: 2px; background: var(--blue); display: inline-block; }
.x-hero h1 { font: 600 clamp(2rem, 4.2vw, 3.15rem)/1.08 var(--serif); margin: 0 0 .9rem; padding: 0; max-width: 26ch; }
.x-lede { font-size: 1.14rem; line-height: 1.6; color: #3a434e; max-width: 62ch; margin: 0; }

/* section header */
.x-section { margin: 3.2rem 0 1rem; animation: x-rise .55s ease both; }
.x-kicker { font: 600 .72rem/1 var(--mono); letter-spacing: .14em; text-transform: uppercase; color: var(--muted); margin-bottom: .55rem; }
.x-kicker b { color: var(--blue); font-weight: 600; margin-right: .5rem; }
.x-section h2 { font: 600 clamp(1.5rem, 2.8vw, 2.05rem)/1.15 var(--serif); margin: 0 0 .6rem; padding: 0; }
.x-section p.x-intro { color: #3a434e; font-size: 1.04rem; line-height: 1.62; max-width: 68ch; margin: 0; }

/* text blocks */
.x-callout { border-left: 3px solid var(--blue); background: var(--blue-soft); padding: .85rem 1.1rem; border-radius: 0 10px 10px 0;
             line-height: 1.6; margin: .6rem 0 1rem; }
.x-callout.red { border-color: var(--red); background: var(--red-soft); }
.x-callout.green { border-color: var(--green); background: var(--green-soft); }
.x-big { font: 600 clamp(2.4rem, 5vw, 3.6rem)/1 var(--serif); color: var(--ink); letter-spacing: -0.02em; }
.x-big.red { color: var(--red); } .x-big.blue { color: var(--blue); } .x-big.green { color: var(--green); }
.x-under { font-size: .95rem; color: var(--muted); margin-top: .45rem; line-height: 1.45; }
.x-num { font-family: var(--mono); font-weight: 500; }
.x-brand { display: flex; align-items: center; gap: .55rem; flex-wrap: wrap; padding-bottom: .2rem; }
.x-word { font: 600 1.18rem/1 var(--serif); letter-spacing: -0.01em; color: var(--ink); }
.x-tag { font: 500 .78rem/1 var(--mono); letter-spacing: .06em; color: var(--muted); padding-left: .55rem;
         border-left: 1px solid var(--line); }
.x-foot { margin-top: 4rem; padding-top: 1.1rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .84rem; line-height: 1.6; }
.x-chip { display: inline-block; font: 500 .78rem/1.5 var(--mono); padding: .05rem .5rem; border-radius: 999px; border: 1px solid var(--line);
          background: #fff; color: var(--muted); }
.x-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.x-board-row { display: grid; grid-template-columns: minmax(120px, 230px) 1fr; gap: 14px; align-items: center; margin: 12px 0; }
@media (max-width: 640px) { .x-board-row { grid-template-columns: 1fr; gap: 6px; } }
@keyframes x-rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .x-hero, .x-section { animation: none; } }
"""


def html(markup):
    "Render HTML. Lines are joined so Markdown never mistakes indented HTML for a code block."
    st.markdown("".join(line.strip() for line in markup.splitlines()), unsafe_allow_html=True)


def svg(markup):
    "Render an inline SVG diagram through Markdown; on narrow screens it scrolls sideways instead of shrinking."
    body = " ".join(line.strip() for line in markup.splitlines())
    st.markdown(f'<div class="x-scroll">{body}</div>', unsafe_allow_html=True)


def embed(markup, height):
    "An interactive HTML piece in its own frame (st.iframe where it exists, st.components.v1.html before it)."
    if hasattr(st, "iframe"):
        st.iframe(markup, height=height)
    else:
        import streamlit.components.v1 as components
        components.html(markup, height=height)


def style():
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


def hero(eyebrow, title, lede=""):
    html(f'<div class="x-hero"><div class="x-eyebrow">{eyebrow}</div><h1>{title}</h1>'
         + (f'<p class="x-lede">{lede}</p>' if lede else "") + "</div>")


def section(number, kicker, title, intro=""):
    html(f'<div class="x-section"><div class="x-kicker"><b>{number}</b>{kicker}</div><h2>{title}</h2>'
         + (f'<p class="x-intro">{intro}</p>' if intro else "") + "</div>")


def callout(text, tone=""):
    html(f'<div class="x-callout {tone}">{text}</div>')


def big_number(value, under, tone=""):
    html(f'<div class="x-big {tone}">{value}</div><div class="x-under">{under}</div>')


def link(page, label, icon=None):
    "A link to another page of the app; plain text when the page runs on its own (as in the tests)."
    try:
        st.page_link(page, label=label, icon=icon)
    except Exception:                                   # no navigation around this page
        st.markdown(f"**{label}**")


NAME, TAGLINE = "NeedlePoint", "Find the needle on day one."
# The mark: a needle with its eye, and a red point where it lands.
MARK = ("<svg width='22' height='22' viewBox='0 0 24 24' aria-hidden='true'>"
        "<line x1='5' y1='19' x2='19' y2='5' stroke='#14181f' stroke-width='2' stroke-linecap='round'/>"
        "<ellipse cx='17.2' cy='6.8' rx='2.4' ry='1.1' transform='rotate(-45 17.2 6.8)' fill='#fff' "
        "stroke='#14181f' stroke-width='1.3'/><circle cx='4.6' cy='19.4' r='2.6' fill='#c8372d'/></svg>")


def brand():
    "The name and tagline, above every page."
    html(f'<div class="x-brand">{MARK}<span class="x-word">{NAME}</span><span class="x-tag">{TAGLINE}</span></div>')


def footer():
    html(f'<div class="x-foot"><b>{NAME}</b> · {TAGLINE} Data: NVD CVE API 2.0 (every CVE published 2016–2024, downloaded Nov 10, 2026), '
         "CISA's Known Exploited Vulnerabilities catalogue (version 2026.11.10) and FIRST's EPSS scores.</div>")


def strip_tags(text):
    return re.sub(r"<[^>]+>", "", text)
