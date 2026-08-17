import streamlit as st
import pandas as pd

st.set_page_config(page_title="SOC Alert Triage", layout="wide")

@st.cache_data
def load_queue():
    df = pd.read_csv("priority_queue.csv")
    df["is_fp"] = df["is_fp"].astype(bool)
    return df
    
@st.cache_data
def load_scorecard():
    return pd.read_csv("results.csv")

queue = load_queue()
scorecard = load_scorecard()

st.title("SOC Alert Triage")
st.markdown("Prioritized alert queue and detection performance on CIC-IDS2017.")

st.header("Detection scorecard")
st.dataframe(scorecard, use_container_width=True)

st.header("Ranking performance")
st.image("figures/coverage_curve.png",
         caption="Coverage tracks the random-ordering diagonal; noise-skipped stays above 0.95"
         "through the first 60% of the queue.")

st.sidebar.header("Filters")

rules = sorted(queue["rule"].unique())
selected_rules = st.sidebar.multiselect("Rule", rules, default=rules)

hide_fp = st.sidebar.checkbox("Hide false positives", value=False)

top_n = st.sidebar.slider("Show top N% of queue", 10, 100, 100, step=10)

filtered = queue[queue["rule"].isin(selected_rules)]

if hide_fp:
    filtered = filtered[~filtered["is_fp"]]
    
cutoff = int(len(filtered) * top_n / 100)
filtered = filtered.head(cutoff)

total_shown = len(filtered)
tp_shown = int((~filtered["is_fp"]).sum())
fp_shown = int(filtered["is_fp"].sum())

fp_rate = fp_shown / total_shown if total_shown else 0

col1, col2, col3 = st.columns(3)
col1.metric("Alerts shown", f"{total_shown:,}")
col2.metric("True positives", f"{tp_shown:,}")
col3.metric("False positives", f"{fp_shown:,}", f"{fp_rate:.1%} of shown")

st.header("Prioritized queue")
st.markdown(f"Showing **{len(filtered):,}** alerts")
st.dataframe(filtered, use_container_width=True)