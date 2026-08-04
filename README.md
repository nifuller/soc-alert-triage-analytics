# soc-alert-triage-analytics
# SOC Alert Triage Analytics

> Turning 2.8M raw network flows into a prioritized, tuned alert queue — the way a SOC analyst actually works.

<!-- TODO: add badges once set up, e.g. Python version, license -->
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Overview

Most intrusion-detection projects stop at "train a classifier, report accuracy." This one starts where a Security Operations Center's day actually begins: **too many alerts, not enough time.** Using the labeled CIC-IDS2017 network-flow dataset, I generate alerts from explainable detection rules, then analyze and tune that alert queue — measuring false-positive rates, ranking rules by signal-to-noise, and prioritizing what an analyst should look at first.

The deliverable is not a model. It's the **triage analytics layer** on top of detections, plus a dashboard that makes the queue actionable.

## Key results

<!-- TODO: fill these in once your pipeline runs -->
- Reduced simulated alert volume by **__%** while retaining **__%** attack coverage
- Ranked **__** detection rules by precision; identified the **__** noisiest
- Triage dashboard sorts the queue by a priority score derived from severity + confidence

## Dataset

**CIC-IDS2017** — Canadian Institute for Cybersecurity ([source](https://www.unb.ca/cic/datasets/ids-2017.html))

This project uses the **`GeneratedLabelledFlows`** files (not the ML-only CSVs), because the triage analysis needs `Source IP` and `Timestamp` to aggregate alerts per source over time.

- **Tuesday** — Brute force (FTP-Patator :21, SSH-Patator :22)
- **Wednesday** — DoS (Hulk, GoldenEye, slowloris, Slowhttptest)
- **Monday** — benign only; used as the "normal" baseline for thresholds

> Data files are not committed to this repo (see `.gitignore`). Download them from the source above.

## Approach

1. **Clean** — normalize column names (raw files have leading spaces), handle `inf`/`NaN`, drop the duplicate `Fwd Header Length.1` column.
2. **Baseline** — profile Monday's benign traffic; compute per-port percentiles for the features the rules use.
3. **Detect** — apply explainable rules to generate alerts (see below).
4. **Score** — compare alerts to ground-truth labels for per-rule TP / FP / FN, precision, recall.
5. **Triage** — analyze the alert queue: volume over time, FP rate per rule, noisiest sources, priority ranking.
6. **Dashboard** — surface it all in Splunk / Streamlit.

## Detection rules

| Rule | Attack | Key signal |
|------|--------|-----------|
| Brute force | FTP/SSH Patator | Attempt **rate per source** to an auth port (not any single flow) |
| DoS — flood | Hulk, GoldenEye | High packet rate on port 80 |
| DoS — low & slow | slowloris, Slowhttptest | Long-lived flow + near-zero throughput |

All thresholds are derived from the benign baseline (percentile-based), not hardcoded. See `src/rules.py`.

## Dashboard

<!-- TODO: add a screenshot -->
![Triage dashboard](figures/dashboard.png)

<!-- TODO: one or two sentences describing the panels -->

## Repo structure

```
├── data/                 # raw flows (gitignored)
├── notebooks/
│   └── 01_baseline_eda.ipynb
├── src/
│   ├── clean.py          # column cleanup + inf/NaN handling
│   ├── baseline.py       # per-port percentile thresholds from Monday
│   ├── rules.py          # brute-force + DoS detection rules
│   ├── score.py          # TP/FP/FN vs. labels
│   └── triage.py         # alert-queue analytics
├── dashboard/            # Splunk exports / Streamlit app
├── figures/
├── requirements.txt
└── README.md
```

## How to run

```bash
# 1. install
pip install -r requirements.txt

# 2. drop the GeneratedLabelledFlows CSVs into data/

# 3. build baseline thresholds from Monday
python src/baseline.py

# 4. run rules -> alerts -> scoring
python src/rules.py
python src/score.py

# 5. triage analytics + dashboard
python src/triage.py
# streamlit run dashboard/app.py   # if using Streamlit
```

## Skills demonstrated

- **Detection engineering** — authoring and evaluating explainable rules
- **Alert triage & tuning** — FP-rate analysis, signal-to-noise ranking, prioritization
- **Data analytics** — EDA, time-series aggregation, class-imbalance handling (pandas)
- **SIEM / dashboarding** — Splunk SPL / Streamlit
- **Security-domain fluency** — TP/FP reasoning, attack taxonomies, MITRE ATT&CK

## MITRE ATT&CK mapping

<!-- Refine to sub-techniques as you go -->
| Attack | Technique |
|--------|-----------|
| FTP/SSH Patator | T1110 — Brute Force |
| DoS (Hulk, GoldenEye, slowloris, Slowhttptest) | T1499 — Endpoint Denial of Service |

## Future work

- Extend to Thursday (web attacks: SQLi, XSS) and Friday (DDoS, port scan, botnet)
- Group related alerts into incidents ("campaign view")
- Add mock SLA metrics (mean time to acknowledge / triage)

## Disclaimer

For research and educational purposes only.

## License

MIT — see [LICENSE](LICENSE).
