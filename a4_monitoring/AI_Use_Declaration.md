# AI Use Declaration — Assignment 4, AISRA1301

Student: Aslan Zhunzhumenov, Master's programme AI+X, QAIRU
Date: November 2026

## Tools used
- **Claude (Anthropic), via the Claude app**: a general-purpose AI assistant.
- **MLflow 3.18**: the monitoring tool under study (tracking and tracing), cited in the report.
- **qwen2.5:3b (via Ollama)**: the model of the monitored system. Its outputs come from the Assignment 3 run; no new model calls were made.

## Substantive AI assistance (Claude)
| Activity | What the assistant did | What I did |
|---|---|---|
| Design | Proposed MLflow as the tool, the offline-replay design with two simulated faulty releases, the indicator set and the thresholds | Chose the scenario and the responsible roles (shift supervisor, ML owner) from my security-post context and approved the design |
| Code | Wrote `a4_monitor.py`, `RUN_A4.bat`, the figure, diagram and screenshot scripts | Ran the replay on my computer and checked the alerts against the logs |
| Analysis | Computed every number from the recorded logs; drafted the risk table and the deployment conditions | Checked the numbers in `a4_results/` and decided on CONDITIONAL GO |
| Report | Drafted the English text, tables, diagrams and README | Reviewed, edited and approved the final text; I am responsible for all claims |

## Integrity statement
- The monitoring experiment is an **offline replay** of real traces recorded on 20 November 2026 (Assignment 3). The faults were simulated by switching between recorded configurations, and this is stated in the report. No new measurements were invented.
- Every number in the report comes from `a4_results/` (produced by `a4_monitor.py`) or from the published Assignment 3 results.
- The MLflow trace timings come from an offline reconstruction; the recorded latencies are stored as span attributes.
- All personal data in the system is fictional.
