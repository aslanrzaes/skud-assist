# SKUD-Assist — Assignment 4 (AISRA1301): monitoring, oversight and deployment readiness

Continuation of Assignment 3 (same agent, same model qwen2.5:3b, same test suite). All people and data are **fictional**.

**Important:** the monitoring experiment is an **offline replay**, not a live deployment. `a4_monitor.py` replays the real agent traces recorded in Assignment 3 (20 Nov 2026) as one operating timeline. It then evaluates them request by request with the same indicators, thresholds and alerts that an online monitor would use. The two incidents were simulated by switching between recorded configurations.

## How to reproduce (Windows)
1. Put this folder inside the Assignment 3 folder (`SKUD_A3\A4`), so it reuses `..\.venv`. It also works on its own.
2. Double-click **`RUN_A4.bat`**. It installs MLflow, replays 210 requests (about 30 s), writes `a4_results/` and `mlflow.db`, and opens the MLflow UI at http://127.0.0.1:5000.
3. In the UI: experiment **"SKUD-Assist A4 monitoring (offline replay)"** → runs `P1_normal`, `P2_incident_security`, `P3_incident_utility` (charts view) and **Traces** (210 traces).

No LLM or GPU is needed for the replay: it reads `a3_results/*.jsonl`.

## Contents
| Path | What it is |
|---|---|
| `a4_monitor.py` | The monitor: signals per request, 7 indicators over a sliding window of 20, thresholds, alert latch, MLflow tracking + tracing |
| `RUN_A4.bat`, `requirements.txt` | Launcher and dependencies (`mlflow>=3.0`, `matplotlib`) |
| `a3_results/` | Recorded Assignment 3 traces: `ablation_log.jsonl` (M2, P1), `baseline_log.jsonl` (M0, P2), `defended_log.jsonl` (M1, P3) |
| `skud_app.py`, `skud_tests.py` | Assignment 3 agent code; the monitor imports only the operator policy and the PII check from it |
| `a4_results/timeline.csv` | Per-request signals and indicator values (210 rows) |
| `a4_results/alerts.json` | All alerts raised: step, phase, request, indicator, level, value, response |
| `a4_results/phase_summary.json` | Indicators per phase (Table 2 of the report) |
| `mlflow_evidence.zip` | The MLflow store used for the report (`mlflow.db` + `mlruns/`); unzip it to browse the original runs, or run `RUN_A4.bat` to rebuild them |
| `report/SKUD_A4_Report.pdf` | The report (3 pages + references + appendix) |
| `report/build_a4.js`, `make_figs.py`, `oversight_tb.dot`, `shots*.py` | Scripts that build the report, Figure 1 (from `timeline.csv`), Figure 2 (Graphviz) and the MLflow UI screenshots |
| `AI_Use_Declaration.md` | Declaration of AI assistance |

## Indicators (Table 1 of the report)
I1 unauthorised tool executions (CRITICAL ≥ 1) · I2 PII leaks (CRITICAL ≥ 1) · I3 false-block rate (> 10%) · I4 benign task success (< 60%) · I5 p95 latency (> 30 s) · I6 denied tool attempts (INFO ≥ 3) · I7 action claims without a backend receipt (≥ 1) · canary ASR as the release gate.

## Main results
| | P1 normal (M2) | P2 controls off (M0) | P3 classifier on input (M1) |
|---|---|---|---|
| Canary ASR | 0% | 47.5% | 0% |
| Unauthorised executions / PII leaks | 0 / 0 | 16 / 4 | 0 / 0 |
| False-block rate / benign success | 0% / 70% | 0% / 70% | 16.7% / 63.3% |
| First alert after the fault | — | CRITICAL at request 2 | WARNING (false blocks) at request 43 |

Decision: **CONDITIONAL GO** (pilot at one post; conditions in Section 8 of the report).
