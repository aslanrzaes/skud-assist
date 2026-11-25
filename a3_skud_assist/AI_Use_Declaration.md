# AI Use Declaration — Assignment 3, AISRA1301

Student: Aslan Zhunzhumenov, Master's programme AI+X, QAIRU
Date: November 2026

## Tools used
- **Claude (Anthropic), Opus model, via the Claude app**: a general-purpose AI assistant.
- **qwen2.5:3b (Alibaba Qwen, via Ollama)**: the model *under test*, not an authoring aid.
- **protectai/deberta-v3-base-prompt-injection-v2** and **NVIDIA garak 0.17.1**: components and tools of the experiment, cited in the report.

## Substantive AI assistance (Claude)
| Activity | What the assistant did | What I did |
|---|---|---|
| Problem framing | Proposed options for an individual project in my domain; suggested AgentDojo as the reference paper | Chose the access-control (SKUD) scenario from my professional field and approved the paper |
| Code | Wrote `skud_app.py`, `skud_tests.py`, `run_all.py`, `run_ablation.py` and the launchers; fixed dependency and memory errors | Installed and ran everything on my own computer, checked console output, reported errors |
| Test design | Drafted the 40 attack and 30 benign cases and the scoring rules | Reviewed the cases for realism in a security-post context |
| Analysis | Wrote scripts that compute every reported number, CI and figure directly from the raw logs; inspected traces | Checked the results against the logs and the garak HTML reports |
| Report | Drafted the English text, tables and README | Reviewed, edited and approved the final text; I am responsible for all claims |

## Integrity statement
- All results were produced by actually running the code on my computer on 20 November 2026. No number in the report was typed by hand: each one is computed from `results/` by `report/calc_numbers.py`.
- A first run with a different model (qwen3.5:4b) was invalid and was discarded. This is disclosed in the README.
- The baseline M0 was re-established for this assignment. It is not the Midterm baseline (see Section 2 of the report).
- All personal data in the system is fictional.
