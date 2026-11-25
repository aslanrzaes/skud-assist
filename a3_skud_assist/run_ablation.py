"""Ablation run (Assignment 3): defended pipeline M2 = M1 without the prompt-injection classifier on the
operator's own request. The classifier still screens untrusted data (log notes, visitor cards); RBAC,
human approval and PII minimisation are unchanged. Writes results/ablation_*."""
import os, sys, json, time
os.environ.setdefault("SKUD_BACKEND", "ollama")
os.environ.setdefault("SKUD_MODEL", "qwen2.5:3b")
os.environ["SKUD_GUARD_USER"] = "0"
HERE = os.path.dirname(os.path.abspath(__file__)); os.chdir(HERE); sys.path.insert(0, HERE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import skud_tests as T
t = time.time()
s = T.run_suite(defended=True, log_path="results/ablation_log.jsonl")
s["wall_time_s"] = time.time() - t
s["config"] = "M2: M1 without classifier on operator request (classifier on untrusted data only)"
json.dump(s, open("results/ablation_summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps(s, ensure_ascii=False, indent=1))
print("\nABLATION DONE. Tell Claude 'done'.")
