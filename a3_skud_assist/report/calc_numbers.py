"""Derive every number used in the report from the raw result files (no hand-typed values)."""
import json, os, sys, math, statistics as st
R = sys.argv[1]

def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0, c - h), min(1, c + h))

def load(mode):
    rows = [json.loads(l) for l in open(os.path.join(R, f"{mode}_log.jsonl"), encoding="utf-8")]
    summ = json.load(open(os.path.join(R, f"{mode}_summary.json"), encoding="utf-8"))
    att = [r for r in rows if "category" in r]; ben = [r for r in rows if "kind" in r]
    k = sum(r["success"] for r in att)
    out = dict(summary=summ, n_att=len(att), n_ben=len(ben), succ=k, asr_ci=wilson(k, len(att)),
               succ_ids=[r["id"] for r in att if r["success"]],
               ben_lat_mean=st.mean(r["latency_s"] for r in ben), ben_lat_median=st.median(r["latency_s"] for r in ben),
               att_lat_mean=st.mean(r["latency_s"] for r in att),
               false_blocks=[r["id"] for r in ben if r["false_block"]],
               failed_benign=[r["id"] for r in ben if not r["success"]],
               routed=[r["id"] for r in ben if r["routed_to_human"]])
    # which layer acted on each attack
    lay = {"guard_user": [], "guard_data": [], "rbac_deny": [], "human_approval": [], "pii_min": []}
    for r in att:
        f = r.get("filtered") or []; b = r.get("blocked") or []
        if any(x["where"] == "user" for x in f): lay["guard_user"].append(r["id"])
        if any(x["where"] != "user" for x in f): lay["guard_data"].append(r["id"])
        if any(str(x.get("why", "")).startswith("denied") for x in b): lay["rbac_deny"].append(r["id"])
        if any(str(x.get("why", "")).startswith("pending_human") for x in b): lay["human_approval"].append(r["id"])
    out["layers"] = lay
    out["guard_user_flag_attacks"] = len(lay["guard_user"])
    out["guard_user_flag_benign"] = sum(any(x["where"] == "user" for x in (r.get("filtered") or [])) for r in ben)
    out["c_data_flagged"] = [r["id"] for r in att if r["category"].startswith("C") and any(x["where"] != "user" for x in (r.get("filtered") or []))]
    return out

N = {m: load(m) for m in ["baseline", "defended", "ablation"] if os.path.exists(os.path.join(R, f"{m}_log.jsonl")) and os.path.exists(os.path.join(R, f"{m}_summary.json"))}
# PII minimisation: B attacks that leaked in baseline but not in defended and were not stopped by the guard
if "defended" in N:
    b0 = set(i for i in N["baseline"]["succ_ids"] if i.startswith("B"))
    N["defended"]["layers"]["pii_min"] = sorted(b0 - set(N["defended"]["layers"]["guard_user"]))
if "ablation" in N:
    N["ablation"]["layers"]["pii_min"] = sorted(b0 - set(N["ablation"]["layers"]["guard_user"]) - set(N["ablation"]["succ_ids"]))
N["garak"] = json.load(open(os.path.join(R, "garak_summary.json"), encoding="utf-8"))
N["env"] = json.load(open(os.path.join(R, "summary.json"), encoding="utf-8"))["environment"]
json.dump(N, open("numbers.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=list)
for m in ["baseline", "defended", "ablation"]:
    if m in N:
        d = N[m]; s = d["summary"]
        print(m, "ASR %d/%d=%.1f%% CI [%.1f, %.1f]" % (d["succ"], d["n_att"], 100 * s["asr_overall"], 100 * d["asr_ci"][0], 100 * d["asr_ci"][1]),
              "| benign succ %.1f auto %.1f FB %.1f routed %s" % (100 * s["benign_success"], 100 * s["benign_completed_automatically"], 100 * s["benign_false_block_rate"], d["routed"]),
              "| lat ben mean %.2f med %.2f att %.2f p95 %.2f" % (d["ben_lat_mean"], d["ben_lat_median"], d["att_lat_mean"], s["latency_p95_s"]))
        print("  layers", {k: v for k, v in d["layers"].items()}, "guard user flags att/ben", d["guard_user_flag_attacks"], d["guard_user_flag_benign"], "C data", d["c_data_flagged"])
        print("  FB", d["false_blocks"], "failed", d["failed_benign"])
