"""Figure 1 for the A3 report: ASR by attack category and benign-task outcomes, M0 vs M1 (vs M2 if present)."""
import json, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

R = sys.argv[1]  # results folder
out = sys.argv[2]
cfg = [("M0 baseline", "baseline_summary.json", "#2a78d6"),
       ("M1 full defence", "defended_summary.json", "#eb6834"),
       ("M2 no guard on operator input", "ablation_summary.json", "#1baf7a")]
cfg = [(n, json.load(open(os.path.join(R, f), encoding="utf-8")), c) for n, f, c in cfg if os.path.exists(os.path.join(R, f))]

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": "#b5b4ae",
                     "axes.labelcolor": "#3d3d3a", "xtick.color": "#3d3d3a", "ytick.color": "#3d3d3a"})
fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.45), gridspec_kw={"width_ratios": [1.35, 1]})

cats = [("A_privilege", "A\nprivilege"), ("B_pii", "B\nPII leak"), ("C_indirect", "C\nindirect"),
        ("D_excessive", "D\nexcessive"), (None, "All 40")]
k = len(cfg); w = 0.8 / k; x = np.arange(len(cats))
ax = axes[0]
for i, (name, s, col) in enumerate(cfg):
    vals = [100 * (s["asr_overall"] if c is None else s["asr_by_category"][c]) for c, _ in cats]
    bars = ax.bar(x + (i - (k - 1) / 2) * w, vals, w - 0.03, color=col, label=name, zorder=3)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}", ha="center", va="bottom", fontsize=7, color="#3d3d3a")
ax.set_xticks(x, [l for _, l in cats]); ax.set_ylim(0, 100); ax.set_ylabel("Attack success rate, %")
ax.set_title("(a) Attack success rate (lower is better)", fontsize=9, loc="left", color="#1f1f1d")

mets = [("benign_completed_automatically", "Auto-\ncompleted"), ("benign_success", "Incl. human\napproval"),
        ("benign_false_block_rate", "False\nblocks")]
x2 = np.arange(len(mets)); ax = axes[1]
for i, (name, s, col) in enumerate(cfg):
    vals = [100 * s[m] for m, _ in mets]
    bars = ax.bar(x2 + (i - (k - 1) / 2) * w, vals, w - 0.03, color=col, zorder=3)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}", ha="center", va="bottom", fontsize=7, color="#3d3d3a")
ax.set_xticks(x2, [l for _, l in mets]); ax.set_ylim(0, 100); ax.set_ylabel("% of 30 benign tasks")
ax.set_title("(b) Legitimate operator tasks", fontsize=9, loc="left", color="#1f1f1d")
for ax in axes:
    ax.grid(axis="y", color="#e6e5e0", linewidth=0.6, zorder=0)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
fig.legend(loc="lower center", ncol=k, frameon=False, bbox_to_anchor=(0.5, -0.02), fontsize=8)
fig.tight_layout(rect=(0, 0.08, 1, 1))
fig.savefig(out, dpi=220)
print("saved", out, [c[0] for c in cfg])
