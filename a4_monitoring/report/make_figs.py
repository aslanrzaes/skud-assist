import csv, json, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os; R=os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","a4_results")+os.sep
rows=list(csv.DictReader(open(R+"timeline.csv")))
alerts=json.load(open(R+"alerts.json"))
x=[int(r["step"]) for r in rows]
f=lambda k:[float(r["ind_"+k]) for r in rows]
plt.rcParams.update({"font.family":"DejaVu Sans","font.size":8})
fig,ax=plt.subplots(3,1,figsize=(7.4,4.6),sharex=True,gridspec_kw={"hspace":0.18})
phases=[(0.5,70.5,"P1 normal (M2)","#eef4ee"),(70.5,140.5,"P2 incident 1: controls off","#fbecec"),(140.5,210.5,"P3 incident 2: classifier on input","#fdf5e6")]
for a in ax:
    for s,e,l,c in phases: a.axvspan(s,e,color=c,lw=0)
    a.grid(axis="y",color="#dddddd",lw=0.5); a.spines[["top","right"]].set_visible(False)
for s,e,l,c in phases: ax[0].text((s+e)/2,1.02,l,ha="center",va="bottom",fontsize=7.5,color="#333333",transform=ax[0].get_xaxis_transform())
ax[0].step(x,f("unauthorized_executions"),where="post",color="#c0392b",lw=1.4,label="unauthorised tool executions (window of 20)")
ax[0].step(x,f("pii_leaks"),where="post",color="#7d3c98",lw=1.4,label="PII leaks (window of 20)")
ax[0].step(x,f("denied_tool_attempts"),where="post",color="#7f8c8d",lw=0.9,ls="--",label="denied tool attempts (INFO)")
ax[0].axhline(1,color="#c0392b",lw=0.8,ls=":"); ax[0].text(212,1,"≥1",fontsize=6.5,va="center",color="#c0392b")
ax[0].set_ylim(0,15); ax[0].set_ylabel("events"); ax[0].legend(loc="upper left",fontsize=6.3,frameon=False,ncol=3,bbox_to_anchor=(0,1.0))
ax[1].plot(x,[100*v for v in f("false_block_rate")],color="#d35400",lw=1.4,label="false-block rate, last 20 benign (%)")
ax[1].plot(x,[100*v for v in f("benign_success_rate")],color="#2471a3",lw=1.4,label="benign task success, last 20 benign (%)")
ax[1].axhline(10,color="#d35400",lw=0.8,ls=":"); ax[1].text(212,10,">10%",fontsize=6.5,va="center",color="#d35400")
ax[1].axhline(60,color="#2471a3",lw=0.8,ls=":"); ax[1].text(212,60,"<60%",fontsize=6.5,va="center",color="#2471a3")
ax[1].set_ylim(0,100); ax[1].set_ylabel("%"); ax[1].legend(loc="lower left",fontsize=6.3,frameon=False,bbox_to_anchor=(0,0.2),ncol=2)
ax[2].plot(x,f("latency_p95_s"),color="#117864",lw=1.4,label="p95 latency, last 20 requests (s)")
ax[2].axhline(30,color="#117864",lw=0.8,ls=":"); ax[2].text(212,30,">30 s",fontsize=6.5,va="center",color="#117864")
ax[2].set_ylim(0,40); ax[2].set_ylabel("seconds"); ax[2].legend(loc="lower left",fontsize=6.5,frameon=False)
ax[2].set_xlabel("request number in the replayed operating timeline (70 requests per phase)")
lvl={"CRITICAL":("#c0392b","v"),"WARNING":("#d35400","^")}
panel={"unauthorized_executions":0,"pii_leaks":0,"false_block_rate":1,"benign_success_rate":1,"latency_p95_s":2,"unconfirmed_action_claims":0}
for a in alerts:
    if a["level"] in lvl and a["indicator"]!="unconfirmed_action_claims":
        c,m=lvl[a["level"]]; i=panel[a["indicator"]]
        y={0:11.3,1:92,2:37}[i]
        ax[i].plot(a["step"],y,marker=m,color=c,ms=6); ax[i].annotate(f"{a['level'].lower()} @{a['step']}",(a["step"],y),xytext=(3,-9),textcoords="offset points",fontsize=6,color=c)
ax[2].set_xlim(0,215)
fig.savefig("fig_dashboard.png",dpi=220,bbox_inches="tight")
