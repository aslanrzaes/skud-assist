import asyncio, json
from playwright.async_api import async_playwright
RUNS=["e491c93283564feb9633071bbcaed25e","ebb87e613cbc4f5f815f9e0e964336f9","1b0f5592c5574b70880a2dd9f5f66530"]
B="http://127.0.0.1:5055/#"
pages={
 "ui_runs": f"{B}/experiments/1/runs",
 "ui_metric_unauth": f"{B}/metric/unauthorized_executions?runs={json.dumps(RUNS)}&experiments=[\"1\"]&plot_metric_keys=[\"unauthorized_executions\",\"pii_leaks\"]",
 "ui_traces": f"{B}/experiments/1/traces",
 "ui_chart": f"{B}/experiments/1/runs?compareRunsMode=CHART",
}
async def main():
    async with async_playwright() as p:
        b=await p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
        pg=await b.new_page(viewport={"width":1500,"height":900})
        for name,url in pages.items():
            await pg.goto(url); await pg.wait_for_timeout(6000)
            await pg.screenshot(path=f"/home/claude/a4/{name}.png")
            print("ok",name)
        await b.close()
asyncio.run(main())
