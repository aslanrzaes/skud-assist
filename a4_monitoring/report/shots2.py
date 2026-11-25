import asyncio
from playwright.async_api import async_playwright
B="http://127.0.0.1:5055/#"
async def main():
    async with async_playwright() as p:
        b=await p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
        pg=await b.new_page(viewport={"width":1500,"height":900})
        async def clean():
            for sel in ["text=Got it"]:
                try: await pg.click(sel, timeout=1500)
                except Exception: pass
            try:
                btns=pg.locator("button[aria-label*='lose']")
                n=await btns.count()
                for i in range(n):
                    try: await btns.nth(i).click(timeout=800)
                    except Exception: pass
            except Exception: pass
            await pg.wait_for_timeout(800)
        await pg.goto(f"{B}/experiments/1/runs?compareRunsMode=CHART"); await pg.wait_for_timeout(5000); await clean()
        await pg.screenshot(path="ui_chart.png")
        await pg.goto(f"{B}/experiments/1/traces"); await pg.wait_for_timeout(5000); await clean()
        await pg.screenshot(path="ui_traces.png")
        # open a trace with tool calls
        await pg.get_by_text("Выдай курьеру Arzan Su", exact=False).first.click()
        await pg.wait_for_timeout(4000)
        await pg.screenshot(path="ui_trace_detail.png")
        await b.close()
asyncio.run(main())
