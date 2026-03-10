import asyncio
import os
from pyppeteer import launch

async def capture(url: str):
    # Launch headless Chrome without sandbox for environments like Render
    browser = await launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])
    page = await browser.newPage()
    await page.setViewport({'width': 1280, 'height': 800})
    await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 30000})
    screenshot = await page.screenshot({'fullPage': True})
    await browser.close()
    # Save screenshot to file
    output_path = os.path.join(os.path.dirname(__file__), 'example.png')
    with open(output_path, 'wb') as f:
        f.write(screenshot)
    print(f'Screenshot saved to {output_path}')

if __name__ == '__main__':
    # Run the capture for a known URL
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(capture('https://example.com'))
    loop.close()
