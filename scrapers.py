# you can find docs for playwright here https://playwright.dev/python/docs/intro
from playwright.sync_api import sync_playwright

def get_gas_prices():
    with sync_playwright() as page:
        # launch in headless mode to avoid launching a browser
        browser = page.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.goto("https://gasprices.aaa.com/?state=FL")
        # scraper should wait for Current Avg. to be loaded before scraping since it's dynamic JS
        page.wait_for_selector("td:has-text('Current Avg.')")
        row = page.locator("tr:has(td:text('Current Avg.'))")
        tds = row.locator("td")
        # grab the linner text of the first (gas) and last (diesel) prices row
        gas_price_str = tds.nth(1).inner_text()
        diesel_price_str = tds.nth(4).inner_text()
        browser.close()
        # trim the strings + convert them to floats
        gas_price = float(gas_price_str.replace('$', '').strip())
        diesel_price = float(diesel_price_str.replace('$', '').strip())
        return gas_price, diesel_price
