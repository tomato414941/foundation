import argparse
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors, requests = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('console', lambda message: errors.append(message.text) if message.type == 'error' else None)
    page.on('request', lambda request: requests.append(request))
    page.goto(args.base + '/docs', wait_until='networkidle')
    expect(page.get_by_role('heading', name='Foundation API', exact=False)).to_be_visible()
    # Swagger expands an operation and displays the contract, including its request schema.
    operation = page.locator('#operations-resources-putResource')
    operation.locator('.opblock-summary-control').click()
    expect(operation.locator('.opblock-description-wrapper').first).to_contain_text('raw bytes')
    expect(operation.get_by_text('Request body', exact=True)).to_be_visible()
    assert 'secret' in operation.inner_text()
    page.screenshot(path=str(shots / 'docs-desktop.png'), full_page=False)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.goto(args.base + '/docs', wait_until='networkidle')
    expect(page.get_by_role('link', name='OpenAPI JSON', exact=True)).to_be_visible()
    page.screenshot(path=str(shots / 'docs-mobile.png'), full_page=False)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    # Loading the reference only fetches this server's document and assets.
    assert all(request.method == 'GET' for request in requests)
    assert all(urlsplit(request.url).netloc == urlsplit(args.base).netloc for request in requests)
    # An explicit user action can also try the documented, non-mutating health operation.
    health = page.locator('#operations-Server-health')
    health.locator('.opblock-summary-control').click()
    health.get_by_role('button', name='Try it out', exact=True).click()
    health.get_by_role('button', name='Execute', exact=True).click()
    expect(health.locator('.live-responses-table')).to_contain_text('200')
    expect(health.locator('.live-responses-table')).to_contain_text('"status": "ok"')
    assert not errors, errors
    reading = browser.new_context(locale='ja-JP', java_script_enabled=False)
    plain = reading.new_page()
    plain.goto(args.base + '/docs', wait_until='networkidle')
    plain.get_by_role('link', name='OpenAPI JSON', exact=True).click()
    expect(plain.locator('body')).to_contain_text('/v1/injections')
    reading.close()
    context.close()
    browser.close()
    print('Docs UI passed: rendered operations, JSON access without JavaScript, desktop/mobile, same-origin loading and an explicit API call.')
