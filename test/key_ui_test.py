import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from ui_flows import virtual_authenticator

# The passkey is asked for where it is needed, and not again: adding and replacing a value need none; showing a
# value uses the key the sign-in opened, which the browser keeps between loads of the page and forgets at sign-out.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
base = args.base.replace('127.0.0.1', 'localhost')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    cdp = virtual_authenticator(context, page)
    page.goto(base, wait_until='networkidle')
    page.get_by_role('button', name='パスキーで始める', exact=True).click()
    page.get_by_role('dialog').get_by_role('button', name='続ける', exact=True).click()
    expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()

    def add(name, value):
        page.get_by_role('button', name='追加', exact=True).click()
        dialog = page.get_by_role('dialog')
        dialog.get_by_label('名前', exact=True).fill(name)
        dialog.get_by_label('値', exact=True).fill(value)
        dialog.get_by_role('button', name='追加', exact=True).click()
        expect(dialog).not_to_be_visible()

    page.goto(base + '/secrets', wait_until='networkidle')
    # From here on no passkey answers: anything that asked for one would wait and fail.
    cdp.send('WebAuthn.disable')
    expect(page.get_by_text('鍵', exact=False)).to_have_count(0)
    add('first', 'first-value')
    row = page.get_by_role('article', name='first', exact=True)
    row.get_by_role('button', name='値を表示', exact=True).click()
    expect(row.locator('.kept-document')).to_have_text('first-value')
    page.screenshot(path=str(shots / 'shown-after-reload.png'), full_page=True)

    # Loaded anew, once more: the key is still there.
    page.reload(wait_until='networkidle')
    row.get_by_role('button', name='値を表示', exact=True).click()
    expect(row.locator('.kept-document')).to_have_text('first-value')

    # A new value is written over the old without reading it; the old one is loaded only when asked for.
    page.reload(wait_until='networkidle')
    row.get_by_role('button', name='値を編集', exact=True).click()
    field = row.get_by_role('textbox', name='値', exact=True)
    expect(field).to_have_value('')
    field.fill('second-value')
    row.get_by_role('button', name='保存', exact=True).click()
    expect(page.get_by_text('保存しました', exact=False).first).to_be_visible()
    row.get_by_role('button', name='値を編集', exact=True).click()
    row.get_by_role('button', name='今の値を読み込む', exact=True).click()
    expect(field).to_have_value('second-value')
    row.get_by_role('button', name='キャンセル', exact=True).click()

    # Signing out forgets the key.
    kept = "() => new Promise(resolve => { const o = indexedDB.open('foundation', 1); o.onupgradeneeded = () => o.result.createObjectStore('keys'); o.onsuccess = () => { const r = o.result.transaction('keys').objectStore('keys').get('own'); r.onsuccess = () => resolve(Boolean(r.result)); }; })"
    assert page.evaluate(kept) is True
    page.goto(base + '/account', wait_until='networkidle')
    page.get_by_role('button', name='サインアウト', exact=True).click()
    expect(page.get_by_role('button', name='パスキーでサインイン', exact=True)).to_be_visible()
    assert page.evaluate(kept) is False
    assert not errors, errors
    browser.close()
