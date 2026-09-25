import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
SECRET = 'ghp_kept-ui-fixture-value'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    small = page.evaluate("""() => [...document.querySelectorAll('p, label, button, small, dt, dd, h2, h3')]
      .filter(el => el.checkVisibility() && parseFloat(getComputedStyle(el).fontSize) < 14)
      .map(el => el.tagName + ': ' + el.textContent.slice(0, 30))""")
    assert not small, small
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'fdn_', 'renewal']:
        assert phrase not in text, phrase


with tempfile.TemporaryDirectory(prefix='foundation-storage-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command, stdin=None):
        result = subprocess.run(['node', 'cli/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15, input=stdin or '')
        assert result.returncode == 0, result.stderr
        assert SECRET not in result.stdout + result.stderr
        return json.loads(result.stdout.split('\n\nKey file')[0])

    # Everything but connect and exec is plain HTTP, which is how an agent uses it.
    def api(method, path, body=None, headers=None):
        request = urllib.request.Request(args.base + path, method=method, data=body,
                                         headers={'authorization': 'Bearer ' + key, **(headers or {})})
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read() or b'{}')

    approval = cli('connect', '--name', 'dev-us のAI')['request']
    key = open(key_dir + '/runtime-key').read().strip()
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1000}, permissions=['clipboard-read', 'clipboard-write'])
    page = context.new_page()
    errors = []
    value_reads = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('request', lambda request: value_reads.append(request.url) if request.method == 'GET' and '/v1/secrets?' in request.url else None)
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()

    # Nothing kept yet, and the page says so.
    page.goto(args.base + '/secrets', wait_until='networkidle')
    expect(page.get_by_role('heading', name='シークレット', exact=True)).to_be_visible()
    expect(page.get_by_text('保存した値はありません。', exact=False)).to_be_visible()
    review(page)

    # The key keeps two things, with no request and no approval: one handed to a command, one only read back.
    api('PUT', '/v1/secrets?name=github/gh-token', SECRET.encode(), {'content-type': 'text/plain'})
    api('PUT', '/v1/secrets?name=release/2026-09-23', json.dumps({'step': 'レビュー待ち'}).encode(), {'content-type': 'application/json'})
    page.reload(wait_until='networkidle')

    github = page.get_by_role('article', name='github/gh-token', exact=True)
    release = page.get_by_role('article', name='release/2026-09-23', exact=True)
    expect(github.get_by_role('heading', name='github/gh-token', exact=True)).to_be_visible()
    expect(github.get_by_text(f'{len(SECRET)} バイト', exact=True)).to_be_visible()
    expect(release.get_by_role('heading', name='release/2026-09-23', exact=True)).to_be_visible()
    expect(release.get_by_role('button', name='値を編集', exact=True)).to_be_visible()
    assert SECRET not in page.locator('body').inner_text(), 'what is kept is never on the page itself'

    review(page)
    page.screenshot(path=str(shots / 'kept-desktop.png'), full_page=True)

    # The owner can fetch anything they keep, including what the key itself may not read back.
    opened = page.request.get(args.base + '/v1/secrets?name=github%2Fgh-token')
    assert opened.status == 200 and opened.text() == SECRET
    dialog = page.get_by_role('dialog')

    for width in [390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width == 390:
            page.screenshot(path=str(shots / 'kept-mobile.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # The name is edited in its own row, with the current name selected and adjacent save/cancel controls.
    # Its controls sit right after it, in the same order as the value's: copy, then edit.
    title_box = github.get_by_role('heading', name='github/gh-token', exact=True).bounding_box()
    copy_box = github.get_by_role('button', name='名前をコピー', exact=True).bounding_box()
    pencil_box = github.get_by_role('button', name='名前を編集', exact=True).bounding_box()
    assert 0 <= copy_box['x'] - (title_box['x'] + title_box['width']) <= 8
    assert 0 <= pencil_box['x'] - (copy_box['x'] + copy_box['width']) <= 8
    github.get_by_role('button', name='名前を編集', exact=True).click()
    editor = github.get_by_role('form', name='名前の変更', exact=True)
    name_input = editor.get_by_label('名前', exact=True)
    expect(name_input).to_be_focused()
    expect(name_input).to_have_value('github/gh-token')
    assert name_input.evaluate('(input) => input.selectionStart === 0 && input.selectionEnd === input.value.length')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        expect(editor.get_by_role('button', name='保存', exact=True)).to_be_visible()
        expect(editor.get_by_role('button', name='キャンセル', exact=True)).to_be_visible()
        expect(github.get_by_text(f'{len(SECRET)} バイト', exact=True)).to_be_visible()
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('rename-desktop.png' if width == 1280 else 'rename-mobile.png')), full_page=True)
    name_input.fill('cancelled name')
    editor.get_by_role('button', name='キャンセル', exact=True).click()
    expect(github.get_by_role('heading', name='github/gh-token', exact=True)).to_be_visible()
    expect(github.get_by_role('button', name='名前を編集', exact=True)).to_be_focused()

    github.get_by_role('button', name='名前を編集', exact=True).click()
    name_input.fill('another draft')
    name_input.press('Escape')
    expect(github.get_by_role('heading', name='github/gh-token', exact=True)).to_be_visible()
    assert [row['name'] for row in api('GET', '/v1/secrets')['secrets']] == ['github/gh-token', 'release/2026-09-23']

    # An occupied name stays editable; saving a corrected name preserves the stored bytes.
    github.get_by_role('button', name='名前を編集', exact=True).click()
    name_input.fill('release/2026-09-23')
    editor.get_by_role('button', name='保存', exact=True).click()
    expect(editor.get_by_role('alert')).to_have_text('その名前はすでに使われています。')
    expect(name_input).to_have_value('release/2026-09-23')
    expect(editor.get_by_role('button', name='保存', exact=True)).to_be_enabled()
    name_input.fill('github token')
    editor.get_by_role('button', name='保存', exact=True).click()
    renamed = page.get_by_role('article', name='github token', exact=True)
    expect(renamed.get_by_role('heading', name='github token', exact=True)).to_be_visible()
    expect(renamed.get_by_role('button', name='名前を編集', exact=True)).to_be_focused()
    kept = page.request.get(args.base + '/v1/secrets?name=github%20token')
    assert kept.status == 200 and kept.text() == SECRET
    renamed.get_by_role('button', name='名前を編集', exact=True).click()
    restored = renamed.get_by_label('名前', exact=True)
    restored.fill('github/gh-token')
    restored.press('Enter')
    expect(github.get_by_role('heading', name='github/gh-token', exact=True)).to_be_visible()
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Each row starts masked with its own controls; metadata follows the value.
    assert value_reads == [], 'the list and renames use metadata only'
    expect(github.locator('.kept-document')).to_have_text('••••••••')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        for label in ['値を表示', 'コピー', '値を編集']:
            expect(github.get_by_role('button', name=label, exact=True)).to_be_visible()
        value_box = github.locator('.secret-value-panel').bounding_box()
        metadata_box = github.locator('.secret-meta').bounding_box()
        assert metadata_box['y'] >= value_box['y'] + value_box['height']
        mask_box = github.locator('.kept-document').bounding_box()
        eye_box = github.get_by_role('button', name='値を表示', exact=True).bounding_box()
        assert 0 <= eye_box['x'] - (mask_box['x'] + mask_box['width']) <= 12
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('value-desktop.png' if width == 1280 else 'value-mobile.png')), full_page=True)
    github.get_by_role('button', name='値を表示', exact=True).click()
    expect(github.locator('.kept-document')).to_have_text(SECRET)
    assert len(value_reads) == 1
    expect(release.locator('.kept-document')).to_have_text('••••••••')
    github.get_by_role('button', name='値を隠す', exact=True).click()
    expect(github.locator('.kept-document')).to_have_text('••••••••')
    github.get_by_role('button', name='コピー', exact=True).click()
    expect(page.get_by_role('status')).to_have_text('コピーしました。')
    assert page.evaluate('navigator.clipboard.readText()') == SECRET
    # The name copies too, for `foundation exec ENV=name`.
    github.get_by_role('button', name='名前をコピー', exact=True).click()
    assert page.evaluate('navigator.clipboard.readText()') == github.get_attribute('aria-label')
    expect(github.locator('.kept-document')).to_have_text('••••••••')

    # Editing and cancelling preserve the value; saving replaces only its bytes.
    github.get_by_role('button', name='値を編集', exact=True).click()
    value_input = github.get_by_role('textbox', name='値', exact=True)
    expect(value_input).to_have_value(SECRET)
    value_input.fill('cancel this draft')
    github.get_by_role('button', name='キャンセル', exact=True).click()
    assert page.request.get(args.base + '/v1/secrets?name=github%2Fgh-token').text() == SECRET
    github.get_by_role('button', name='値を編集', exact=True).click()
    value_input.fill('escape this draft')
    value_input.press('Escape')
    expect(github.locator('.kept-document')).to_have_text('••••••••')
    github.get_by_role('button', name='値を編集', exact=True).click()
    updated = '  {\n  "token": "new-value",\n  "note": "<img src=x onerror=window.valueXss=1>"\n}\n'
    value_input.fill(updated)
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('edit-value-desktop.png' if width == 1280 else 'edit-value-mobile.png')), full_page=True)
    # A failed save keeps the draft and lets the owner retry.
    def unavailable(route):
        if route.request.method == 'PUT':
            route.fulfill(status=503, content_type='application/json', body=json.dumps({'error': {'message': '保存できませんでした。'}}))
        else:
            route.continue_()
    page.route('**/v1/secrets?*', unavailable)
    github.get_by_role('button', name='保存', exact=True).click()
    expect(github.get_by_role('alert')).to_have_text('保存できませんでした。')
    expect(value_input).to_have_value(updated)
    expect(github.get_by_role('button', name='保存', exact=True)).to_be_enabled()
    page.unroute('**/v1/secrets?*', unavailable)
    github.get_by_role('button', name='保存', exact=True).click()
    expect(github.locator('.kept-document')).to_have_text('••••••••')
    assert page.request.get(args.base + '/v1/secrets?name=github%2Fgh-token').text() == updated
    github.get_by_role('button', name='値を表示', exact=True).click()
    expect(github.locator('.kept-document')).to_contain_text('new-value')
    assert github.locator('.kept-document').text_content() == updated
    assert page.evaluate('window.valueXss === undefined')
    github.get_by_role('button', name='値を隠す', exact=True).click()

    # Another writer wins over a stale editor, which keeps the owner's draft for recovery.
    github.get_by_role('button', name='値を編集', exact=True).click()
    value_input.fill('my pending value')
    api('PUT', '/v1/secrets?name=github/gh-token', b'newer value')
    github.get_by_role('button', name='保存', exact=True).click()
    expect(github.get_by_role('alert')).to_have_text('ほかの操作で変更されています。開き直して確認してください。')
    expect(value_input).to_have_value('my pending value')
    assert page.request.get(args.base + '/v1/secrets?name=github%2Fgh-token').text() == 'newer value'
    github.get_by_role('button', name='キャンセル', exact=True).click()

    # Readable text retains its access setting and unchanged CRLF/BOM bytes survive an edit/save.
    unchanged = '\ufefffirst\r\nsecond\r\n'
    api('PUT', '/v1/secrets?name=release/2026-09-23', unchanged.encode('utf-8'))
    release.get_by_role('button', name='値を編集', exact=True).click()
    release.get_by_role('button', name='保存', exact=True).click()
    expect(release.get_by_role('button', name='値を編集', exact=True)).to_be_visible()
    assert page.request.get(args.base + '/v1/secrets?name=release%2F2026-09-23').body() == unchanged.encode('utf-8')
    release.get_by_role('button', name='値を編集', exact=True).click()
    release.get_by_role('textbox', name='値', exact=True).fill('updated readable value')
    release.get_by_role('button', name='保存', exact=True).click()
    expect(release.get_by_role('button', name='値を編集', exact=True)).to_be_visible()
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Changing one name leaves a different row's draft in place.
    github.get_by_role('button', name='値を編集', exact=True).click()
    value_input.fill('keep my draft')
    expect(github.get_by_role('button', name='名前を編集', exact=True)).to_be_disabled()
    release.get_by_role('button', name='名前を編集', exact=True).click()
    release.get_by_role('textbox', name='名前', exact=True).fill('release note')
    release.get_by_role('button', name='保存', exact=True).click()
    release = page.get_by_role('article', name='release note', exact=True)
    expect(release.get_by_role('heading', name='release note', exact=True)).to_be_visible()
    expect(value_input).to_have_value('keep my draft')
    release.get_by_role('button', name='値を編集', exact=True).click()
    release.get_by_role('textbox', name='値', exact=True).fill('second row value')
    release.get_by_role('button', name='保存', exact=True).click()
    expect(release.get_by_role('button', name='値を編集', exact=True)).to_be_visible()
    expect(value_input).to_have_value('keep my draft')
    github.get_by_role('button', name='キャンセル', exact=True).click()

    # Removing one takes it away from the key too.
    release.get_by_role('button', name='削除', exact=True).click()
    expect(dialog.get_by_role('heading', name='release note を削除しますか？', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert [row['name'] for row in api('GET', '/v1/secrets')['secrets']] == ['github/gh-token']

    github.get_by_role('button', name='削除', exact=True).click()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_text('保存した値はありません。', exact=False)).to_be_visible()
    assert api('GET', '/v1/secrets')['secrets'] == []

    # Opaque names survive the owner form, HTML rendering, rename and direct preview.
    literal = ' a/aa/aaa, <img src=x onerror="window.foundationNameXss=1"> '
    page.get_by_role('button', name='追加', exact=True).click()
    dialog.get_by_label('名前', exact=True).fill(literal)
    dialog.get_by_label('値', exact=True).fill(SECRET)
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert api('GET', '/v1/secrets')['secrets'][0]['name'] == literal
    title = page.locator('[aria-label="保存した値"] .agent-name h3')
    assert title.text_content() == literal
    assert page.evaluate('window.foundationNameXss === undefined')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
    page.get_by_role('button', name='名前を編集', exact=True).click()
    literal_editor = page.get_by_role('form', name='名前の変更', exact=True)
    expect(literal_editor.get_by_label('名前', exact=True)).to_have_value(literal)
    literal_editor.get_by_label('名前', exact=True).fill('..')
    literal_editor.get_by_role('button', name='保存', exact=True).click()
    expect(title).to_have_text('..')
    literal_row = page.get_by_role('article', name='..', exact=True)
    literal_row.get_by_role('button', name='値を表示', exact=True).click()
    expect(literal_row.locator('.kept-document')).to_have_text(SECRET)
    page.get_by_role('button', name='削除', exact=True).click()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert api('GET', '/v1/secrets')['secrets'] == []

    # Binary values stay files: download exact bytes, then replace them with a selected file.
    binary = b'\x00\xff\x01fixture'
    api('PUT', '/v1/secrets?name=binary', binary)
    page.reload(wait_until='networkidle')
    binary_row = page.get_by_role('article', name='binary', exact=True)
    binary_row.get_by_role('button', name='値を表示', exact=True).click()
    expect(binary_row.get_by_text('ファイル', exact=True)).to_be_visible()
    with page.expect_download() as download_info:
        binary_row.get_by_role('link', name='ダウンロード', exact=True).click()
    assert Path(download_info.value.path()).read_bytes() == binary
    binary_row.get_by_role('button', name='値を編集', exact=True).click()
    replaced = b'\x00\xfe\x01replacement'
    binary_row.get_by_label('ファイル', exact=True).set_input_files({'name': 'credential.bin', 'mimeType': 'application/octet-stream', 'buffer': replaced})
    binary_row.get_by_role('button', name='保存', exact=True).click()
    expect(binary_row.get_by_text('ファイル', exact=True)).to_be_visible()
    assert page.request.get(args.base + '/v1/secrets?name=binary').body() == replaced
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Storage screen passed: inline name/value controls, footer metadata, on-demand reads, copy, editing, retries, concurrent changes, independent drafts, exact bytes, file replacement, and removal.')
