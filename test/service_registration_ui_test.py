import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots')
args = parser.parse_args()
shots = Path(args.screenshots) if args.screenshots else None
if shots:
    shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/services', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    fragment = urlencode({'email': 'owner@example.test', 'token_hash': hashlib.sha256(b'owner@example.test').hexdigest()})
    page.goto(args.base + '/login/confirm?return_to=%2Fservices#' + fragment, wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_url(args.base + '/services')
    page.wait_for_load_state('networkidle')
    dialog = page.get_by_role('dialog')

    def api(path, method='GET', data=None, raw=None):
        headers = {'Origin': args.base}
        if raw is not None:
            headers['content-type'] = 'text/plain'
        response = context.request.fetch(args.base + path, method=method, data=raw if raw is not None else data, headers=headers)
        assert response.ok, response.text()
        return response.text() if raw is not None else response.json()

    def overview():
        return api('/v1/overview')

    def service(name):
        return next(item for item in overview()['services'] if item['name'] == name)

    def review(label):
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), label
        text = page.locator('body').inner_text()
        for phrase in ['fixture-private-', '実装', '設計意図', 'auth_schemes']:
            assert phrase not in text, (label, phrase)
        small = page.evaluate("""() => [...document.querySelectorAll('label, button, input, p, h3')]
          .filter(el => el.checkVisibility() && parseFloat(getComputedStyle(el).fontSize) < 14)
          .map(el => el.textContent)""")
        assert not small, small
        if shots:
            page.screenshot(path=str(shots / (label + '.png')), full_page=True)


    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog.get_by_label('サービスを探す', exact=True).fill('社内ツール')
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    expect(dialog.get_by_label('サービス名', exact=True)).to_have_value('社内ツール')
    review('name-only')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    row = page.get_by_role('article', name='社内ツール', exact=True)
    expect(row.get_by_text('未接続', exact=True)).to_be_visible()
    page.reload(wait_until='networkidle')
    expect(row.get_by_text('未接続', exact=True)).to_be_visible()
    assert service('社内ツール')['definition']['auth_schemes'] == {}

    row.get_by_role('button', name='接続を追加', exact=True).click()
    dialog.get_by_role('button', name='ログインして許可する').click()
    expect(dialog.get_by_role('heading', name='社内ツールのOAuth設定', exact=True)).to_be_visible()
    page.keyboard.press('Escape')
    expect(dialog).not_to_be_visible()
    assert service('社内ツール')['definition']['auth_schemes'] == {}

    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog.get_by_label('サービスを探す', exact=True).fill('社内')
    choice = dialog.get_by_role('button', name='社内ツール', exact=True)
    expect(choice).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 900})
        review('search-' + str(width))
    choice.focus()
    page.keyboard.press('Enter')
    dialog.get_by_role('button', name='ログインして許可する').click()
    dialog.get_by_label('認可エンドポイントのURL', exact=True).fill('https://service.example/authorize')
    dialog.get_by_label('トークンエンドポイントのURL', exact=True).fill('https://service.example/token')
    review('oauth-mobile')
    dialog.get_by_role('button', name='次へ', exact=True).click()
    expect(dialog.get_by_role('heading', name='OAuthアプリを追加', exact=True)).to_be_visible()
    page.keyboard.press('Escape')
    configured = service('社内ツール')['definition']
    assert configured['auth_schemes']['oauth']['authorize'] == 'https://service.example/authorize'

    page.set_viewport_size({'width': 1280, 'height': 900})
    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog.get_by_label('サービスを探す', exact=True).fill('社内ツール')
    dialog.get_by_role('button', name='一覧にないサービスを追加', exact=True).click()
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog.get_by_role('alert')).to_have_text('同じ名前のサービスがあります。一覧から選んでください。')
    expect(dialog.get_by_label('サービス名', exact=True)).to_have_value('社内ツール')
    assert service('社内ツール')['definition'] == configured
    dialog.get_by_label('サービス名', exact=True).fill('追加のアプリ')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_role('article', name='追加のアプリ', exact=True)).to_be_visible()

    page.goto(args.base + '/secrets', wait_until='networkidle')
    page.get_by_role('button', name='追加', exact=True).click()
    dialog.get_by_label('名前', exact=True).fill('任意の名前/a')
    dialog.get_by_label('値', exact=True).fill('fixture-private-token')
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(page.get_by_role('article', name='任意の名前/a', exact=True)).to_be_visible()
    kept = next(item for item in overview()['secrets'] if item['name'] == '任意の名前/a')
    assert api('/v1/injections', 'POST', {'names': [{'id': kept['id'], 'as': 'MY_TOKEN'}]})['injection']['environment'] == {'MY_TOKEN': 'fixture-private-token'}
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 900})
        review('secrets-' + str(width))

    page.goto(args.base + '/services', wait_until='networkidle')
    deleting = service('追加のアプリ')
    page.get_by_role('article', name='追加のアプリ', exact=True).get_by_role('button', name='削除', exact=True).click()
    expect(dialog.get_by_role('heading', name='追加のアプリ を削除しますか？', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='削除する', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert context.request.get(args.base + '/v1/resources/' + deleting['id']).status == 404
    review('services-mobile')
    assert not errors, errors
    browser.close()
    print('サービスの登録・検索・OAuth設定・競合・削除と、固定トークンの保存・利用を確認しました。')
