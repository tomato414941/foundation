import argparse
import base64
import hashlib
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
parser.add_argument('--engine', choices=['chromium', 'webkit'], default='chromium')
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = getattr(p, args.engine).launch(headless=True)
    device = p.devices['iPhone 13' if args.engine == 'webkit' else 'Pixel 7']
    context = browser.new_context(**{**device, 'locale': 'ja-JP'})
    if args.engine == 'webkit':
        context.add_init_script("Object.defineProperty(navigator, 'platform', {get: () => 'iPhone'});")
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))

    def catalog(route):
        query = parse_qs(urlparse(route.request.url).query)
        if urlparse(route.request.url).path.endswith('/tags'):
            tags = ['3.12-slim', '3.13-slim', '3.14-slim']
            route.fulfill(json={'tags': [{'name': name} for name in tags], 'next': None, **({'default_tag': 'latest'} if not query.get('query') else {})})
        else:
            route.fulfill(json={'images': [{'name': 'python', 'description': 'Python programming language.', 'official': True}, *[{'name': f'example/python-{n}', 'description': 'Python tools.', 'official': False} for n in range(12)]], 'next': None})

    page.route('**/v1/environment-images**', catalog)
    page.goto(args.base + '/environments', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('mobile-picker@example.test')
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    token = base64.urlsafe_b64encode(hashlib.sha256(b'mobile-picker@example.test').digest()).rstrip(b'=').decode()
    page.goto(args.base + '/signin/confirm?return_to=%2Fenvironments#token=' + token + '&email=mobile-picker%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    expect(page.get_by_role('heading', name='エンバイロメント', exact=True)).to_be_visible()

    # HeadlessブラウザではOSキーボードが出ないため、表示領域を縮めて候補を操作する。

    def capture(filename):
        # 共通部品の開閉アニメーションが終わった表示をレビューする。
        page.wait_for_timeout(400)
        page.screenshot(scale='css', path=str(shots / filename))

    def search(label):
        picker = page.get_by_role('dialog', name=label, exact=True)
        expect(picker).to_be_visible()
        return picker.get_by_role('searchbox', name=label, exact=True).or_(picker.get_by_role('combobox', name=label, exact=True))

    def reachable(field, option):
        expect(field).to_be_in_viewport()
        expect(option).to_be_in_viewport()
        for element in [field, option]:
            page.wait_for_function("""element => {
              const r = element.getBoundingClientRect();
              const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
              return element.contains(hit) && r.top >= -1 && r.bottom <= visualViewport.height + 1;
            }""", arg=element.element_handle())
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')

    for width, keyboard_height in [(390, 340), (320, 260)]:
        page.set_viewport_size({'width': width, 'height': 844})
        page.get_by_role('button', name='作成', exact=True).tap()
        dialog = page.get_by_role('dialog', name='エンバイロメントを作成', exact=True)
        name = f'スマホの作業 {width}'
        dialog.get_by_label('名前', exact=False).fill(name)
        capture(f'create-{width}.png')
        dialog.get_by_role('button', name='詳細設定', exact=True).tap()
        image_choice = dialog.get_by_role('button', name=re.compile('^イメージ '))
        version_choice = dialog.get_by_role('button', name=re.compile('^バージョン・種類 '))

        # 検索を取り消すと、入力済みの名前と選択値を保ってフォームへ戻る。
        image_choice.tap()
        field = search('イメージ')
        field.fill('cancelled search')
        page.touchscreen.tap(width / 2, 10)
        expect(dialog).to_be_visible()
        expect(image_choice).to_contain_text('標準イメージ')
        expect(dialog.get_by_label('名前', exact=False)).to_have_value(name)

        image_choice.tap()
        field = search('イメージ')
        field.fill('python')
        first = page.get_by_role('option', name='python', exact=True)
        expect(first).to_be_visible()
        page.set_viewport_size({'width': width, 'height': keyboard_height})
        reachable(field, first)
        capture(f'image-keyboard-{width}.png')
        # 一覧をスクロールして後ろの候補も選択する。
        listing = page.get_by_role('listbox')
        listing.evaluate('element => {element.scrollTop = element.scrollHeight}')
        last = page.get_by_role('option', name='example/python-11', exact=True)
        expect(last).to_be_visible()
        last.scroll_into_view_if_needed()
        reachable(field, last)
        last.tap()
        page.set_viewport_size({'width': width, 'height': 844})
        expect(image_choice).to_contain_text('example/python-11')
        expect(version_choice).to_contain_text('既定（latest）')
        page.wait_for_function('() => document.activeElement.tagName !== "INPUT"')

        version_choice.tap()
        field = search('バージョン・種類')
        field.fill('3.12')
        version = page.get_by_role('option', name='3.12-slim', exact=True)
        expect(version).to_be_visible()
        page.set_viewport_size({'width': width, 'height': keyboard_height})
        reachable(field, version)
        capture(f'version-keyboard-{width}.png')
        version.tap()
        page.set_viewport_size({'width': width, 'height': 844})
        expect(version_choice).to_contain_text('3.12-slim')
        page.wait_for_function('() => document.activeElement.tagName !== "INPUT"')

        # 検索せずにバージョンを選び直し、その設定で環境を作成する。
        version_choice.tap()
        expect(search('バージョン・種類')).to_have_value('')
        expect(page.get_by_role('option', name='既定（latest）', exact=True)).to_be_visible()
        choice = page.get_by_role('option', name='3.13-slim', exact=True)
        reachable(search('バージョン・種類'), choice)
        choice.tap()
        expect(version_choice).to_contain_text('3.13-slim')
        capture(f'selection-form-{width}.png')
        dialog.get_by_role('button', name='作成', exact=True).tap()
        expect(page.locator('.access-row').filter(has_text=name)).to_be_visible()
        resources = context.request.get(args.base + '/v1/principals/me/resources?kind=environment').json()['resources']
        created = next(item for item in resources if item['name'] == name)
        assert created['image'] == 'example/python-11:3.13-slim'

    assert not errors, errors
    context.close()
    browser.close()
    print('スマートフォンで検索を取り消し、表示領域が狭いときもイメージとバージョンをタップして環境を作成する。')
