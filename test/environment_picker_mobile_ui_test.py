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
    context = browser.new_context(locale='ja-JP', viewport={'width': 390, 'height': 844}, is_mobile=True, has_touch=True)
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

    # OSキーボードはheadlessでは出ないため、表示領域だけを縮め、隠れる場所をタップできなくする。
    # レイアウトの高さはそのままにし、入力欄に合わせた表示領域の移動も再現する。
    page.evaluate('''() => {
      const viewport = window.visualViewport, nativeHeight = viewport.height;
      let height = nativeHeight, top = 0;
      Object.defineProperties(viewport, { height: { get: () => height }, offsetTop: { get: () => top } });
      window.setKeyboard = (field, visibleHeight, pan = 0) => {
        const previousHeight = height, previousTop = top;
        document.querySelectorAll('[data-keyboard-mask]').forEach(mask => mask.remove());
        height = visibleHeight || nativeHeight;
        top = field ? Math.max(0, document.querySelector(field).getBoundingClientRect().bottom + 12 - height) + pan : 0;
        if (field) for (const [edge, size] of [['top', top], ['bottom', Math.max(0, innerHeight - top - height)]]) {
          const mask = document.createElement('div');
          mask.dataset.keyboardMask = '';
          Object.assign(mask.style, { position: 'fixed', left: '0', right: '0', [edge]: '0', height: size + 'px', zIndex: '1000', background: '#353538' });
          document.querySelector('dialog').append(mask);
        }
        if (field) {
          const address = document.createElement('div');
          address.dataset.keyboardMask = '';
          Object.assign(address.style, { position: 'fixed', top: (top + height - 72) + 'px', left: '16%', right: '16%', height: '44px', zIndex: '1001', borderRadius: '24px', background: '#353538' });
          document.querySelector('dialog').append(address);
        }
        if (height !== previousHeight) viewport.dispatchEvent(new Event('resize'));
        if (top !== previousTop) viewport.dispatchEvent(new Event('scroll'));
      };
    }''')

    def keyboard(field=None, height=None, pan=0):
        page.evaluate('([field, height, pan]) => window.setKeyboard(field, height, pan)', [field, height, pan])

    def visible_candidates(field):
        popup = page.locator(field + '-picker .environment-picker-popup')
        expect(popup).to_be_visible()
        bounds = popup.bounding_box()
        viewport = page.evaluate('({top: visualViewport.offsetTop, bottom: visualViewport.offsetTop + visualViewport.height})')
        assert bounds['y'] >= viewport['top'], (bounds, viewport)
        assert bounds['y'] + bounds['height'] <= viewport['bottom'], (bounds, viewport)
        assert bounds['y'] + bounds['height'] <= viewport['bottom'] - 72, '候補一覧をブラウザの操作部分より上に表示する'
        assert bounds['height'] >= 48, bounds
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        # Safariのアドレスバーが下部に重なっても、検索欄を直接タップする。
        assert page.locator(field).evaluate('''input => {
          const box = input.getBoundingClientRect();
          return document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2) === input;
        }'''), '検索欄をブラウザの操作部分に重ねずに表示する'

    for width, height in [(390, 340), (320, 260)]:
        page.set_viewport_size({'width': width, 'height': 844})
        page.get_by_role('button', name='作成', exact=True).tap()
        dialog = page.get_by_role('dialog')
        name = f'スマホの作業 {width}'
        dialog.get_by_label('名前', exact=False).fill(name)
        dialog.get_by_text('詳細設定', exact=True).tap()
        image_choice = dialog.get_by_role('button', name=re.compile('^イメージ '))
        version_choice = dialog.get_by_role('button', name=re.compile('^バージョン・種類 '))
        # 選択画面を開いてもキーボードは出さず、キャンセルすると元の設定とフォームに戻る。
        image_choice.tap()
        expect(page.get_by_role('dialog', name='イメージ', exact=True)).to_be_visible()
        expect(dialog.get_by_role('heading', name='イメージ', exact=True)).to_be_in_viewport()
        expect(dialog.get_by_role('option', name='標準イメージ', exact=True)).to_have_attribute('aria-selected', 'true')
        page.screenshot(path=str(shots / f'image-initial-{width}.png'))
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        image = dialog.get_by_role('combobox', name='イメージ', exact=True)
        image.fill('cancelled search')
        # 検索欄から画面の見出しへタップしても、候補を選ぶ画面で操作を続ける。
        dialog.get_by_role('heading', name='イメージ', exact=True).tap()
        expect(page.get_by_role('dialog', name='イメージ', exact=True)).to_be_visible()
        dialog.get_by_role('button', name='キャンセル', exact=True).tap()
        expect(dialog.get_by_role('heading', name='エンバイロメントを作成', exact=True)).to_be_visible()
        expect(dialog.get_by_label('名前', exact=False)).to_have_value(name)
        expect(image_choice).to_contain_text('標準イメージ')
        image_choice.tap()
        image.tap()
        image.fill('python')
        expect(dialog.get_by_role('option', name='python', exact=True)).to_be_visible()
        keyboard('#environment-image', height)
        visible_candidates('#environment-image')
        page.screenshot(path=str(shots / f'image-keyboard-{width}.png'))
        # 一覧を末尾までスクロールしても検索欄を使え、候補をタップしてフォームに戻る。
        last = dialog.get_by_role('option', name='example/python-11', exact=True)
        last.scroll_into_view_if_needed()
        visible_candidates('#environment-image')
        last.tap()
        expect(image_choice).to_contain_text('example/python-11')
        expect(dialog.get_by_role('heading', name='エンバイロメントを作成', exact=True)).to_be_visible()
        version = dialog.get_by_role('combobox', name='バージョン・種類', exact=True)
        expect(version_choice).to_contain_text('既定（latest）')
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        keyboard()

        version_choice.tap()
        expect(page.get_by_role('dialog', name='バージョン・種類', exact=True)).to_be_visible()
        expect(dialog.get_by_role('heading', name='バージョン・種類', exact=True)).to_be_in_viewport()
        expect(dialog.get_by_role('option', name='既定（latest）', exact=True)).to_have_attribute('aria-selected', 'true')
        page.screenshot(path=str(shots / f'version-initial-{width}.png'))
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        version.tap()
        version.fill('3.12')
        expect(dialog.get_by_role('option', name='3.12-slim', exact=True)).to_be_visible()
        keyboard('#environment-version', height)
        visible_candidates('#environment-version')
        keyboard('#environment-version', height, 16)
        visible_candidates('#environment-version')
        keyboard('#environment-version', height - 40)
        visible_candidates('#environment-version')
        page.screenshot(path=str(shots / f'version-keyboard-{width}.png'))
        dialog.get_by_role('option', name='3.12-slim', exact=True).tap()
        expect(version_choice).to_contain_text('3.12-slim')
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        keyboard()

        # バージョン一覧は、キーボードを出さずにそのまま選択する。
        version_choice.tap()
        expect(dialog.get_by_role('option', name='3.13-slim', exact=True)).to_be_visible()
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        dialog.get_by_role('option', name='3.13-slim', exact=True).tap()
        expect(version_choice).to_contain_text('3.13-slim')

        # 検索キーで入力を終え、候補一覧をタップする。
        image_choice.tap()
        image.tap()
        image.fill('py')
        keyboard('#environment-image', height)
        image.press('Enter')
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        keyboard()
        dialog.get_by_role('option', name='python', exact=True).tap()
        expect(image_choice).to_contain_text('python')
        expect(version_choice).to_contain_text('既定（latest）')
        expect(dialog.get_by_role('button', name='作成', exact=True)).to_be_enabled()
        page.screenshot(path=str(shots / f'selection-form-{width}.png'))
        dialog.get_by_role('button', name='作成', exact=True).tap()
        expect(page.locator('.access-row').filter(has_text=name)).to_be_visible()
        resources = context.request.get(args.base + '/v1/principals/me/resources?kind=environment').json()['resources']
        created = next(item for item in resources if item['name'] == name)
        assert created['image'] == 'python:latest'

    assert not errors, errors
    context.close()
    browser.close()
    print('スマートフォンでキーボード表示中もイメージとバージョンをタップして選択する。候補の選択と検索の確定でキーボードを閉じる。')
