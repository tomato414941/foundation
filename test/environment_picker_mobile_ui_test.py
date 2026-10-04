import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
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
        assert bounds['height'] >= 48, bounds
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')

    for width, height in [(390, 340), (320, 260)]:
        page.set_viewport_size({'width': width, 'height': 844})
        page.get_by_role('button', name='作成', exact=True).tap()
        dialog = page.get_by_role('dialog')
        dialog.get_by_text('詳細設定', exact=True).tap()
        image = dialog.get_by_role('combobox', name='イメージ', exact=True)
        image.tap()
        image.fill('python')
        expect(dialog.get_by_role('option', name='python', exact=True)).to_be_visible()
        keyboard('#environment-image', height)
        visible_candidates('#environment-image')
        page.screenshot(path=str(shots / f'image-keyboard-{width}.png'))
        # キーボードが出たまま、候補をタップして既定バージョンで選択を終える。
        dialog.get_by_role('option', name='python', exact=True).tap()
        expect(image).to_have_value('python')
        version = dialog.get_by_role('combobox', name='バージョン・種類', exact=True)
        expect(version).to_have_value('既定（latest）')
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        keyboard()

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
        expect(version).to_have_value('3.12-slim')
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        keyboard()

        # 矢印から候補を開くと、キーボードを出さずにバージョンを選択する。
        dialog.get_by_role('button', name='バージョン・種類', exact=True).tap()
        expect(dialog.get_by_role('option', name='3.13-slim', exact=True)).to_be_visible()
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        dialog.get_by_role('option', name='3.13-slim', exact=True).tap()
        expect(version).to_have_value('3.13-slim')

        # 検索キーで入力を終え、候補一覧をタップする。
        image.tap()
        image.fill('py')
        keyboard('#environment-image', height)
        image.press('Enter')
        assert page.evaluate('document.activeElement.tagName !== "INPUT"')
        keyboard()
        dialog.get_by_role('option', name='python', exact=True).tap()
        expect(version).to_have_value('既定（latest）')
        expect(dialog.get_by_role('button', name='作成', exact=True)).to_be_enabled()
        dialog.get_by_role('button', name='閉じる', exact=True).tap()

    assert not errors, errors
    context.close()
    browser.close()
    print('スマートフォンでキーボード表示中もイメージとバージョンをタップして選択する。候補の選択と検索の確定でキーボードを閉じる。')
