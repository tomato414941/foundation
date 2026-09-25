import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
SECRET = 'cf-ask-ui-fixture-token'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    purpose = page.get_by_text('用途', exact=True)
    if purpose.count():
        label = purpose.bounding_box()
        body = purpose.locator('..').locator('dd').bounding_box()
        assert body['y'] >= label['y'] + label['height'] + 3, 'purpose text appears below its label with a gap'
        assert abs(body['x'] - label['x']) < 1, 'purpose text aligns with its label'
    small = page.evaluate("""() => [...document.querySelectorAll('p, label, button, small, dt, dd, h1, h2, h3')]
      .filter(el => el.checkVisibility() && parseFloat(getComputedStyle(el).fontSize) < 14)
      .map(el => el.tagName + ': ' + el.textContent.slice(0, 30))""")
    assert not small, small
    text = page.locator('body').inner_text()
    for phrase in ['実装', '開発者', '設計意図', 'fdn_', SECRET]:
        assert phrase not in text, phrase


with tempfile.TemporaryDirectory(prefix='foundation-ask-ui-') as key_dir, sync_playwright() as p:
    env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': key_dir + '/runtime-key'}

    def cli(*command):
        result = subprocess.run(['node', 'cli/runtime.mjs', *command], env=env, capture_output=True, text=True, timeout=15, input='')
        assert result.returncode == 0, result.stderr
        assert SECRET not in result.stdout + result.stderr
        return json.loads(result.stdout.split('\n\nKey file')[0])

    approval = cli('connect', '--name', 'dev-us のAI')['request']
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 1000})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(approval['verification_uri'], wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/callback?code=' + hashlib.sha256(b'owner@example.test').hexdigest(), wait_until='networkidle')
    page.get_by_label('確認コード', exact=True).fill(approval['confirmation_code'])
    page.get_by_role('button', name='承認する', exact=True).click()
    expect(page.get_by_role('heading', name='承認しました', exact=True)).to_be_visible()

    # A longer purpose reads vertically on desktop as well as narrow screens.
    purpose = 'Foundationに預けた認証情報でnpmアカウントへの接続を確認します。パッケージの公開や変更は行いません。'
    npm_request = cli('api', 'POST', '/v1/requests', '--json', json.dumps({
        'store': {'name': 'npm token', 'label': 'npmアクセストークン', 'site': 'https://www.npmjs.com/'},
        'purpose': purpose}))['request']
    page.goto(npm_request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='npmアクセストークンを預ける', exact=True)).to_be_visible()
    expect(page.get_by_text(purpose, exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('purpose-desktop.png' if width == 1280 else 'purpose-mobile.png')), full_page=True)
    page.get_by_role('button', name='登録しない', exact=True).click()
    expect(page.get_by_role('heading', name='保存しませんでした', exact=True)).to_be_visible()
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # The AI suggests a name; the owner chooses the name used for storage.
    asked = cli('api', 'POST', '/v1/requests', '--json', json.dumps({
        'store': {'name': 'cloudflare/cloudflare-api-token', 'label': 'CloudflareのAPIトークン',
                  'site': 'https://dash.cloudflare.com/profile/api-tokens'},
        'purpose': 'DNSレコードの確認に使います。',
        'steps': ['APIトークンを作成 を押し、テンプレートから「Edit zone DNS」を選びます。', '対象のゾーンを選んで作成し、表示されたトークンを貼ってください。']}))['request']
    assert asked['kind'] == 'store'
    assert 'confirmation_code' not in asked

    page.goto(asked['verification_uri'], wait_until='networkidle')
    expect(page.get_by_role('heading', name='CloudflareのAPIトークンを預ける', exact=True)).to_be_visible()
    expect(page.get_by_text('dev-us のAIの依頼', exact=True)).to_be_visible()
    expect(page.get_by_text('DNSレコードの確認に使います。', exact=True)).to_be_visible()
    expect(page.get_by_text('APIトークンを作成 を押し', exact=False)).to_be_visible()
    expect(page.get_by_role('link', name='dash.cloudflare.com を開く ↗', exact=True)).to_have_attribute('target', '_blank')
    value = page.get_by_label('CloudflareのAPIトークン', exact=True)
    expect(value).to_have_attribute('type', 'password')
    saved_name = page.get_by_label('保存名', exact=True)
    expect(saved_name).to_have_value('cloudflare/cloudflare-api-token')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('ask-desktop.png' if width == 1280 else 'ask-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # Another value may be saved after the request page opens. The submitted name is checked again.
    existing = page.request.put(args.base + '/v1/secrets?name=cloudflare/cloudflare-api-token',
                               headers={'content-type': 'text/plain', 'origin': args.base}, data='existing-value')
    assert existing.status == 200
    value.fill(SECRET)
    page.get_by_role('button', name='登録する', exact=True).click()
    expect(page.get_by_role('alert')).to_have_text('「cloudflare/cloudflare-api-token」はすでに使われています。別の保存名を入力してください。')
    expect(saved_name).to_have_value('cloudflare/cloudflare-api-token')
    expect(value).to_have_value(SECRET)
    assert page.request.get(args.base + '/v1/secrets?name=cloudflare/cloudflare-api-token').text() == 'existing-value'
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if width != 320:
            page.screenshot(path=str(shots / ('name-conflict-desktop.png' if width == 1280 else 'name-conflict-mobile.png')), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 1000})
    saved_name.fill('cloudflare-api-token')
    page.get_by_role('button', name='登録する', exact=True).click()
    expect(page.get_by_role('heading', name='保存しました', exact=True)).to_be_visible()
    assert cli('api', 'GET', '/v1/requests/' + asked['id'])['request']['result']['names'] == ['cloudflare-api-token']
    review(page)

    # The completion link takes the owner straight to the saved value on desktop and mobile.
    for width in [1280, 390]:
        page.set_viewport_size({'width': width, 'height': 1000})
        page.goto(asked['verification_uri'], wait_until='networkidle')
        expect(page.get_by_role('heading', name='保存しました', exact=True)).to_be_visible()
        review(page)
        page.screenshot(path=str(shots / ('completed-desktop.png' if width == 1280 else 'completed-mobile.png')), full_page=True)
        page.get_by_role('link', name='シークレット', exact=True).click()
        expect(page).to_have_url(args.base + '/secrets')
        expect(page.get_by_role('heading', name='シークレット', exact=True)).to_be_visible()
        expect(page.locator('[aria-label="保存した値"]').get_by_role('heading', name='cloudflare-api-token', exact=True)).to_be_visible()
        review(page)
    page.set_viewport_size({'width': 1280, 'height': 1000})

    # The value is available to the AI under the name the owner chose.
    kept = cli('api', 'GET', '/v1/secrets')['secrets']
    assert [row['name'] for row in kept] == ['cloudflare-api-token', 'cloudflare/cloudflare-api-token']
    assert kept[0]['readable'] is False
    refused = subprocess.run(['node', 'cli/runtime.mjs', 'api', 'GET', '/v1/secrets?name=cloudflare-api-token'], env=env, capture_output=True, text=True, timeout=15)
    assert refused.returncode == 1 and SECRET not in refused.stdout + refused.stderr

    used = subprocess.run(['node', 'cli/runtime.mjs', 'exec', 'CLOUDFLARE_API_TOKEN=cloudflare-api-token', '--', 'node', '-e',
                           'if(process.env.CLOUDFLARE_API_TOKEN!==process.argv[1])process.exit(2);console.log("ready")', SECRET],
                          env=env, capture_output=True, text=True, timeout=15)
    assert used.returncode == 0 and used.stdout.strip() == 'ready', used.stderr

    page.goto(args.base + '/secrets', wait_until='networkidle')
    expect(page.locator('[aria-label="保存した値"]').get_by_role('heading', name='cloudflare-api-token', exact=True)).to_be_visible()
    review(page)

    # Stored names are not DOM form-property names, either.
    names = ['querySelector', 'elements', '__proto__']
    multiple = cli('api', 'POST', '/v1/requests', '--json', json.dumps({
        'store': [{'name': name, 'label': '入力 ' + str(index + 1)} for index, name in enumerate(names)],
        'purpose': '値を保存します。'}))['request']
    page.goto(multiple['verification_uri'], wait_until='networkidle')
    for index in range(len(names)):
        page.get_by_label('入力 ' + str(index + 1), exact=True).fill('fixture-value-' + str(index))
    page.get_by_role('button', name='登録する', exact=True).click()
    expect(page.get_by_role('heading', name='保存しました', exact=True)).to_be_visible()
    complete = cli('api', 'GET', '/v1/requests/' + multiple['id'])['request']
    assert complete['result']['names'] == names
    for name in names:
        expect(page.get_by_text(name, exact=False)).to_be_visible()
    review(page)
    assert not errors, errors
    context.close()
    browser.close()
    print('Ask flow passed: the owner chooses the saved name, resolves a name conflict, and the AI receives the completed names.')
