import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from ui_flows import virtual_authenticator, make_key, unlock, hand_to_foundation, revoke_access

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
# Passkeys need a hostname.
args.base = args.base.replace('127.0.0.1', 'localhost')
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
runtime = Path(__file__).resolve().parents[1] / 'cli' / 'runtime.mjs'

with tempfile.TemporaryDirectory(prefix='foundation-start-cli-') as temporary, sync_playwright() as p:
    cli_env = {key: value for key, value in os.environ.items() if not key.startswith('FOUNDATION_')}
    cli_env.update({'XDG_CONFIG_HOME': str(Path(temporary) / 'config'),
                    'FOUNDATION_RUNTIME_KEY_FILE': str(Path(temporary) / 'agent.key')})

    def cli(*arguments):
        return subprocess.run(['node', str(runtime), *arguments], env=cli_env,
                              capture_output=True, text=True, timeout=30)

    browser = p.chromium.launch(headless=True)
    # The public entry links to the specification even without JavaScript.
    reading = browser.new_context(locale='ja-JP', java_script_enabled=False)
    entry = reading.new_page()
    entry.goto(args.base, wait_until='networkidle')
    expect(entry.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()
    entry.screenshot(path=str(shots / 'entry-no-js.png'), full_page=True)
    entry.get_by_role('link', name='API仕様', exact=True).click()
    entry.get_by_role('link', name='OpenAPI JSON', exact=True).click()
    expect(entry.locator('body')).to_contain_text('"openapi":"3.1.1"')
    expect(entry.locator('body')).to_contain_text('/v1/principals')
    reading.close()

    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 800})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    virtual_authenticator(context, page)
    page.goto(args.base, wait_until='networkidle')
    expect(page.get_by_role('heading', name='サインイン', exact=True)).to_be_visible()
    expect(page.get_by_role('link', name='API仕様', exact=True)).to_have_attribute('href', '/docs')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 800})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        expect(page.get_by_role('link', name='API仕様', exact=True)).to_be_visible()
        page.screenshot(path=str(shots / f'signin-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1280, 'height': 800})
    email = 'new-user@example.test'
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    token = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()
    page.goto(args.base + '/signin/confirm#token=' + token + '&email=' + email,
              wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()

    # After sign-in, the home page opens each resource page on desktop and mobile.
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 844 if width < 400 else 800})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        if width != 320:
            page.screenshot(path=str(shots / f'home-{width}.png'), full_page=True)
        for title, path in [('シークレット', '/secrets'), ('サービス', '/services'),
                            ('オブジェクト', '/objects'), ('プリンシパル', '/principals'),
                            ('ファンクション', '/functions')]:
            page.get_by_role('main').get_by_role('link', name=re.compile('^' + title)).click()
            expect(page).to_have_url(args.base + path)
            expect(page.get_by_role('heading', name=title, exact=True)).to_be_visible()
            page.goto(args.base, wait_until='networkidle')
            expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()
    page.set_viewport_size({'width': 1280, 'height': 800})

    # ホームはサービスとの接続の件数を要約し、サービスの画面へ案内する。
    for count in [0, 1, 40]:
        summary = {'resources': [
            {'service': {'id': 'google', 'name': 'Google'}, 'auth_scheme': 'oauth', 'label': f'複数の用途で利用する接続先のアカウント {number}@example.test'}
            for number in range(count)
        ]}
        page.route('**/v1/principals/me/resources?kind=connection', lambda route: route.fulfill(json=summary))
        for width in [1280, 390]:
            page.set_viewport_size({'width': width, 'height': 844})
            page.reload(wait_until='networkidle')
            card = page.get_by_role('main').get_by_role('link', name=f'サービス {count} 件', exact=True)
            expect(card).to_be_visible()
            expect(card).to_have_attribute('href', '/services')
            expect(card).to_have_text(f'サービス{count} 件')
            if count == 40:
                page.screenshot(path=str(shots / f'home-connections-{width}.png'), full_page=True)
        page.unroute('**/v1/principals/me/resources?kind=connection')
    page.set_viewport_size({'width': 1280, 'height': 800})
    page.reload(wait_until='networkidle')

    # The specification is public, independent of the owner's browser session.
    public = p.request.new_context()
    response = public.get(args.base + '/openapi.json')
    assert response.status == 200
    assert response.headers['content-type'].startswith('application/json')
    assert response.json()['servers'] == [{'url': args.base}]
    public.dispose()

    # A new CLI initialises, asks to join, and the owner approves through the existing UI.
    started = cli('init', args.base, '--name', '初めて使うAI')
    assert started.returncode == 0, started.stderr
    connected = cli('join')
    assert connected.returncode == 0, connected.stderr
    request = json.loads(connected.stdout)['request']
    before = cli('api', 'GET', '/v1/principals/me')
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout)['principal']['acts_for'] == []
    page.goto(request['verification_uri'], wait_until='networkidle')
    expect(page.get_by_text('初めて使うAIの依頼', exact=True)).to_be_visible()
    page.get_by_label('確認コード', exact=True).fill(request['user_code'])
    page.get_by_role('button', name='許可する', exact=True).click()
    expect(page.get_by_role('heading', name='アクセスを許可しました', exact=True)).to_be_visible()
    approved = cli('api', 'GET', '/v1/principals/me')
    assert approved.returncode == 0, approved.stderr
    assert len(json.loads(approved.stdout)['principal']['acts_for']) == 1

    # Secrets need a key, from a passkey; the AI uses them through Foundation, handed over here.
    make_key(page, args.base)
    unlock(page, args.base)
    hand_to_foundation(page)
    page.get_by_role('button', name='追加', exact=True).click()
    form = page.get_by_role('dialog')
    form.get_by_label('名前', exact=True).fill('onboarding-demo')
    form.get_by_label('値', exact=True).fill('fixture-onboarding-value')
    form.get_by_role('button', name='追加', exact=True).click()
    expect(page.get_by_role('heading', name='onboarding-demo', exact=True)).to_be_visible()
    command = ('exec', 'DEMO_TOKEN=onboarding-demo', '--', 'node', '-e',
               "process.exit(process.env.DEMO_TOKEN === 'fixture-onboarding-value' ? 0 : 1)")
    used = cli(*command)
    assert used.returncode == 0, used.stderr

    page.goto(args.base + '/principals', wait_until='networkidle')
    row = page.locator('.access-row').filter(has_text='初めて使うAI')
    revoke_access(page, '初めて使うAI').get_by_role('button', name='解除', exact=True).click()
    expect(row.get_by_text('サブプリンシパル', exact=True)).to_be_visible()
    expect(row.get_by_text('エージェント', exact=True)).to_have_count(0)
    refused = cli(*command)
    assert refused.returncode == 1 and 'not_approved' in refused.stderr
    assert not errors, errors
    context.close()
    browser.close()
    print('Start UI passed: home navigation, responsive layout, public specification, fresh CLI approval, delivery and revocation.')
