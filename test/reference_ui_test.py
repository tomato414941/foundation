import argparse
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect
from ui_flows import start_connect, allow_foundation, plain, injected

# A token field that refers to a secret: chosen under the field when connecting, used every time the connection is,
# and following the secret when it changes. Against the fixture with Cloudflare configured.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
email = 'referrer@example.test'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '設計意図', 'fdn_', 'cf-referenced', 'reference']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/services', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/signin/confirm?return_to=%2Fservices#' + urlencode({'email': email, 'token': base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()}), wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(args.base + '/services')
    allow_foundation(context.request, args.base)
    kept = context.request.put(args.base + '/v1/principals/me/resources?kind=secret&name=cloudflare token', data=plain('cf-referenced-1'), headers={'content-type': 'application/json', 'origin': args.base})
    assert kept.ok, kept.text()
    page.reload(wait_until='networkidle')

    # Under the field: paste a value, or refer to a secret. Choosing a secret puts the input away.
    dialog = start_connect(page, 'Cloudflare', 'トークンを使う')
    field = dialog.get_by_label('APIトークン', exact=True)
    expect(field).to_be_visible()
    choice = dialog.get_by_label('シークレットを参照する：APIトークン', exact=True)
    expect(choice).to_have_value('')
    choice.select_option(label='シークレットを参照する：cloudflare token')
    expect(field).to_be_hidden()
    review(page)
    page.screenshot(path=str(shots / 'reference-dialog.png'), full_page=True)
    dialog.get_by_role('button', name='接続する', exact=True).click()
    expect(page.get_by_text('Cloudflareに接続しました。', exact=True)).to_be_visible()
    connections = context.request.get(args.base + '/v1/principals/me/resources?kind=connection').json()['resources']
    assert len(connections) == 1 and connections[0]['references'] == [kept.json()['resource']['id']], connections
    assert injected(context.request, args.base, 'cloudflare token').text() == 'cf-referenced-1'
    delivered = context.request.post(args.base + '/v1/principals/me/injections', data=json.dumps({'names': [{'id': connections[0]['id']}]}), headers={'content-type': 'application/json', 'origin': args.base}).json()
    assert delivered['injection']['environment']['CLOUDFLARE_API_TOKEN'] == 'cf-referenced-1'
    # The secret changes; the connection follows. Referenced, the secret stays.
    assert context.request.put(args.base + '/v1/resources/' + kept.json()['resource']['id'] + '/content', data=plain('cf-referenced-2'), headers={'content-type': 'application/json', 'origin': args.base}).ok
    delivered = context.request.post(args.base + '/v1/principals/me/injections', data=json.dumps({'names': [{'id': connections[0]['id']}]}), headers={'content-type': 'application/json', 'origin': args.base}).json()
    assert delivered['injection']['environment']['CLOUDFLARE_API_TOKEN'] == 'cf-referenced-2'
    refused = context.request.delete(args.base + '/v1/resources/' + kept.json()['resource']['id'], data='{}', headers={'content-type': 'application/json', 'origin': args.base})
    assert refused.status == 409 and refused.json()['error']['code'] == 'secret_in_use', refused.text()
    page.goto(args.base + '/services', wait_until='networkidle')
    review(page)
    assert not errors, errors
    browser.close()
    print('参照: トークンの欄でシークレットを選んで接続し、使うたびにその中身が渡り、変えれば追い、参照されている間は消せないことを確認しました。')
