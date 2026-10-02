import argparse
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from playwright.sync_api import sync_playwright, expect
from ui_flows import allow_foundation, plain, injected, b64url

# Everything an account has, given to another principal from the account page: a secret the other then uses
# through Foundation, and an owned principal that becomes theirs.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '設計意図', 'fdn_', 'transfer']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(locale='ja-JP', viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    email = 'giver@example.test'
    page.goto(args.base + '/account', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    fragment = urlencode({'email': email, 'token': base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()})
    page.goto(args.base + '/signin/confirm?return_to=%2Faccount#' + fragment, wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(args.base + '/account')
    allow_foundation(context.request, args.base)
    kept = context.request.put(args.base + '/v1/resources?kind=secret&name=handed', data=plain('hand-me'), headers={'content-type': 'application/json', 'origin': args.base})
    assert kept.ok, kept.text()
    owned = context.request.post(args.base + '/v1/principals', data=json.dumps({'name': 'my agent', 'agent': True, 'key': True}), headers={'content-type': 'application/json', 'origin': args.base}).json()

    # The one given to: a principal of its own, with a key, and Foundation as its agent.
    other = p.request.new_context()
    made = other.post(args.base + '/v1/principals', data=json.dumps({'name': 'receiver'}), headers={'content-type': 'application/json'}).json()
    headers = {'authorization': 'Bearer ' + made['token']}
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert other.put(args.base + '/v1/key', data=json.dumps({'public_key': b64url(public)}), headers={**headers, 'content-type': 'application/json'}).ok
    overview = other.get(args.base + '/v1/overview', headers=headers).json()
    assert other.post(args.base + '/v1/relations', data=json.dumps({'subject': overview['foundation']['principal_id'], 'relation': 'agent', 'object_type': 'principal', 'object_id': made['principal']['id']}), headers={**headers, 'content-type': 'application/json'}).ok

    page.reload(wait_until='networkidle')
    # The account shows its own ID, for whoever is to give to it.
    expect(page.get_by_role('region', name='ID').get_by_text(context.request.get(args.base + '/v1/overview').json()['user']['id'], exact=True)).to_be_visible()
    section = page.get_by_role('region', name='引き渡す')
    expect(section).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'account-transfer.png'), full_page=True)
    section.get_by_role('button', name='引き渡す', exact=True).click()
    dialog = page.get_by_role('dialog')
    # Nothing chosen gives nothing; everything chosen gives everything.
    dialog.get_by_label('引き渡す相手の ID', exact=True).fill(made['principal']['id'])
    dialog.get_by_role('button', name='引き渡す', exact=True).click()
    expect(dialog.get_by_role('alert')).to_have_text('引き渡すものを選んでください。')
    expect(dialog.get_by_role('group', name='シークレット').get_by_role('checkbox', name='handed')).to_be_visible()
    expect(dialog.get_by_role('group', name='登録した相手').get_by_role('checkbox', name='my agent')).to_be_visible()
    for box in dialog.get_by_role('checkbox').all():
        box.check()
    review(page)
    page.screenshot(path=str(shots / 'transfer-dialog.png'), full_page=True)
    dialog.get_by_role('button', name='引き渡す', exact=True).click()
    expect(dialog).not_to_be_visible()
    assert context.request.get(args.base + '/v1/resources?kind=secret').json()['resources'] == []
    assert context.request.get(args.base + '/v1/principals').json()['principals'] == []
    theirs = other.get(args.base + '/v1/resources?kind=secret', headers=headers).json()['resources']
    assert [row['name'] for row in theirs] == ['handed']
    assert injected(other, args.base, 'handed', headers=headers).text() == 'hand-me'
    assert [row['id'] for row in other.get(args.base + '/v1/principals', headers=headers).json()['principals']] == [owned['principal']['id']]
    assert not errors, errors
    browser.close()
    print('引き渡す: 選んだ秘密と相手が別のアカウントのものになり、相手が Foundation を通して使えることを確認しました。')
