import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

# Adding a principal makes it and issues its key, and nothing more: it reaches nothing until, from its details, it is
# made an agent - a line drawn, which the list then shows and which can be taken back.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
email = 'principals@example.test'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['実装', '設計意図', 'fdn_', 'agent']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/principals', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/signin/confirm?return_to=%2Fprincipals#' + urlencode({'email': email, 'token': base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()}), wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(args.base + '/principals')

    page.get_by_role('button', name='追加', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_role('heading', name='相手を追加', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'add-principal.png'), full_page=True)
    dialog.get_by_label('名前', exact=True).fill('laptop')
    dialog.get_by_role('button', name='追加してキーを発行', exact=True).click()
    expect(dialog.get_by_label('アクセスキー', exact=True)).to_be_visible()
    key = dialog.get_by_label('アクセスキー', exact=True).input_value()
    dialog.get_by_role('button', name='閉じる', exact=True).last.click()
    row = page.get_by_role('article').filter(has=page.get_by_role('heading', name='laptop', exact=True))
    expect(row.get_by_text('全体へのアクセス許可なし', exact=True)).to_be_visible()
    # Made, it reaches nothing of the owner's.
    agents = context.request.get(args.base + '/v1/principals/me/relations?relation=agent&direction=to').json()['relations']
    assert all(item['principal']['name'] != 'laptop' for item in agents)
    whoami = p.request.new_context().get(args.base + '/v1/principals/me', headers={'authorization': 'Bearer ' + key}).json()
    assert whoami['acts_for'] == []

    # From its details, made the owner's agent: a line drawn, and the list says so.
    row.get_by_role('button', name='詳細', exact=True).click()
    expect(dialog.get_by_role('heading', name='laptop', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'principal-details.png'), full_page=True)
    dialog.get_by_role('button', name='代理人にする', exact=True).click()
    expect(dialog.get_by_text('許可の詳細', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='閉じる', exact=True).last.click()
    expect(row.get_by_text('許可 ', exact=False)).to_be_visible()
    assert p.request.new_context().get(args.base + '/v1/principals/me', headers={'authorization': 'Bearer ' + key}).json()['acts_for'] == [context.request.get(args.base + '/v1/principals/me').json()['principal']['id']]
    row.get_by_role('button', name='取り消す', exact=True).click()
    dialog.get_by_role('button', name='許可を取り消す', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(row.get_by_text('全体へのアクセス許可なし', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('相手の追加: 作っただけでは何も届かず、詳細から代理人にすると線が引かれ、取り消せることを確認しました。')
