import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect
from ui_flows import revoke_access

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

    # Oneself is listed first and read like any other: its name, its id, every way in, who pays.
    mine = page.locator('.access-row').first
    expect(mine.get_by_text('自分', exact=True)).to_be_visible()
    mine.get_by_role('button', name='詳細', exact=True).click()
    own = page.get_by_role('dialog')
    expect(own.locator('.detail-row').filter(has_text='クレデンシャル')).to_contain_text(email)
    expect(own.locator('.detail-row').filter(has_text='費用の負担')).to_be_visible()
    expect(own.get_by_role('button', name='削除', exact=True)).to_have_count(0)
    review(page)
    page.screenshot(path=str(shots / 'own-details.png'), full_page=True)
    own.get_by_role('button', name='閉じる', exact=True).last.click()
    # A name left empty is drawn for it, as for any principal that gives none.
    page.get_by_role('button', name='作成', exact=True).click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_role('button', name='作成', exact=True).click()
    expect(dialog.locator('.detail-row').filter(has_text='名前')).to_contain_text(re.compile(r"[A-Z][A-Za-z' ]+ [A-Z][A-Za-z' ]+"))
    dialog.get_by_role('button', name='閉じる', exact=True).last.click()
    page.get_by_role('button', name='作成', exact=True).click()
    expect(dialog.get_by_role('heading', name='新しいプリンシパル', exact=True)).to_be_visible()
    review(page)
    page.screenshot(path=str(shots / 'add-principal.png'), full_page=True)
    dialog.get_by_label('名前', exact=True).fill('laptop')
    dialog.get_by_role('button', name='作成', exact=True).click()
    # Made, its details open: who bears its use, and a key issued there.
    expect(dialog.get_by_role('heading', name='laptop', exact=True)).to_be_visible()
    expect(dialog.get_by_text('費用の負担', exact=True)).to_be_visible()
    expect(dialog.locator('.detail-row').filter(has_text='費用の負担')).to_contain_text(context.request.get(args.base + '/v1/principals/me').json()['principal']['name'])
    dialog.get_by_role('button', name='キーを発行', exact=True).click()
    expect(dialog.get_by_label('アクセスキー', exact=True)).to_be_visible()
    key = dialog.get_by_label('アクセスキー', exact=True).input_value()
    dialog.get_by_role('button', name='完了', exact=True).click()
    expect(dialog.locator('.credential-item')).to_have_count(1)
    dialog.get_by_role('button', name='閉じる', exact=True).last.click()
    row = page.get_by_role('article').filter(has=page.get_by_role('heading', name='laptop', exact=True))
    expect(row.get_by_text('サブプリンシパル', exact=True)).to_be_visible()
    # Made, it reaches nothing of the owner's.
    agents = context.request.get(args.base + '/v1/principals/me/relations?relation=agent&direction=to').json()['relations']
    assert all(item['principal']['name'] != 'laptop' for item in agents)
    whoami = p.request.new_context().get(args.base + '/v1/principals/me', headers={'authorization': 'Bearer ' + key}).json()
    assert whoami['principal']['acts_for'] == []

    # Narrowing the list by name.
    page.get_by_label('名前で絞り込む', exact=True).fill('zzz')
    expect(page.get_by_text('該当するプリンシパルはありません。', exact=True)).to_be_visible()
    page.get_by_label('名前で絞り込む', exact=True).fill('lap')
    expect(row).to_be_visible()

    # What it is to others shows too, where its owner can read it: here, another's agent as well.
    made = context.request.post(args.base + '/v1/principals', data=json.dumps({'name': 'helper'}), headers={'content-type': 'application/json', 'origin': args.base}).json()['principal']
    laptop = next(line['principal']['id'] for line in context.request.get(args.base + '/v1/principals/me/relations?relation=owner&direction=from').json()['relations'] if line['principal']['name'] == 'laptop')
    drawn = context.request.post(args.base + '/v1/principals/' + laptop + '/relations', data=json.dumps({'relation': 'agent', 'object_type': 'principal', 'object_id': made['id']}), headers={'content-type': 'application/json', 'origin': args.base})
    assert drawn.status == 201, drawn.text()
    # From its details, made the owner's agent: a line drawn, and the list says so.
    row.get_by_role('button', name='詳細', exact=True).click()
    expect(dialog.get_by_role('heading', name='laptop', exact=True)).to_be_visible()
    expect(dialog.locator('.detail-row').filter(has_text='ほかの関係')).to_contain_text('helper のエージェント')
    review(page)
    page.screenshot(path=str(shots / 'principal-details.png'), full_page=True)
    dialog.get_by_role('button', name='エージェントに設定', exact=True).click()
    # What an agent may do is said here, where it is decided.
    expect(dialog.get_by_role('heading', name='laptop をエージェントに設定しますか？', exact=True)).to_be_visible()
    expect(dialog.get_by_text('許可の詳細', exact=True)).to_be_visible()
    review(page)
    dialog.locator('.dialog-actions').get_by_role('button', name='エージェントに設定', exact=True).click()
    expect(dialog.locator('.detail-row').filter(has_text='エージェント').first).to_contain_text('のエージェント')
    dialog.get_by_role('button', name='閉じる', exact=True).last.click()
    expect(row.get_by_text('エージェント', exact=True)).to_be_visible()
    assert context.request.get(args.base + '/v1/principals/me').json()['principal']['id'] in p.request.new_context().get(args.base + '/v1/principals/me', headers={'authorization': 'Bearer ' + key}).json()['principal']['acts_for']
    revoke_access(page, 'laptop').get_by_role('button', name='解除', exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(row.get_by_text('エージェント', exact=True)).to_have_count(0)
    expect(row.get_by_text('サブプリンシパル', exact=True)).to_be_visible()
    assert not errors, errors
    browser.close()
    print('相手の追加: 作っただけでは何も届かず、詳細から代理人にすると線が引かれ、取り消せることを確認しました。')
