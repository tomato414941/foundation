import argparse
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots')
args = parser.parse_args()
shots = Path(args.screenshots) if args.screenshots else None
if shots:
    shots.mkdir(parents=True, exist_ok=True)
ROLE = 'arn:aws:iam::222222222222:role/foundation-connection-FoundationRole-ABC'


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for private in ['assumed-secret', 'assumed-session', 'fixture-secret', 'X-Amz-Signature']:
        assert private not in text, private


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1280, 'height': 1000})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/grants', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill('owner@example.test')
    page.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(page.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()
    page.goto(args.base + '/login/confirm#token_hash=' + hashlib.sha256(b'owner@example.test').hexdigest() + '&email=owner%40example.test', wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_load_state('networkidle')
    page.goto(args.base + '/grants', wait_until='networkidle')
    expect(page.get_by_role('heading', name='AWS', exact=True)).to_be_visible()
    page.get_by_role('button', name='AWSで役割を作る', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_role('heading', name='AWSに接続', exact=True)).to_be_visible()
    expect(dialog.get_by_text('鍵は預かりません。', exact=False)).to_be_visible()
    dialog.get_by_role('button', name='AWSで役割を作る', exact=True).click()

    # The console opens in another tab; here the owner pastes the role's name. A wrong paste is answered in place.
    expect(dialog.get_by_role('heading', name='AWSで役割を作る', exact=True)).to_be_visible()
    link = dialog.get_by_role('link', name='AWSの画面を開く ↗', exact=True)
    href = link.get_attribute('href')
    assert href.startswith('https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/create/review?'), href
    parameters = parse_qs(urlparse(href).fragment.split('?', 1)[1])
    assert parameters['stackName'] == ['foundation-connection']
    assert parameters['param_FoundationRoleArn'] == ['arn:aws:iam::111111111111:role/foundation-host-InstanceRole']
    assert link.get_attribute('target') == '_blank'
    if shots:
        page.screenshot(path=str(shots / 'aws-role.png'), full_page=True)
    dialog.get_by_label('作成された役割のARN', exact=True).fill('not an arn')
    dialog.get_by_role('button', name='接続する', exact=True).click()
    expect(dialog.get_by_role('alert')).to_contain_text('役割のARN')
    dialog.get_by_label('作成された役割のARN', exact=True).fill(ROLE)
    dialog.get_by_role('button', name='接続する', exact=True).click()
    expect(page.get_by_text('AWSに接続しました。', exact=True)).to_be_visible()
    expect(dialog).not_to_be_visible()
    row = page.locator('.agent-row').filter(has=page.get_by_text('222222222222 / foundation-connection-FoundationRole-ABC', exact=True))
    expect(row).to_be_visible()
    expect(row.get_by_text('利用できます', exact=True)).to_be_visible()
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 1000})
        review(page)
        if shots and width != 320:
            page.screenshot(path=str(shots / ('aws-desktop.png' if width == 1280 else 'aws-mobile.png')), full_page=True)

    # Disconnecting removes the grant here; the role itself is the owner's to delete at AWS, and the screen says so.
    page.set_viewport_size({'width': 1280, 'height': 1000})
    row.get_by_role('button', name='接続を解除', exact=True).click()
    expect(dialog.get_by_text('foundation-connection', exact=False)).to_be_visible()
    dialog.get_by_role('button', name='接続を解除', exact=True).click()
    expect(page.get_by_text('解除しました。', exact=True)).to_be_visible()
    expect(page.get_by_text('222222222222 / foundation-connection-FoundationRole-ABC', exact=True)).to_have_count(0)
    assert not errors, errors
    browser.close()
    print('AWS: 役割の作成リンク・誤った貼り付け・接続・解除と、PC・スマートフォンの表示を確認しました。')
