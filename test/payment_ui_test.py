import argparse
import base64
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

# Paying, against the fixture server with FOUNDATION_TEST_PAYMENT=1, whose Stripe answers as Stripe would: the account
# page offers to set a payment method, Stripe's page (stood in for here) sends the person back, and the account page
# says it is set.
parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
email = 'payer@example.test'
token = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()


def review(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    text = page.locator('body').inner_text()
    for phrase in ['Stripe', 'subscription', 'checkout', '実装', '設計意図']:
        assert phrase not in text, phrase


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 390, 'height': 844})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(args.base + '/account', wait_until='networkidle')
    page.get_by_label('メールアドレス', exact=True).fill(email)
    page.get_by_role('button', name='サインインメールを送信', exact=True).click()
    page.goto(args.base + '/signin/confirm?' + urlencode({'return_to': '/account'}) + '#' + urlencode({'token': token, 'email': email}), wait_until='networkidle')
    page.get_by_role('button', name='サインイン', exact=True).click()
    page.wait_for_url(args.base + '/account')

    section = page.get_by_role('region', name='支払い')
    expect(section.get_by_text('無料枠を超えて使うには、支払い方法を登録します。', exact=True)).to_be_visible()
    page.screenshot(path=str(shots / 'account-before-390.png'), full_page=True)
    review(page)
    # Stripe's page, where the card would be entered, sends the person straight back.
    page.route('https://checkout.stripe.com/**', lambda route: route.fulfill(status=302, headers={'location': args.base + '/account?payment=cs_test_1'}, body=''))
    section.get_by_role('button', name='支払い方法を登録', exact=True).click()
    expect(page.get_by_text('支払い方法を登録しました。', exact=True)).to_be_visible()
    expect(section.get_by_text('支払い方法を登録済みです。無料枠を超えた分が請求されます。', exact=True)).to_be_visible()
    assert page.url == args.base + '/account', page.url
    page.screenshot(path=str(shots / 'account-after-390.png'), full_page=True)
    review(page)
    assert not errors, errors
    browser.close()
    print('支払い: アカウントでの登録の案内・Stripeの画面からの戻り・登録済みの表示と、スマートフォンの表示を確認しました。')
