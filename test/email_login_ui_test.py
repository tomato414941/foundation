import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
parser.add_argument('--engine', choices=['chromium', 'webkit'], default='chromium')
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
email = 'mobile+login@example.test'
key = hashlib.sha256(email.encode()).hexdigest()
link = args.base + '/login/confirm?return_to=%2Fgrants#' + urlencode({'token_hash': key, 'email': email})

with sync_playwright() as p:
    browser = getattr(p, args.engine).launch(headless=True)
    sender = browser.new_context(viewport={'width': 1280, 'height': 900})
    receiver = browser.new_context(viewport={'width': 390, 'height': 844})
    start = sender.new_page()
    start.goto(args.base, wait_until='networkidle')
    start.get_by_label('メールアドレス', exact=True).fill(email)
    start.get_by_role('button', name='ログインメールを送信', exact=True).click()
    expect(start.get_by_role('heading', name='メールを確認', exact=True)).to_be_visible()

    page = receiver.new_page()
    errors, calls, urls = [], [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('request', lambda request: urls.append(request.url))
    page.on('request', lambda request: calls.append(request) if request.url.endswith('/v1/login/verify') else None)
    page.goto(link, wait_until='networkidle')
    expect(page.get_by_role('heading', name='ログイン', exact=True)).to_be_visible()
    expect(page.get_by_text(email, exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='ログイン', exact=True)).to_be_enabled()
    assert page.url == args.base + '/login/confirm'
    assert calls == [], 'リンクを開いた時点では、確認ボタンの操作を待つ'
    assert receiver.request.get(args.base + '/v1/overview').status == 401
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    for width in [1280, 390, 320]:
        page.set_viewport_size({'width': width, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(shots / ('confirm-' + str(width) + '.png')), full_page=True)

    # Reloading the cleared URL asks for the email link again, which remains usable.
    page.reload(wait_until='networkidle')
    expect(page.get_by_text('メールに届いたリンクを開き直してください。', exact=True)).to_be_visible()
    page.goto(link, wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    page.wait_for_url(args.base + '/grants')
    page.wait_for_load_state('networkidle')
    assert receiver.request.get(args.base + '/v1/overview').json()['user']['email'] == email
    assert len(calls) == 1
    assert all(key not in url for url in urls), '鍵をHTTPのURLへ送信しない'
    assert sender.request.get(args.base + '/v1/overview').status == 401, '受け取った側だけをログイン済みにする'

    # An already used key leaves the current login intact and explains the failed attempt.
    page.goto(link, wait_until='networkidle')
    page.get_by_role('button', name='ログイン', exact=True).click()
    expect(page.get_by_role('alert')).to_have_text('リンクが無効か、有効期限が切れています。')
    assert receiver.request.get(args.base + '/v1/overview').json()['user']['email'] == email
    assert not errors, errors
    receiver.close()
    sender.close()
    browser.close()
    print('別ブラウザで確認してログインする。先読み・再読み込み・再利用・モバイル表示を確認する。')
