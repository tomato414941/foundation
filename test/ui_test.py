import argparse
import hashlib
from pathlib import Path
import json
from urllib.parse import urlparse, parse_qs, urlencode
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument("--base", required=True)
parser.add_argument("--screenshots", required=True)
parser.add_argument("--empty-config", action="store_true")
args = parser.parse_args()
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)

def check_display(page):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "horizontal overflow"
    result = page.evaluate("""() => {
      const nodes = [...document.querySelectorAll('p, label, button, small, dt, dd, input, textarea, summary')];
      return nodes.filter(el => el.getBoundingClientRect().width && el.getBoundingClientRect().height && el.checkVisibility())
        .filter(el => parseFloat(getComputedStyle(el).fontSize) < 14)
        .map(el => el.tagName + ': ' + el.textContent.slice(0, 30));
    }""")
    assert not result, result
    copy = page.locator("body").inner_text()
    for phrase in ["client_secret", "refresh_token", "実装", "開発者", "設計意図", "未設定です"]:
        assert phrase not in copy, phrase

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1280, "height": 950})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(args.base)
    page.wait_for_load_state("networkidle")
    expect(page.get_by_role("heading", name="ログイン", exact=True)).to_be_visible()
    check_display(page)
    page.screenshot(path=str(shots / "login.png"), full_page=True)
    for width in [390, 320, 1280]:
        page.set_viewport_size({"width": width, "height": 950})
        check_display(page)
    if args.empty_config:
        expect(page.get_by_role("button", name="ログインメールを送信", exact=True)).to_be_disabled()
        expect(page.get_by_text("現在ログインを利用できません。", exact=True)).to_be_visible()
        for width in [390, 320]:
            page.set_viewport_size({"width": width, "height": 844})
            check_display(page)
        assert not errors, errors
        context.close()
        browser.close()
        print("Unconfigured authentication fails closed; mobile copy reviewed.")
        raise SystemExit(0)

    page.get_by_label("メールアドレス", exact=True).fill("owner@example.test")
    assert page.locator('input[type="password"]').count() == 0
    page.get_by_role("button", name="ログインメールを送信", exact=True).click()
    expect(page.get_by_role("heading", name="メールを確認", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="再送信まで", exact=False)).to_be_disabled()
    check_display(page)
    page.screenshot(path=str(shots / "email-link.png"), full_page=True)
    for width in [390, 320, 1280]:
        page.set_viewport_size({"width": width, "height": 950})
        check_display(page)
        if width == 320:
            page.screenshot(path=str(shots / "email-link-mobile.png"), full_page=True)
    page.reload(wait_until="networkidle")
    expect(page.get_by_role("heading", name="メールを確認", exact=True)).to_be_visible()
    assert page.locator('input[name="code"]').count() == 0
    assert "fdn_login" not in page.evaluate("document.cookie")
    assert page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
    page.get_by_role("button", name="メールアドレスを変更", exact=True).click()
    expect(page.get_by_label("メールアドレス", exact=True)).to_have_value("owner@example.test")
    page.get_by_label("メールアドレス", exact=True).fill("new@example.test")
    page.get_by_role("button", name="ログインメールを送信", exact=True).click()
    expect(page.get_by_role("heading", name="メールを確認", exact=True)).to_be_visible()
    expect(page.get_by_text("new@example.test", exact=True)).to_be_visible()
    page.goto(args.base + "/auth/callback?code=invalid-authorization-code", wait_until="networkidle")
    expect(page.get_by_text("リンクが無効か、有効期限が切れています。最新のメールのリンクを開いてください。", exact=True)).to_be_visible()
    assert "code=" not in page.url
    # Simulate opening the email's link in another tab of the same browser.
    code = hashlib.sha256(b"new@example.test").hexdigest()
    link_page = context.new_page()
    link_page.goto(args.base + "/auth/callback?code=" + code, wait_until="networkidle")
    expect(link_page.get_by_role("heading", name="シークレット", exact=True)).to_be_visible()
    assert "code=" not in link_page.url and "#" not in link_page.url
    link_page.close()
    page.bring_to_front()
    page.evaluate('window.dispatchEvent(new Event("focus"))')
    expect(page.get_by_role("heading", name="シークレット", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="メールの読み取り", exact=True)).to_be_enabled()
    expect(page.get_by_role("button", name="アクセスキーを追加", exact=True)).to_be_enabled()
    assert page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
    assert "fdn_session" not in page.evaluate("document.cookie")
    page.screenshot(path=str(shots / "empty.png"), full_page=True)

    # Replace only Google's authorization page with a redirect. No Google login/network traffic.
    authorization = {"code": "personal-readonly", "deny": False}
    def google_consent(route):
        query = parse_qs(urlparse(route.request.url).query)
        assert query["code_challenge_method"] == ["S256"]
        assert query["access_type"] == ["offline"]
        params = {"state": query["state"][0]}
        params.update({"error": "access_denied"} if authorization["deny"] else {"code": authorization["code"]})
        route.fulfill(status=302, headers={"location": query["redirect_uri"][0] + "?" + urlencode(params)}, body="")
    page.route("https://accounts.google.com/o/oauth2/v2/auth?*", google_consent)
    dialog = page.get_by_role("dialog")

    # Each read range is its own connection; the owner starts the one they want.
    def connect(code, metadata=False):
        authorization["code"] = code
        page.locator(".agent-row").filter(has_text="Gmail").get_by_role("button", name="件名・差出人などの読み取り" if metadata else "メールの読み取り", exact=True).click()
        expect(dialog).to_be_visible()
        check_display(page)
        if not metadata:
            page.screenshot(path=str(shots / "connect.png"), full_page=True)
        dialog.locator("button[type=submit]").click()
        expect(page.get_by_role("heading", name="シークレット", exact=True)).to_be_visible()
        expect(page.get_by_text("認証情報を登録しました。", exact=True)).to_be_visible()
        page.wait_for_load_state("networkidle")
        assert "code=" not in page.url and "state=" not in page.url

    connect("personal-readonly")
    connect("work-metadata", True)
    # Both sit under one group, named by the paths they were kept at.
    gmail = page.locator('[aria-labelledby="gmail-title"]')
    expect(gmail.locator(".agent-name h3")).to_have_text(["personal@example.test", "work@example.test"])
    expect(gmail.get_by_text("件名・差出人などの読み取り", exact=True)).to_be_visible()
    # What a connection keeps is its own business; the owner opens it only to look.
    expect(gmail.get_by_text("google-oauth-access-token", exact=True).first).to_be_hidden()
    gmail.get_by_text("3件の中身", exact=True).first.click()
    expect(gmail.get_by_text("google-oauth-access-token", exact=True).first).to_be_visible()

    def create_runtime(name):
        page.get_by_role("button", name="アクセスキーを追加", exact=True).click()
        dialog.get_by_label("アクセスキーの名前", exact=True).fill(name)
        dialog.get_by_role("button", name="アクセスキーを発行", exact=True).click()
        expect(dialog.locator("#agent-token")).to_be_visible()
        token = dialog.locator("#agent-token").input_value()
        # Deliberately never screenshot keys, including test keys.
        dialog.get_by_role("button", name="閉じる", exact=True).last.click()
        return token

    token_a = create_runtime("dev-us")
    token_b = create_runtime("別のアクセスキー")
    caller = p.request.new_context(base_url=args.base)
    def runtime(path, token, method="GET"):
        return caller.fetch(path, method=method, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, data="{}" if method == "POST" else None)
    def deliver(paths, token):
        return caller.fetch("/v1/deliver", method="POST", headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, data=json.dumps({"paths": paths}))
    connections = runtime("/v1/acquisitions", token_a).json()["acquisitions"]
    assert len(connections) == 2, "an issued key uses everything its owner keeps"
    paths = [entry["path"] for entry in connections[0]["secrets"]]
    issued = deliver(paths, token_a)
    assert issued.status == 200 and issued.json()["delivery"]["environment"]["GOOGLE_OAUTH_ACCESS_TOKEN"].startswith("google-access-")
    assert "google-access-" not in page.content()
    page.reload()
    page.wait_for_load_state("networkidle")
    check_display(page)
    page.screenshot(path=str(shots / "desktop.png"), full_page=True)

    row = page.locator(".agent-row").filter(has_text="dev-us")
    assert deliver(paths, token_b).status == 200

    for width in [1280, 800, 768, 601, 600, 390, 320]:
        page.set_viewport_size({"width": width, "height": 950})
        check_display(page)
    page.set_viewport_size({"width": 390, "height": 1000})
    page.screenshot(path=str(shots / "mobile.png"), full_page=True)
    # Cancellation returns a useful message without disclosing provider errors.
    authorization["deny"] = True
    gmail.get_by_role("button", name="接続し直す", exact=True).first.click()
    dialog.locator("button[type=submit]").click()
    expect(page.get_by_text("登録をキャンセルしました。", exact=True)).to_be_visible()
    authorization["deny"] = False

    page.set_viewport_size({"width": 390, "height": 844})
    row.get_by_role("button", name="失効", exact=True).click()
    expect(dialog.get_by_text("有効期限まで", exact=False)).to_be_visible()
    check_display(page)
    page.screenshot(path=str(shots / "revoke-mobile.png"), full_page=True)
    dialog.get_by_role("button", name="失効させる", exact=True).click()
    expect(dialog).not_to_be_visible()
    assert runtime("/v1/acquisitions", token_a).status == 401
    assert runtime("/v1/acquisitions", token_b).status == 200
    gmail.get_by_role("button", name="接続を解除", exact=True).first.click()
    check_display(page)
    page.screenshot(path=str(shots / "disconnect-mobile.png"), full_page=True)
    dialog.get_by_role("button", name="接続を解除", exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(gmail.locator(".agent-name h3")).to_have_text(["work@example.test"])
    assert deliver(paths, token_b).status == 404, "what it kept went with it"
    page.get_by_role("button", name="ログアウト", exact=True).click()
    expect(page.get_by_role("heading", name="ログイン", exact=True)).to_be_visible()
    assert not errors, errors
    print("Browser checks passed: email-link signup/login, invalid links, reload, email change, cross-tab login, two connections, what each keeps, delivery, revoke, disconnect, mobile and copy.")
    print("Screenshots:", str(shots))
    caller.dispose()
    context.close()
    browser.close()
