import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import urllib.request
import uuid

from playwright.sync_api import sync_playwright, expect


ORIGIN = "http://localhost:3458"
ARTIFACTS = Path("test-results/browser")


class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        cls.playwright = sync_playwright().start()
        cls.chromium = cls.playwright.chromium.launch(headless=True)
        cls.webkit = cls.playwright.webkit.launch(headless=True)

    @classmethod
    def tearDownClass(cls):
        cls.chromium.close()
        cls.webkit.close()
        cls.playwright.stop()

    def setUp(self):
        self.contexts = []
        self.errors = []

    def tearDown(self):
        for context in self.contexts:
            context.close()
        self.assertEqual(self.errors, [], "Browser scripts complete successfully")

    def page(self, webkit=False, mobile=False):
        context = (self.webkit if webkit else self.chromium).new_context(
            viewport={"width": 390 if mobile else 1440, "height": 844 if mobile else 1050},
            is_mobile=mobile, has_touch=mobile,
        )
        self.contexts.append(context)
        page = context.new_page()
        page.on("pageerror", lambda error: self.errors.append(str(error)))
        page.on("console", lambda message: self.errors.append(message.text) if message.type == "error" and "Content Security Policy" in message.text else None)
        page.expose_function("foundationPolicyViolation", lambda directive: self.errors.append("CSP: " + directive))
        page.add_init_script("document.addEventListener('securitypolicyviolation', event => window.foundationPolicyViolation(event.effectiveDirective));")
        return page

    def passkey_account(self, name="Browser account"):
        page = self.page()
        cdp = page.context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True, "hasPrf": True,
        }})
        page.goto(ORIGIN + "/signin")
        page.wait_for_load_state("networkidle")
        page.get_by_role("button", name="アカウントを作成", exact=True).click()
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("button", name="パスキーを作成", exact=True).click()
        page.wait_for_url("**/p/**")
        page.wait_for_load_state("networkidle")
        principal = page.request.get(ORIGIN + "/api/session").json()["principal"]
        self.assertIsNotNone(principal["publicKey"])
        return page, principal

    def secret(self, page, principal, name="Test secret", value="browser-secret"):
        page.goto(f"{ORIGIN}/p/{principal['id']}/secrets/new")
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("textbox", name="値", exact=True).fill(value)
        page.get_by_role("checkbox", name="Foundationでの実行に使用する").check()
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        return page.url

    def select(self, page, label, option):
        page.get_by_role("combobox", name=label, exact=True).click()
        page.get_by_role("option", name=option, exact=True).click()
        expect(page.get_by_role("listbox")).to_be_hidden()

    def test_パスキーで登録してシークレットを編集し再ログイン後に復号する(self):
        page, principal = self.passkey_account()
        path = self.secret(page, principal)
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("browser-secret")
        page.get_by_role("link", name="編集", exact=True).click()
        page.get_by_role("textbox", name="名前", exact=True).fill("Updated secret")
        page.get_by_role("textbox", name="値", exact=True).fill("updated-value")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("heading", name="Updated secret", exact=True)).to_be_visible()
        page.reload()
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("updated-value")
        with page.expect_download() as download:
            page.get_by_role("button", name="ダウンロード", exact=True).click()
        self.assertEqual(Path(download.value.path()).read_text(), "updated-value")
        page.get_by_role("button", name="ログアウト", exact=True).click()
        page.wait_for_url("**/signin")
        page.get_by_role("button", name="パスキーでログイン", exact=True).click()
        page.wait_for_url("**/p/**")
        page.goto(path)
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("updated-value")
        page.screenshot(path=str(ARTIFACTS / "secret-desktop-ja.png"), full_page=True, caret="initial")

    def test_相手の鍵で共有したシークレットを開き共有解除を反映する(self):
        owner, principal = self.passkey_account("Secret owner")
        reader, recipient = self.passkey_account("Secret reader")
        path = self.secret(owner, principal, "Shared secret")
        owner.get_by_role("link", name="共有", exact=True).click()
        owner.get_by_role("textbox", name="共有相手のプリンシパルID").fill(recipient["id"])
        owner.get_by_role("checkbox", name="内容を開く", exact=True).check()
        owner.get_by_role("button", name="権限を保存", exact=True).click()
        expect(owner.get_by_text("Secret reader", exact=True)).to_be_visible()
        reader.goto(ORIGIN + "/shared")
        reader.get_by_role("link", name="Shared secret", exact=True).click()
        reader.get_by_role("button", name="内容を表示", exact=True).click()
        expect(reader.get_by_role("textbox", name="値", exact=True)).to_have_value("browser-secret")
        owner.get_by_role("listitem").filter(has_text="Secret reader").get_by_role("button", name="権限を解除", exact=True).click()
        expect(owner.get_by_text("Secret reader", exact=True)).to_be_hidden()
        resource_id = path.rsplit("/", 1)[1]
        self.assertEqual(reader.request.get(f"{ORIGIN}/api/resources/{resource_id}/secret").status, 403)

    def test_メンバー追加と所有者変更でシークレットを引き継ぐ(self):
        owner, principal = self.passkey_account("Project owner")
        member, recipient = self.passkey_account("Project member")
        successor, new_owner = self.passkey_account("Project successor")
        owner.goto(f"{ORIGIN}/p/{principal['id']}/principals/new")
        owner.get_by_role("textbox", name="名前", exact=True).fill("Shared project")
        owner.get_by_role("button", name="作成", exact=True).click()
        expect(owner.get_by_role("heading", name="Shared project", exact=True)).to_be_visible()
        project = {"id": owner.url.rsplit("/", 1)[1]}
        secret_path = self.secret(owner, project, "Team secret", "team-secret-value")
        owner.goto(f"{ORIGIN}/p/{project['id']}/principals")
        owner.get_by_role("textbox", name="相手のプリンシパルID").fill(recipient["id"])
        self.select(owner, "関係", "メンバー")
        owner.get_by_role("button", name="追加", exact=True).click()
        expect(owner.get_by_text("Project member → メンバー → Shared project", exact=True)).to_be_visible()
        member.goto(secret_path)
        member.get_by_role("button", name="内容を表示", exact=True).click()
        expect(member.get_by_role("textbox", name="値", exact=True)).to_have_value("team-secret-value")
        owner.goto(f"{ORIGIN}/p/{project['id']}/settings/general")
        owner.get_by_role("textbox", name="新しい所有者のプリンシパルID").fill(new_owner["id"])
        owner.get_by_role("button", name="所有者を変更", exact=True).click()
        owner.wait_for_url(f"**/p/{principal['id']}")
        successor.goto(secret_path)
        successor.get_by_role("button", name="内容を表示", exact=True).click()
        expect(successor.get_by_role("textbox", name="値", exact=True)).to_have_value("team-secret-value")

    def test_サービス接続とプリンシパルを作成して委任する(self):
        page, principal = self.passkey_account()
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new")
        self.select(page, "サービス", "GitHub")
        page.get_by_role("textbox", name="名前", exact=True).fill("GitHub test")
        page.get_by_label("Personal access token").fill("test-provider-token")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("heading", name="GitHub test", exact=True)).to_be_visible()
        expect(page.get_by_text("GH_TOKEN", exact=False)).to_be_visible()
        page.goto(f"{ORIGIN}/p/{principal['id']}/principals/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Automation")
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Automation", exact=True)).to_be_visible()
        child_id = page.url.rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/principals")
        page.get_by_role("textbox", name="相手のプリンシパルID").fill(child_id)
        page.get_by_role("button", name="追加", exact=True).click()
        expect(page.get_by_text("Automation → 代理 → Browser account", exact=True)).to_be_visible()

    def test_ファイルを保存して実行環境を起動しコマンドを実行して停止する(self):
        page, principal = self.passkey_account()
        response = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(response.ok, response.text())
        page.goto(f"{ORIGIN}/p/{principal['id']}/objects/new")
        page.locator('input[name="file"]').set_input_files({"name": "report.txt", "mimeType": "text/plain", "buffer": b"browser file"})
        page.get_by_role("button", name="アップロード", exact=True).click()
        expect(page.get_by_role("heading", name="report.txt", exact=True)).to_be_visible()
        with page.expect_download() as download:
            page.get_by_role("link", name="ダウンロード", exact=True).click()
        self.assertEqual(Path(download.value.path()).read_text(), "browser file")
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Worker")
        page.get_by_role("button", name="起動", exact=True).click()
        expect(page.get_by_role("heading", name="Worker", exact=True)).to_be_visible()
        expect(page.get_by_role("link", name="実行", exact=True)).to_be_visible(timeout=15000)
        environment_path = page.url
        page.get_by_role("link", name="実行", exact=True).click()
        page.get_by_role("button", name="実行", exact=True).click()
        expect(page.get_by_text('"stdout": "ok"', exact=False)).to_be_visible(timeout=15000)
        page.goto(environment_path)
        page.get_by_role("button", name="停止", exact=True).click()
        page.get_by_role("dialog").get_by_role("button", name="停止", exact=True).click()
        expect(page.get_by_text("停止済み", exact=True)).to_be_visible(timeout=15000)

    def test_依頼内容を確認して承認し新しいプリンシパルを作成する(self):
        sender, _ = self.passkey_account("Requester")
        receiver, principal = self.passkey_account("Approver")
        sender.goto(ORIGIN + "/requests/new")
        sender.get_by_role("textbox", name="依頼先のプリンシパルID").fill(principal["id"])
        sender.get_by_role("textbox", name="メッセージ", exact=True).fill("Create a project account")
        sender.get_by_role("textbox", name="操作（JSON）", exact=True).fill(json.dumps([{"method": "POST", "path": "/api/principals", "body": {"name": "Approved project", "ownerId": "$approver"}}]))
        sender.get_by_role("button", name="作成", exact=True).click()
        sender.wait_for_url("**/requests/*")
        expect(sender.get_by_text("確認待ち", exact=True)).to_be_visible()
        receiver.goto(sender.url)
        receiver.get_by_role("button", name="承認", exact=True).click()
        expect(receiver.get_by_text("承認済み", exact=True)).to_be_visible()
        projects = receiver.request.get(ORIGIN + "/api/principals").json()["items"]
        self.assertIn("Approved project", [item["name"] for item in projects])

    def test_通常のログインがある端末で依頼専用リンクを開いて依頼を承認する(self):
        sender, _ = self.passkey_account("Link requester")
        owner, principal = self.passkey_account("Link approver")
        viewer, _ = self.passkey_account("Existing session")
        sender.goto(ORIGIN + "/requests/new")
        sender.get_by_role("textbox", name="依頼先のプリンシパルID").fill(principal["id"])
        sender.get_by_role("textbox", name="操作（JSON）", exact=True).fill(json.dumps([{"method": "POST", "path": "/api/principals", "body": {"name": "Link project", "ownerId": "$approver"}}]))
        sender.get_by_role("button", name="作成", exact=True).click()
        sender.wait_for_url("**/requests/*")
        expect(sender.get_by_text("確認待ち", exact=True)).to_be_visible()
        owner.goto(sender.url)
        owner.get_by_role("button", name="確認用リンクを作成", exact=True).click()
        link_field = owner.get_by_role("textbox", name="URL", exact=True)
        expect(link_field).to_be_visible()
        viewer.goto(link_field.input_value())
        expect(viewer.get_by_role("button", name="承認", exact=True)).to_be_visible()
        current = viewer.request.get(ORIGIN + "/api/session").json()
        self.assertEqual(current["principal"]["id"], principal["id"])
        self.assertEqual(current["requestId"], sender.url.rsplit("/", 1)[1])
        viewer.get_by_role("button", name="承認", exact=True).click()
        expect(viewer.get_by_text("承認済み", exact=True)).to_be_visible()
        projects = owner.request.get(ORIGIN + "/api/principals").json()["items"]
        self.assertIn("Link project", [item["name"] for item in projects])

    def test_モバイルでメール認証して英語表示へ切り替えフォームを操作する(self):
        page = self.page(webkit=True, mobile=True)
        address = "mobile-" + uuid.uuid4().hex[:8] + "@example.com"
        page.goto(ORIGIN + "/signin")
        page.get_by_role("textbox", name="メールアドレス", exact=True).fill(address)
        page.get_by_role("button", name="ログインリンクを送信", exact=True).click()
        expect(page.get_by_role("alert")).to_contain_text(address)
        link = page.request.get(ORIGIN + "/__test/mail/" + address).json()["link"]
        page.goto(link)
        page.get_by_role("button", name="メールを確認して続ける", exact=True).click()
        page.wait_for_url("**/p/**")
        self.select(page, "言語", "English")
        page.get_by_role("button", name="Open navigation", exact=True).click()
        page.get_by_role("link", name="Environments", exact=True).click()
        page.get_by_role("link", name="Create", exact=True).click()
        expect(page.get_by_role("heading", name="Create environment", exact=True)).to_be_visible()
        page.get_by_role("textbox", name="Name", exact=True).fill("Mobile worker")
        self.select(page, "Size", "Medium — 2 CPU / 1 GB")
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.get_by_role("link", name="Cancel", exact=True).click()
        expect(page.get_by_role("heading", name="Environments", exact=True)).to_be_visible()
        page.reload()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()


if __name__ == "__main__":
    server = None
    if not os.environ.get("FOUNDATION_UI_SERVER"):
        log = (ARTIFACTS.parent / "browser-server.log")
        log.parent.mkdir(parents=True, exist_ok=True)
        server_output = log.open("w")
        server = subprocess.Popen(["node", "--import", "tsx", "tests/browser-server.ts"], stdout=server_output, stderr=server_output)
        for attempt in range(100):
            if server.poll() is not None:
                server_output.close()
                raise RuntimeError(log.read_text())
            try:
                with urllib.request.urlopen(ORIGIN + "/__test/ready", timeout=1) as response:
                    if json.load(response)["pid"] == server.pid:
                        break
            except Exception:
                pass
            time.sleep(0.1)
        else:
            server.terminate()
            server.wait(timeout=20)
            server_output.close()
            raise RuntimeError("Browser test server did not start")
    try:
        unittest.main(verbosity=2)
    finally:
        if server:
            server.terminate()
            server.wait(timeout=20)
            server_output.close()
