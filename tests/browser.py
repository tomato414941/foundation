import json
import os
import re
from pathlib import Path
import subprocess
import time
import unittest
import urllib.request
import uuid

from playwright.sync_api import sync_playwright, expect


ORIGIN = "http://localhost:" + os.environ.get("FOUNDATION_TEST_PORT", "3458")
ARTIFACTS = Path("test-results/browser")


class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        cls.next_client = 1
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
        self.authenticators = {}
        self.environments = []

    def tearDown(self):
        result = self._outcome.result
        if any(test is self for test, _ in result.failures + result.errors):
            for index, context in enumerate(self.contexts):
                for page in context.pages:
                    if not page.is_closed():
                        page.screenshot(path=str(ARTIFACTS / (self._testMethodName + str(index) + '.png')), full_page=True)
                        print(page.url + '\n' + page.locator('body').inner_text()[:10000], flush=True)
        for page, environment_id in self.environments:
            page.request.post(ORIGIN + '/api/resources/' + environment_id + '/stop', data={}, headers={'origin': ORIGIN})
        for context in self.contexts:
            context.close()
        self.assertEqual(self.errors, [], "Browser scripts complete successfully")

    def page(self, webkit=False, mobile=False):
        client = type(self).next_client
        type(self).next_client += 1
        context = (self.webkit if webkit else self.chromium).new_context(
            viewport={"width": 390 if mobile else 1440, "height": 844 if mobile else 1050},
            is_mobile=mobile, has_touch=mobile,
            extra_http_headers={"x-forwarded-for": f"198.18.{client // 256}.{client % 256}"},
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
        authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True, "hasPrf": True,
        }})
        self.authenticators[page] = (cdp, authenticator["authenticatorId"])
        page.goto(ORIGIN + "/signin")
        page.wait_for_load_state("networkidle")
        page.get_by_role("button", name="アカウントを作成", exact=True).click()
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("button", name="パスキーを作成", exact=True).click()
        page.wait_for_url("**/p/**")
        page.wait_for_load_state("networkidle")
        response = page.request.get(ORIGIN + "/api/session")
        self.assertTrue(response.ok, response.text())
        principal = response.json()["principal"]
        self.assertIsNotNone(principal["publicKey"])
        return page, principal

    def secret(self, page, principal, name="Test secret", value="browser-secret"):
        page.goto(f"{ORIGIN}/p/{principal['id']}/secrets/new")
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("textbox", name="値", exact=True).fill(value)
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        return page.url

    def select(self, page, label, option):
        page.get_by_role("combobox", name=label, exact=True).click()
        page.get_by_role("option", name=option, exact=True).click()
        expect(page.get_by_role("listbox")).to_be_hidden()

    def trust_fingerprint(self, page, principal_id, fingerprint):
        previous = page.url
        page.goto(ORIGIN + "/account/trust")
        page.get_by_role("textbox", name="共有相手のプリンシパルID", exact=True).fill(principal_id)
        page.get_by_role("textbox", name="鍵の指紋", exact=True).fill(fingerprint)
        page.get_by_role("button", name="相手の鍵を確認", exact=True).click()
        expect(page.get_by_text("保存しました。", exact=True)).to_be_visible()
        page.goto(previous)

    def trust(self, page, other, principal):
        previous = other.url
        other.goto(ORIGIN + "/account/trust")
        fingerprint = other.get_by_text(re.compile(r"^[A-Za-z0-9_-]{43}$")).inner_text()
        other.goto(previous)
        self.trust_fingerprint(page, principal["id"], fingerprint)

    def executor(self, page, principal, name="Browser executor"):
        response = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(response.ok, response.text())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("button", name="起動", exact=True).click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        expect(page.get_by_role("link", name="実行", exact=True)).to_be_visible(timeout=15000)
        path = page.url
        self.environments.append((page, path.rsplit('/', 1)[1]))
        fingerprint = page.request.get(ORIGIN + "/__test/executor/" + path.rsplit("/", 1)[1] + "/fingerprint").json()
        self.trust_fingerprint(page, fingerprint["id"], fingerprint["fingerprint"])
        return path

    def accept_connection(self, page, name):
        expect(page.get_by_role("heading", name="接続先と権限を確認して保存", exact=True)).to_be_visible(timeout=15000)
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible(timeout=15000)
        page.wait_for_url("**/services/*")

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
        self.trust(owner, reader, recipient)
        self.trust(reader, owner, principal)
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
        self.assertEqual(reader.request.get(f"{ORIGIN}/api/resources/{resource_id}/custody").status, 403)

    def test_追加したパスキーでログインして保存済みのシークレットを復号する(self):
        page, principal = self.passkey_account("Existing account")
        cdp, authenticator_id = self.authenticators[page]
        original_credential = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})["credentials"][0]["credentialId"]
        path = self.secret(page, principal, "Existing secret", "Saved secret value")
        page.get_by_role("button", name="ログアウト", exact=True).click()
        page.wait_for_url("**/signin")
        page.get_by_role("button", name="パスキーでログイン", exact=True).click()
        page.wait_for_url("**/p/**")
        page.goto(path)
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("Saved secret value")
        page.get_by_role("link", name="編集", exact=True).click()
        page.get_by_role("textbox", name="値", exact=True).fill("Edited existing secret")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("heading", name="Existing secret", exact=True)).to_be_visible()
        page.goto(ORIGIN + "/account")
        page.wait_for_load_state("networkidle")
        unlock = page.get_by_role("button", name="パスキーでロック解除", exact=True)
        with page.expect_response(lambda response: response.url.endswith("/auth/passkeys/verify")):
            unlock.click()
        expect(unlock).to_be_enabled()
        expect(page.get_by_text("この端末でシークレットを開けます。", exact=True)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "account-desktop-ja.png"), full_page=True)
        cdp.send("WebAuthn.removeCredential", {"authenticatorId": authenticator_id, "credentialId": original_credential})
        page.get_by_role("link", name="パスキーを追加", exact=True).click()
        page.get_by_role("textbox", name="名前", exact=True).fill("Additional passkey")
        page.get_by_role("button", name="追加", exact=True).click()
        page.wait_for_url("**/settings/credentials")
        expect(page.get_by_text("Additional passkey", exact=True)).to_be_visible()
        page.get_by_role("button", name="ログアウト", exact=True).click()
        page.wait_for_url("**/signin")
        page.get_by_role("button", name="パスキーでログイン", exact=True).click()
        page.wait_for_url("**/p/**")
        page.goto(path)
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("Edited existing secret")
        page.screenshot(path=str(ARTIFACTS / "additional-passkey-ja.png"), full_page=True)

    def test_ブラウザで発行したキーでCLIにログインしブラウザが封じたシークレットを読む(self):
        import tempfile
        page, principal = self.passkey_account("Key issuer")
        path = self.secret(page, principal, "Issuer secret", "Issued through the browser")
        secret_id = path.rstrip("/").split("/")[-1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/credentials/new")
        page.wait_for_load_state("networkidle")
        self.select(page, "種類", "APIキー")
        page.get_by_role("textbox", name="名前", exact=True).fill("Laptop key")
        page.get_by_role("button", name="追加", exact=True).click()
        token = page.get_by_role("textbox", name="APIキー", exact=True).input_value()
        self.assertTrue(token.startswith("fk_"))
        page.screenshot(path=str(ARTIFACTS / "issued-key-ja.png"), full_page=True)
        session = page.request.get(ORIGIN + "/api/session", headers={"authorization": "Bearer " + token.split(".")[0]}).json()
        self.assertEqual(session["principal"]["id"], principal["id"])
        self.assertIsNotNone(session["wrappedKey"])
        with tempfile.TemporaryDirectory() as home:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = home
            key_file = Path(home) / "key.txt"
            key_file.write_text(token + "\n")
            initialized = subprocess.run(
                ["node", "cli/dist/cli.mjs", "login", "--key", "@" + str(key_file), "--origin", ORIGIN],
                capture_output=True, text=True, env=environment,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            self.assertEqual(json.loads(initialized.stdout)["principal"]["id"], principal["id"])
            read = subprocess.run(
                ["node", "cli/dist/cli.mjs", "read", secret_id],
                capture_output=True, text=True, env=environment,
            )
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout, "Issued through the browser")
        created = page.request.post(ORIGIN + "/api/principals", data={"name": "Keyless child", "ownerId": principal["id"]}, headers={"origin": ORIGIN})
        self.assertEqual(created.status, 201, created.text())
        child = created.json()
        self.assertIsNone(child["publicKey"])
        page.goto(ORIGIN + "/account/trust")
        owner_fingerprint = page.get_by_text(re.compile(r"^[A-Za-z0-9_-]{43}$")).inner_text()
        page.goto(f"{ORIGIN}/p/{child['id']}/settings/credentials/new")
        page.wait_for_load_state("networkidle")
        self.select(page, "種類", "APIキー")
        page.get_by_role("textbox", name="名前", exact=True).fill("Child key")
        page.get_by_role("button", name="追加", exact=True).click()
        child_token = page.get_by_role("textbox", name="APIキー", exact=True).input_value()
        self.assertIsNotNone(page.request.get(ORIGIN + "/api/principals/" + child["id"]).json()["publicKey"])
        with tempfile.TemporaryDirectory() as home:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = home
            initialized = subprocess.run(
                ["node", "cli/dist/cli.mjs", "login", "--key", "@-", "--origin", ORIGIN],
                capture_output=True, text=True, env=environment, input=child_token,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            trusted = subprocess.run(
                ["node", "cli/dist/cli.mjs", "trust", principal["id"], "--fingerprint", owner_fingerprint],
                capture_output=True, text=True, env=environment,
            )
            self.assertEqual(trusted.returncode, 0, trusted.stderr)
            kept = subprocess.run(
                ["node", "cli/dist/cli.mjs", "keep", "Child secret", "--stdin"],
                capture_output=True, text=True, env=environment, input="kept by the child",
            )
            self.assertEqual(kept.returncode, 0, kept.stderr)
            read = subprocess.run(
                ["node", "cli/dist/cli.mjs", "read", json.loads(kept.stdout)["id"]],
                capture_output=True, text=True, env=environment,
            )
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout, "kept by the child")

    def test_端末のログインをブラウザで許可すると端末が本人として入りシークレットを読む(self):
        import re, tempfile
        page, principal = self.passkey_account("Device approver")
        path = self.secret(page, principal, "Approver secret", "Read after device sign-in")
        secret_id = path.rstrip("/").split("/")[-1]
        with tempfile.TemporaryDirectory() as home:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = home
            login = subprocess.Popen(
                ["node", "cli/dist/cli.mjs", "login", "--name", "Approved laptop", "--origin", ORIGIN],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
            )
            shown = ""
            for _ in range(200):
                shown += login.stderr.readline()
                if "enter the code" in shown:
                    break
            url = re.search(r"Open (\S+)", shown).group(1)
            code = re.search(r"code ([A-Z0-9]{4}-[A-Z0-9]{4})", shown).group(1)
            page.goto(url)
            page.wait_for_load_state("networkidle")
            expect(page.get_by_text("Approved laptop がログインしようとしています。", exact=True)).to_be_visible()
            page.get_by_role("textbox", name="確認コード", exact=True).fill(code)
            page.screenshot(path=str(ARTIFACTS / "device-signin-ja.png"), full_page=True)
            page.get_by_role("button", name="許可", exact=True).click()
            expect(page.get_by_text("Approved laptop をログインさせました。端末に戻ってください。", exact=True)).to_be_visible()
            stdout, stderr = login.communicate(timeout=60)
            self.assertEqual(login.returncode, 0, stderr)
            self.assertEqual(json.loads(stdout)["principal"]["id"], principal["id"])
            read = subprocess.run(["node", "cli/dist/cli.mjs", "read", secret_id], capture_output=True, text=True, env=environment)
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout, "Read after device sign-in")

    def test_ログイン方法の一覧に鍵の状態と使用中の印を示し発行したキーが鍵を持つ(self):
        page, principal = self.passkey_account("Credentials viewer")
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/credentials")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_text("この端末でシークレットを開けます。", exact=True)).to_be_visible()
        row = page.get_by_role("listitem").filter(has_text="Credentials viewer")
        expect(row.get_by_text("使用中", exact=True)).to_be_visible()
        expect(row.get_by_text("シークレットを開ける", exact=False)).to_be_visible()
        expect(row.get_by_role("button", name="削除", exact=True)).to_have_count(0)
        page.get_by_role("link", name="キーを発行", exact=True).click()
        expect(page.get_by_role("heading", name="キーを発行", exact=True)).to_be_visible()
        expect(page.get_by_role("combobox", name="種類", exact=True)).to_have_count(0)
        page.get_by_role("textbox", name="名前", exact=True).fill("Issued key")
        page.get_by_role("button", name="追加", exact=True).click()
        expect(page.get_by_role("textbox", name="APIキー", exact=True)).to_be_visible()
        page.get_by_role("link", name="閉じる", exact=True).click()
        page.wait_for_url("**/settings/credentials")
        key_row = page.get_by_role("listitem").filter(has_text="Issued key")
        expect(key_row.get_by_text("シークレットを開ける", exact=False)).to_be_visible()
        expect(key_row.get_by_role("button", name="削除", exact=True)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "credentials-desktop-ja.png"), full_page=True)

    def test_メンバー追加と所有者変更でシークレットを引き継ぐ(self):
        owner, principal = self.passkey_account("Project owner")
        member, recipient = self.passkey_account("Project member")
        successor, new_owner = self.passkey_account("Project successor")
        self.trust(owner, member, recipient)
        self.trust(owner, successor, new_owner)
        self.trust(member, owner, principal)
        self.trust(successor, owner, principal)
        self.trust(successor, member, recipient)
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
        self.executor(page, principal)
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new")
        self.select(page, "サービス", "AWS")
        self.select(page, "サービス", "GitHub")
        page.get_by_role("textbox", name="名前", exact=True).fill("GitHub test")
        page.get_by_label("Personal access token").fill("test-provider-token")
        self.select(page, "実行環境", "Browser executor")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "GitHub test")
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

    def test_接続方法を選んで登録し共有分類から再利用して再認証を確認する(self):
        page, principal = self.passkey_account("Connection owner")
        self.executor(page, principal)
        root = f"{ORIGIN}/p/{principal['id']}"
        methods = {
            "personal": {"name": "Personal access", "kind": "token", "config": {
                "fields": [{"name": "personalKey", "label": "Personal key", "secret": True}],
                "outputs": {"PERSONAL_KEY": "/personalKey"},
            }},
            "project": {"name": "Project access", "kind": "token", "config": {
                "fields": [{"name": "projectKey", "label": "Project key", "secret": True}],
                "outputs": {"PROJECT_KEY": "/projectKey"},
            }},
        }
        page.goto(root + "/definitions/new")
        page.wait_for_load_state("networkidle")
        page.get_by_role("textbox", name="名前", exact=True).fill("Work APIs")
        page.get_by_role("textbox", name="定義（JSON）", exact=True).fill(json.dumps({"methods": methods}))
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Work APIs", exact=True)).to_be_visible()
        service = page.request.get(ORIGIN + "/api/resources/" + page.url.rsplit("/", 1)[1]).json()
        page.goto(root + "/services/new")
        page.wait_for_load_state("networkidle")
        self.select(page, "サービス", "Work APIs")
        self.select(page, "接続方法", "Personal access")
        page.get_by_label("Personal key").fill("personal-fixture-key")
        self.select(page, "接続方法", "Project access")
        page.get_by_label("Project key").fill("project-fixture-key")
        page.get_by_role("textbox", name="名前", exact=True).fill("Primary account")
        self.select(page, "実行環境", "Browser executor")
        page.screenshot(path=str(ARTIFACTS / "connection-method-ja.png"), full_page=True, animations="disabled")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "Primary account")
        expect(page.get_by_role("heading", name="Primary account", exact=True)).to_be_visible()
        expect(page.get_by_text("外部サービスの権限は未確認", exact=True)).to_be_visible()
        expect(page.get_by_text("接続先の名義は未確認", exact=True)).to_be_visible()
        expect(page.get_by_text("Project access", exact=True)).to_be_visible()
        connection_path = page.url
        connection_id = connection_path.rsplit("/", 1)[1]
        page.goto(root + "/definitions/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Other workspace")
        page.get_by_role("textbox", name="定義（JSON）", exact=True).fill(json.dumps({"methods": {"shared": service["data"]["methods"]["project"]}}))
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Other workspace", exact=True)).to_be_visible()
        page.goto(root + "/services/new")
        self.select(page, "サービス", "Other workspace")
        expect(page.get_by_text("この接続方法で登録済みの接続を利用できます。", exact=True)).to_be_visible()
        page.get_by_role("link", name="Primary account", exact=True).click()
        expect(page.get_by_role("heading", name="Primary account", exact=True)).to_be_visible()
        self.assertEqual(page.url, connection_path)
        expect(page.get_by_text("Other workspace, Work APIs", exact=True)).to_be_visible()
        page.get_by_role("link", name="再接続", exact=True).click()
        expect(page.get_by_role("combobox", name="接続方法", exact=True)).to_be_disabled()
        page.get_by_label("Project key").fill("rotated-fixture-key")
        self.select(page, "実行環境", "Browser executor")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("heading", name="接続先と権限を確認して保存", exact=True)).to_be_visible(timeout=15000)
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(ARTIFACTS / "connection-review-ja.png"), full_page=True, animations="disabled")
        self.select(page, "言語", "English")
        page.set_viewport_size({"width": 390, "height": 844})
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("heading", name="Confirm account and permissions, then save", exact=True)).to_be_visible()
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.screenshot(path=str(ARTIFACTS / "connection-review-mobile-en.png"), full_page=True, animations="disabled")
        page.get_by_role("button", name="Save", exact=True).click()
        page.wait_for_url(connection_path)
        expect(page.get_by_role("heading", name="Primary account", exact=True)).to_be_visible(timeout=15000)
        self.assertEqual(page.url, connection_path)
        connection = page.request.get(ORIGIN + "/api/resources/" + connection_id).json()
        self.assertEqual(connection["data"]["methodId"], service["data"]["methods"]["project"])
        self.assertEqual(connection["version"], 2)
        expect(page.get_by_text("External permissions not verified", exact=True)).to_be_visible()
        page.wait_for_load_state("networkidle")
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.screenshot(path=str(ARTIFACTS / "connection-mobile-en.png"), full_page=True, animations="disabled")

    def test_独立した接続方法を登録しOAuthアプリを対応する方法に結び付ける(self):
        page, principal = self.passkey_account("Method owner")
        self.executor(page, principal)
        root = f"{ORIGIN}/p/{principal['id']}"
        page.goto(root + "/methods/new")
        page.wait_for_load_state("networkidle")
        page.get_by_role("textbox", name="名前", exact=True).fill("Workspace sign-in")
        page.get_by_role("textbox", name="定義（JSON）", exact=True).fill(json.dumps({"kind": "oauth", "config": {
            "authorizeUrl": "https://provider.example/authorize", "tokenUrl": "https://provider.example/token",
            "fields": [{"name": "workspace", "label": "Workspace", "required": True}],
        }}))
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Workspace sign-in", exact=True)).to_be_visible()
        method_id = page.url.rsplit("/", 1)[1]
        page.goto(root + "/apps/new")
        page.wait_for_load_state("networkidle")
        self.select(page, "サービス", "すべての接続方法")
        self.select(page, "接続方法", "Workspace sign-in")
        page.get_by_role("textbox", name="名前", exact=True).fill("Workspace application")
        page.get_by_label("クライアントID").fill("browser-client")
        page.get_by_label("クライアントシークレット").fill("browser-client-secret")
        page.get_by_label("Workspace", exact=False).fill("workspace-name")
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Workspace application", exact=True)).to_be_visible()
        application = page.request.get(ORIGIN + "/api/resources/" + page.url.rsplit("/", 1)[1]).json()
        self.assertEqual(application["data"]["methodId"], method_id)
        page.get_by_role("link", name="編集", exact=True).click()
        expect(page.get_by_label("Workspace", exact=False)).to_have_value("workspace-name")
        page.goto(root + "/services/new?method=" + method_id)
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("combobox", name="接続方法", exact=True)).to_have_text("Workspace sign-in")
        expect(page.get_by_role("combobox", name="OAuthアプリ", exact=True)).to_have_text("Workspace application")
        expect(page.get_by_role("button", name="接続する", exact=True)).to_be_enabled()
        page.screenshot(path=str(ARTIFACTS / "connection-oauth-app-ja.png"), full_page=True, animations="disabled")

    def test_選んだ実行先のAWSの身元を信頼するIAMロールをAWSで作るリンクを示す(self):
        page, principal = self.passkey_account()
        self.executor(page, principal)
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        self.select(page, "実行環境", "Browser executor")
        link = page.get_by_role("link", name="AWSでIAMロールを作る", exact=True)
        expect(link).to_be_visible()
        href = link.get_attribute("href")
        self.assertIn("console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/create/review?", href)
        self.assertIn("templateURL=https%3A%2F%2Fobjects.example%2Fpublished%2Faws-connection.yaml", href)
        self.assertIn("param_PrincipalArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ffoundation-test-executor", href)
        external_id = re.search(r"param_ExternalId=([0-9a-f]{32})", href).group(1)
        self.assertEqual(page.get_by_label("External ID", exact=True).input_value(), external_id)
        page.screenshot(path=str(ARTIFACTS / "connection-aws-role-ja.png"), full_page=True, animations="disabled")

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
        environment_path = self.executor(page, principal, "Worker")
        page.get_by_role("link", name="実行", exact=True).click()
        page.get_by_role("textbox", name="コマンド", exact=True).fill(json.dumps(["node", "-e", "process.stdout.write('ok')"]))
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
        receiver.wait_for_load_state("networkidle")
        expect(receiver.get_by_text("1. プリンシパルを作る", exact=True)).to_be_visible()
        expect(receiver.get_by_text("POST /api/principals")).to_have_count(0)
        receiver.screenshot(path=str(ARTIFACTS / "request-approval-ja.png"), full_page=True)
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
        request_id = sender.url.rsplit("/", 1)[1]
        response = owner.request.post(f"{ORIGIN}/api/requests/{request_id}/links", data={}, headers={"origin": ORIGIN})
        self.assertTrue(response.ok, response.text())
        viewer.goto(response.json()["url"])
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
        expect(page.get_by_role("dialog")).to_be_visible()
        page.get_by_role("link", name="Environments", exact=True).click()
        page.get_by_role("link", name="Create", exact=True).click()
        expect(page.get_by_role("heading", name="Create environment", exact=True)).to_be_visible()
        page.get_by_role("textbox", name="Name", exact=True).fill("Mobile worker")
        self.select(page, "Size", "Medium — 2 CPU / 2 GB")
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.get_by_role("link", name="Cancel", exact=True).click()
        expect(page.get_by_role("heading", name="Environments", exact=True)).to_be_visible()
        page.reload()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()

    def test_外部連携の完了URLとやり直し用URLを保存して表示する(self):
        page, principal = self.passkey_account("URL settings account")
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/integrations")
        page.wait_for_load_state("networkidle")
        page.get_by_role("textbox", name="完了後のURL", exact=True).fill("https://client.example/complete")
        page.get_by_role("textbox", name="やり直し用のURL", exact=True).fill("https://client.example/retry")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("alert")).to_contain_text("保存しました")
        page.reload()
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("textbox", name="完了後のURL", exact=True)).to_have_value("https://client.example/complete")
        expect(page.get_by_role("textbox", name="やり直し用のURL", exact=True)).to_have_value("https://client.example/retry")
        page.screenshot(path=str(ARTIFACTS / "integrations-desktop-ja.png"), full_page=True)
        print("Rendered settings: " + page.get_by_role("tabpanel").inner_text(), flush=True)

    def test_設定を保存しキーボードでタブと確認画面を操作する(self):
        page, principal = self.passkey_account("Keyboard account")
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/general")
        page.get_by_role("textbox", name="名前", exact=True).fill("Updated keyboard account")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("alert")).to_contain_text("保存しました")
        page.get_by_role("tab", name="基本情報", exact=True).focus()
        page.keyboard.press("ArrowRight")
        page.wait_for_url("**/settings/credentials")
        expect(page.get_by_role("tabpanel").get_by_text("Keyboard account", exact=True)).to_be_visible()
        page.get_by_role("tab", name="ログイン方法・APIキー", exact=True).focus()
        page.keyboard.press("ArrowRight")
        page.wait_for_url("**/settings/billing")
        expect(page.get_by_role("progressbar", name="ストレージ", exact=True)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "settings-desktop-ja.png"), full_page=True)
        page.get_by_role("tab", name="基本情報", exact=True).click()
        remove = page.get_by_role("button", name="プリンシパルを削除", exact=True)
        remove.click()
        expect(page.get_by_role("dialog")).to_be_visible()
        page.keyboard.press("Escape")
        expect(remove).to_be_focused()
        expect(page.get_by_role("textbox", name="名前", exact=True)).to_have_value("Updated keyboard account")


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
