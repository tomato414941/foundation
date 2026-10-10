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

    def variable(self, page, principal, name="Test variable", value="browser-value"):
        page.goto(f"{ORIGIN}/p/{principal['id']}/variables/new")
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
        page.get_by_role("textbox", name="公開鍵の指紋", exact=True).fill(fingerprint)
        page.get_by_role("button", name="相手の鍵を確認", exact=True).click()
        expect(page.get_by_text("保存しました。", exact=True)).to_be_visible()
        page.goto(previous)

    def trust(self, page, other, principal):
        previous = other.url
        other.goto(ORIGIN + "/account/trust")
        fingerprint = other.get_by_text(re.compile(r"^sha256:[0-9a-f]{64}$")).inner_text()
        other.goto(previous)
        self.trust_fingerprint(page, principal["id"], fingerprint)

    def executor(self, page, principal, name="Browser executor"):
        response = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(response.ok, response.text())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("button", name="起動", exact=True).click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
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

    def test_パスキーで登録して変数を編集し再ログイン後に復号する(self):
        page, principal = self.passkey_account()
        path = self.variable(page, principal)
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("browser-value")
        page.get_by_role("link", name="編集", exact=True).click()
        page.get_by_role("textbox", name="名前", exact=True).fill("Updated variable")
        page.get_by_role("textbox", name="値", exact=True).fill("updated-value")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("heading", name="Updated variable", exact=True)).to_be_visible()
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
        page.screenshot(path=str(ARTIFACTS / "variable-desktop-ja.png"), full_page=True, caret="initial")

    def test_相手の鍵で共有した変数を開き共有解除を反映する(self):
        owner, principal = self.passkey_account("Variable owner")
        reader, recipient = self.passkey_account("Variable reader")
        self.trust(owner, reader, recipient)
        self.trust(reader, owner, principal)
        path = self.variable(owner, principal, "Shared variable")
        owner.get_by_role("link", name="共有", exact=True).click()
        owner.get_by_role("textbox", name="共有相手のプリンシパルID").fill(recipient["id"])
        owner.get_by_role("checkbox", name="内容を開く", exact=True).check()
        owner.get_by_role("button", name="権限を保存", exact=True).click()
        expect(owner.get_by_text("Variable reader", exact=True)).to_be_visible()
        reader.goto(ORIGIN + "/shared")
        reader.get_by_role("link", name="Shared variable", exact=True).click()
        reader.get_by_role("button", name="内容を表示", exact=True).click()
        expect(reader.get_by_role("textbox", name="値", exact=True)).to_have_value("browser-value")
        owner.get_by_role("listitem").filter(has_text="Variable reader").get_by_role("button", name="権限を解除", exact=True).click()
        expect(owner.get_by_text("Variable reader", exact=True)).to_be_hidden()
        resource_id = path.rsplit("/", 1)[1]
        self.assertEqual(reader.request.get(f"{ORIGIN}/api/resources/{resource_id}/custody").status, 403)

    def test_追加したパスキーでログインして保存済みの変数を復号する(self):
        page, principal = self.passkey_account("Existing account")
        cdp, authenticator_id = self.authenticators[page]
        original_credential = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator_id})["credentials"][0]["credentialId"]
        path = self.variable(page, principal, "Existing variable", "Saved variable value")
        page.get_by_role("button", name="ログアウト", exact=True).click()
        page.wait_for_url("**/signin")
        page.get_by_role("button", name="パスキーでログイン", exact=True).click()
        page.wait_for_url("**/p/**")
        page.goto(path)
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("Saved variable value")
        page.get_by_role("link", name="編集", exact=True).click()
        page.get_by_role("textbox", name="値", exact=True).fill("Edited existing variable")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("heading", name="Existing variable", exact=True)).to_be_visible()
        page.goto(ORIGIN + "/account")
        page.wait_for_load_state("networkidle")
        unlock = page.get_by_role("button", name="パスキーでロック解除", exact=True)
        with page.expect_response(lambda response: response.url.endswith("/auth/passkeys/verify")):
            unlock.click()
        expect(unlock).to_be_enabled()
        expect(page.get_by_text("この端末で暗号化された値を開けます。", exact=True)).to_be_visible()
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
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("Edited existing variable")
        page.screenshot(path=str(ARTIFACTS / "additional-passkey-ja.png"), full_page=True)

    def test_ブラウザで発行したキーでCLIにログインしブラウザが封じた変数を読む(self):
        import tempfile
        page, principal = self.passkey_account("Key issuer")
        path = self.variable(page, principal, "Issuer variable", "Issued through the browser")
        variable_id = path.rstrip("/").split("/")[-1]
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
                ["node", "cli/dist/cli.mjs", "read", variable_id],
                capture_output=True, text=True, env=environment,
            )
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout, "Issued through the browser")
        created = page.request.post(ORIGIN + "/api/principals", data={"name": "Keyless child", "ownerId": principal["id"]}, headers={"origin": ORIGIN})
        self.assertEqual(created.status, 201, created.text())
        child = created.json()
        self.assertIsNone(child["publicKey"])
        page.goto(ORIGIN + "/account/trust")
        owner_fingerprint = page.get_by_text(re.compile(r"^sha256:[0-9a-f]{64}$")).inner_text()
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
                ["node", "cli/dist/cli.mjs", "keep", "Child variable", "--stdin"],
                capture_output=True, text=True, env=environment, input="kept by the child",
            )
            self.assertEqual(kept.returncode, 0, kept.stderr)
            read = subprocess.run(
                ["node", "cli/dist/cli.mjs", "read", json.loads(kept.stdout)["id"]],
                capture_output=True, text=True, env=environment,
            )
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout, "kept by the child")

    def test_端末のログインをブラウザで許可すると端末が本人として入り変数を読む(self):
        import re, tempfile
        page, principal = self.passkey_account("Device approver")
        path = self.variable(page, principal, "Approver variable", "Read after device sign-in")
        variable_id = path.rstrip("/").split("/")[-1]
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
            read = subprocess.run(["node", "cli/dist/cli.mjs", "read", variable_id], capture_output=True, text=True, env=environment)
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertEqual(read.stdout, "Read after device sign-in")

    def test_ログイン方法の一覧に鍵の状態と使用中の印を示し発行したキーが鍵を持つ(self):
        page, principal = self.passkey_account("Credentials viewer")
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/credentials")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_text("この端末で暗号化された値を開けます。", exact=True)).to_be_visible()
        row = page.get_by_role("listitem").filter(has_text="Credentials viewer")
        expect(row.get_by_text("使用中", exact=True)).to_be_visible()
        expect(row.get_by_text("暗号化された値を開ける", exact=False)).to_be_visible()
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
        expect(key_row.get_by_text("暗号化された値を開ける", exact=False)).to_be_visible()
        expect(key_row.get_by_role("button", name="削除", exact=True)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "credentials-desktop-ja.png"), full_page=True)

    def test_期限の切れた許可が残る変数を鍵を持つブラウザが開いたときに外して封じ直す(self):
        import re, tempfile
        page, principal = self.passkey_account("Expiring owner")
        with tempfile.TemporaryDirectory() as home:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = home
            login = subprocess.Popen(["node", "cli/dist/cli.mjs", "login", "--name", "Expiring laptop", "--origin", ORIGIN],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
            shown = ""
            for _ in range(200):
                shown += login.stderr.readline()
                if "enter the code" in shown:
                    break
            page.goto(re.search(r"Open (\S+)", shown).group(1))
            page.get_by_role("textbox", name="確認コード", exact=True).fill(re.search(r"code ([A-Z0-9]{4}-[A-Z0-9]{4})", shown).group(1))
            page.get_by_role("button", name="許可", exact=True).click()
            login.communicate(timeout=60)
            self.assertEqual(login.returncode, 0)
            variable_id = str(uuid.uuid4())
            stored = subprocess.run(["node", "--import", "tsx", "--input-type=module", "-e", f"""
                import {{ readFile }} from 'node:fs/promises';
                import {{ ContentTypes, Operations, protect }} from './shared/custody.ts';
                const file = JSON.parse(await readFile('{home}/foundation/identity.json', 'utf8'));
                const me = file.identities.find(item => item.principalId === file.current);
                const grant = {{ actor: me.binding, executor: me.binding, operations: [Operations.command], functionDigests: [], origins: [],
                  callerProgram: true, expiresAt: new Date(Date.now() - 60_000).toISOString() }};
                const policy = {{ format: 2, origin: '{ORIGIN}', id: '{variable_id}', ownerId: me.principalId, contentType: ContentTypes.value,
                  revision: 1, authorities: [me.binding], readers: [me.binding], grants: [grant], producers: [] }};
                const content = await protect(new TextEncoder().encode('saved with an expired grant'), policy, 1, me.binding, me.keys);
                const response = await fetch('{ORIGIN}/api/resources/{variable_id}/custody', {{ method: 'PUT',
                  headers: {{ 'content-type': 'application/json', authorization: 'Bearer ' + me.token }},
                  body: JSON.stringify({{ name: 'Expiring token', content }}) }});
                if (!response.ok) throw new Error(await response.text());
            """], capture_output=True, text=True, env=environment)
            self.assertEqual(stored.returncode, 0, stored.stderr)
        pending = lambda: page.request.get(f"{ORIGIN}/api/principals/{principal['id']}/reprotection").json()["items"]
        self.assertEqual(pending(), [{"id": variable_id, "reason": "grantExpired"}])
        page.goto(f"{ORIGIN}/p/{principal['id']}/variables")
        for _ in range(50):
            if not pending():
                break
            page.wait_for_timeout(200)
        self.assertEqual(pending(), [])
        policy = page.request.get(f"{ORIGIN}/api/resources/{variable_id}/custody").json()["content"]["policy"]
        self.assertEqual(policy["grants"], [])
        page.goto(f"{ORIGIN}/p/{principal['id']}/variables/{variable_id}")
        page.get_by_role("button", name="内容を表示", exact=True).click()
        expect(page.get_by_role("textbox", name="値", exact=True)).to_have_value("saved with an expired grant")

    def test_メンバー追加と所有者変更で変数を引き継ぐ(self):
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
        variable_path = self.variable(owner, project, "Team variable", "team-variable-value")
        owner.goto(f"{ORIGIN}/p/{project['id']}/principals")
        owner.get_by_role("textbox", name="相手のプリンシパルID").fill(recipient["id"])
        self.select(owner, "関係", "メンバー")
        owner.get_by_role("button", name="追加", exact=True).click()
        expect(owner.get_by_text("Project member は Shared project のメンバー", exact=True)).to_be_visible()
        member.goto(variable_path)
        member.get_by_role("button", name="内容を表示", exact=True).click()
        expect(member.get_by_role("textbox", name="値", exact=True)).to_have_value("team-variable-value")
        owner.goto(f"{ORIGIN}/p/{project['id']}/settings/general")
        owner.get_by_role("textbox", name="新しい所有者のプリンシパルID").fill(new_owner["id"])
        owner.get_by_role("button", name="所有者を変更", exact=True).click()
        owner.wait_for_url("**/requests/*")
        change = "Shared project の所有者を Project successor に変更"
        expect(owner.get_by_text(change, exact=True)).to_be_visible()
        owner.screenshot(path=str(ARTIFACTS / "transfer-request-ja.png"), full_page=True)
        successor.goto(owner.url)
        expect(successor.get_by_text(change, exact=True)).to_be_visible()
        successor.screenshot(path=str(ARTIFACTS / "transfer-approve-ja.png"), full_page=True)
        successor.get_by_role("button", name="承認", exact=True).click()
        expect(successor.get_by_text("承認済み", exact=True)).to_be_visible()
        successor.goto(variable_path)
        successor.get_by_role("button", name="内容を表示", exact=True).click()
        expect(successor.get_by_role("textbox", name="値", exact=True)).to_have_value("team-variable-value")

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
        expect(page.get_by_text("Automation は Browser account の代理", exact=True)).to_be_visible()

    def test_所有するAIの接続を本人の一覧で検索し持ち主を確認して開く(self):
        page, principal = self.passkey_account("Connection owner")
        paid = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        created = page.request.post(ORIGIN + "/api/principals", data={
            "name": "dev-us の AI", "ownerId": principal["id"],
        }, headers={"origin": ORIGIN})
        self.assertTrue(created.ok, created.text())
        child = created.json()
        self.executor(page, child, "Owned AI executor")
        page.goto(f"{ORIGIN}/p/{child['id']}/services/new?method=github:token")
        page.get_by_role("textbox", name="名前", exact=True).fill("AI GitHub connection")
        page.get_by_label("Personal access token").fill("test-provider-token")
        self.select(page, "実行環境", "Owned AI executor")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AI GitHub connection")
        connection_path = page.url
        page.goto(f"{ORIGIN}/p/{principal['id']}/services")
        page.wait_for_load_state("networkidle")
        row = page.get_by_role("row").filter(has=page.get_by_role("link", name="AI GitHub connection", exact=True))
        expect(row.get_by_text("所有者:", exact=False)).to_be_visible()
        expect(row.get_by_role("link", name="dev-us の AI", exact=True)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "owned-connections-desktop-ja.png"), full_page=True, animations="disabled")
        page.get_by_role("searchbox", name="検索", exact=True).fill("AI GitHub")
        page.get_by_role("button", name="検索", exact=True).click()
        expect(row).to_be_visible()
        page.reload()
        expect(row.get_by_role("link", name="dev-us の AI", exact=True)).to_be_visible()
        self.select(page, "言語", "English")
        page.set_viewport_size({"width": 390, "height": 844})
        page.wait_for_load_state("networkidle")
        expect(row.get_by_text("Owner:", exact=False)).to_be_visible()
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.screenshot(path=str(ARTIFACTS / "owned-connections-mobile-en.png"), full_page=True, animations="disabled")
        row.get_by_role("link", name="AI GitHub connection", exact=True).click()
        expect(page.get_by_role("heading", name="AI GitHub connection", exact=True)).to_be_visible()
        self.assertEqual(page.url, connection_path)

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
        application_edit_path = page.url
        page.goto(root + "/services/new?method=" + method_id)
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("combobox", name="接続方法", exact=True)).to_have_text("Workspace sign-in")
        expect(page.get_by_role("combobox", name="OAuthアプリ", exact=True)).to_have_text("Workspace application")
        expect(page.get_by_role("button", name="接続する", exact=True)).to_be_enabled()
        page.screenshot(path=str(ARTIFACTS / "connection-oauth-app-ja.png"), full_page=True, animations="disabled")
        catalog = page.request.get(ORIGIN + "/api/connection-methods").json()
        catalog["items"] = [method for method in catalog["items"] if method["id"] != method_id]
        page.route(ORIGIN + "/api/connection-methods", lambda route: route.fulfill(json=catalog))
        page.goto(application_edit_path)
        expect(page.get_by_label("クライアントID", exact=True)).to_have_value("browser-client")
        expect(page.get_by_label("クライアントシークレット", exact=True)).to_be_visible()
        expect(page.get_by_label("コールバックURL", exact=True)).to_have_value(ORIGIN + "/oauth/callback")

    def test_アプリ認証の案内を示し保存済みのアプリでOVHへ接続し再接続する(self):
        page, principal = self.passkey_account("Application owner")
        environment_path = self.executor(page, principal)
        environment_id = environment_path.rsplit("/", 1)[1]
        root = f"{ORIGIN}/p/{principal['id']}"
        page.goto(root + "/apps/new?method=ovh:client_credentials_ca")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_text("アカウントを登録したAPI接続先（EU・CA・US）を選んでください。", exact=False)).to_be_visible()
        page.get_by_role("textbox", name="名前", exact=True).fill("OVH application")
        page.get_by_label("クライアントID", exact=True).fill("browser-client")
        page.get_by_label("クライアントシークレット", exact=True).fill("browser-client-secret")
        page.get_by_role("checkbox", name="Browser executor", exact=True).check()
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="OVH application", exact=True)).to_be_visible()
        application_path = page.url
        application_id = application_path.rsplit("/", 1)[1]
        before = page.request.get(ORIGIN + "/api/resources/" + application_id).json()
        page.get_by_role("link", name="編集", exact=True).click()
        expect(page.get_by_label("クライアントID", exact=True)).to_have_value("browser-client")
        page.get_by_role("textbox", name="名前", exact=True).fill("Saved OVH application")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("heading", name="Saved OVH application", exact=True)).to_be_visible()
        after = page.request.get(ORIGIN + "/api/resources/" + application_id).json()
        self.assertEqual(after["data"]["generation"], before["data"]["generation"])
        self.assertEqual(after["data"]["methodId"], "ovh:client_credentials_ca")
        page.goto(root + "/services/new?method=ovh:client_credentials_ca")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("combobox", name="OAuthアプリ", exact=True)).to_have_text("Saved OVH application")
        expect(page.get_by_label("スコープ", exact=True)).to_have_value("all")
        self.select(page, "実行環境", "Browser executor")
        page.get_by_role("textbox", name="名前", exact=True).fill("OVH account")
        page.screenshot(path=str(ARTIFACTS / "connection-ovh-preparation-ja.png"), full_page=True, animations="disabled")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "OVH account")
        connection_path = page.url
        page.get_by_role("link", name="再接続", exact=True).click()
        expect(page.get_by_role("combobox", name="OAuthアプリ", exact=True)).to_have_text("Saved OVH application")
        expect(page.get_by_label("スコープ", exact=True)).to_have_value("all")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "OVH account")
        self.assertEqual(page.url, connection_path)
        requests = page.request.get(ORIGIN + "/__test/executor/" + environment_id + "/oauth").json()
        self.assertEqual(requests, [{"clientId": "browser-client", "clientSecret": "browser-client-secret", "scope": "all"}] * 2)
        page.goto(root + "/apps/new?method=shopify:client_credentials")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_text("自分のShopify組織のストアにインストール済みのアプリを使用してください。", exact=False)).to_be_visible()
        page.get_by_label("ストア名", exact=True).fill("example")
        self.select(page, "言語", "English")
        page.set_viewport_size({"width": 390, "height": 844})
        page.wait_for_load_state("networkidle")
        expect(page.get_by_text("Use an app installed on a store in your own Shopify organization.", exact=False)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "connection-shopify-preparation-en.png"), full_page=True, animations="disabled")

    def test_選んだ実行先のAWSの身元を信頼するIAMロールをAWSで作るリンクを示す(self):
        page, principal = self.passkey_account()
        self.executor(page, principal)
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        self.select(page, "認証方法", "実行環境のAWS認証")
        page.get_by_role("checkbox", name="別のIAMロールを使う", exact=True).check()
        self.select(page, "実行環境", "Browser executor")
        link = page.get_by_role("link", name="AWSでIAMロールを作る", exact=True)
        expect(link).to_be_visible()
        href = link.get_attribute("href")
        self.assertIn("console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/create/review?", href)
        self.assertIn("templateURL=https%3A%2F%2Fobjects.example%2Fpublished%2Faws-connection.yaml", href)
        self.assertIn("param_PrincipalArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fservice%2Ffoundation-test-executor", href)
        external_id = re.search(r"param_ExternalId=([0-9a-f]{32})", href).group(1)
        self.assertEqual(page.get_by_label("External ID", exact=True).input_value(), external_id)
        page.get_by_label("External ID", exact=True).fill("edited-external-id")
        page.get_by_label("リージョン", exact=True).fill("us-west-2")
        expect(link).to_have_attribute("href", re.compile(r"home\?region=us-west-2#.*param_ExternalId=edited-external-id"))
        self.select(page, "サービス", "Render")
        expect(page.get_by_label("API key", exact=True)).to_be_visible()
        self.select(page, "サービス", "AWS")
        expect(page.get_by_label("External ID", exact=True)).to_have_value("edited-external-id")
        expect(page.get_by_label("リージョン", exact=True)).to_have_value("us-west-2")
        expect(page.get_by_role("combobox", name="実行環境", exact=True)).to_have_text("Browser executor")
        expect(link).to_have_attribute("href", re.compile(r"home\?region=us-west-2#.*param_ExternalId=edited-external-id"))
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(ARTIFACTS / "connection-aws-role-ja.png"), full_page=True, animations="disabled")

    def test_AWS接続を保存し再接続でロール設定と共有先を引き継ぐ(self):
        page, principal = self.passkey_account("AWS owner")
        reader, recipient = self.passkey_account("AWS reader")
        self.trust(page, reader, recipient)
        self.trust(reader, page, principal)
        environment_path = self.executor(page, principal)
        environment_id = environment_path.rsplit("/", 1)[1]
        role = {"arn": "arn:aws:iam::123456789012:role/team/Example", "region": "us-west-2",
                "externalId": "saved-external-id"}
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        self.select(page, "認証方法", "実行環境のAWS認証")
        page.get_by_role("checkbox", name="別のIAMロールを使う", exact=True).check()
        self.select(page, "実行環境", "Browser executor")
        page.get_by_role("textbox", name="名前", exact=True).fill("AWS account")
        page.get_by_label("IAMロールのARN", exact=True).fill(role["arn"])
        page.get_by_label("リージョン", exact=True).fill(role["region"])
        page.get_by_label("External ID", exact=True).fill(role["externalId"])
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AWS account")
        connection_path = page.url
        connection_id = connection_path.rsplit("/", 1)[1]
        page.get_by_role("link", name="共有", exact=True).click()
        page.get_by_role("textbox", name="共有相手のプリンシパルID").fill(recipient["id"])
        page.get_by_role("checkbox", name="内容を開く", exact=True).check()
        page.get_by_role("button", name="権限を保存", exact=True).click()
        expect(page.get_by_text("AWS reader", exact=True)).to_be_visible()
        before = page.request.get(ORIGIN + "/api/resources/" + connection_id + "/custody").json()["content"]["policy"]
        page.goto(connection_path)
        page.get_by_role("link", name="再接続", exact=True).click()
        expect(page.get_by_label("IAMロールのARN", exact=True)).to_have_value(role["arn"])
        expect(page.get_by_label("リージョン", exact=True)).to_have_value(role["region"])
        expect(page.get_by_label("External ID", exact=True)).to_have_value(role["externalId"])
        expect(page.get_by_role("combobox", name="実行環境", exact=True)).to_have_text("Browser executor")
        link = page.get_by_role("link", name="AWSでIAMロールを作る", exact=True)
        expect(link).to_have_attribute("href", re.compile(r"home\?region=us-west-2#.*param_ExternalId=saved-external-id"))
        page.screenshot(path=str(ARTIFACTS / "connection-aws-reconnect-ja.png"), full_page=True, animations="disabled")
        print("Rendered AWS reconnect: " + page.locator("main").inner_text(), flush=True)
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AWS account")
        self.assertEqual(page.url, connection_path)
        requests = page.request.get(ORIGIN + "/__test/executor/" + environment_id + "/roles").json()
        self.assertGreaterEqual(len(requests), 2)
        self.assertTrue(all(request == role for request in requests), requests)
        after = page.request.get(ORIGIN + "/api/resources/" + connection_id + "/custody").json()["content"]["policy"]
        self.assertEqual(after["readers"], before["readers"])
        self.assertEqual(after["authorities"], before["authorities"])
        self.assertEqual([grant["executor"] for grant in after["grants"]], [grant["executor"] for grant in before["grants"]])
        self.assertTrue(reader.request.get(ORIGIN + "/api/resources/" + connection_id + "/custody").ok)

    def test_AWSの身元が未確認の実行先を案内し既存ロールの接続を確認する(self):
        page, principal = self.passkey_account("AWS identity owner")
        self.executor(page, principal)

        def unconfirmed_identity(route):
            response = route.fetch()
            data = response.json()
            for item in data["items"]:
                item["data"].pop("awsPrincipal", None)
            route.fulfill(response=response, json=data)

        page.route(re.compile(r"/api/principals/[^/]+/resources\?kind=environment"), unconfirmed_identity)
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        self.select(page, "認証方法", "実行環境のAWS認証")
        page.get_by_role("checkbox", name="別のIAMロールを使う", exact=True).check()
        self.select(page, "実行環境", "Browser executor")
        expect(page.get_by_text("選んだ実行環境のAWSの身元を確認できません。", exact=False)).to_be_visible()
        page.get_by_role("textbox", name="名前", exact=True).fill("Existing AWS role")
        page.get_by_label("IAMロールのARN", exact=True).fill("arn:aws:iam::123456789012:role/team/Existing")
        page.get_by_label("External ID", exact=True).fill("existing-external-id")
        page.screenshot(path=str(ARTIFACTS / "connection-aws-unconfirmed-ja.png"), full_page=True, animations="disabled")
        print("Rendered AWS identity notice: " + page.get_by_role("alert").inner_text(), flush=True)
        self.select(page, "言語", "English")
        expect(page.get_by_text("Could not verify the chosen environment's AWS identity.", exact=False)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "connection-aws-unconfirmed-en.png"), full_page=True, animations="disabled")
        self.select(page, "Language", "日本語")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "Existing AWS role")

    def test_AWSアクセスキーを保存し再接続で認証情報を引き継いで更新する(self):
        page, principal = self.passkey_account("AWS access key owner")
        environment_id = self.executor(page, principal).rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        expect(page.get_by_role("combobox", name="認証方法", exact=True)).to_have_text("アクセスキー")
        page.get_by_role("textbox", name="名前", exact=True).fill("AWS keys")
        page.get_by_label("アクセスキーID", exact=True).fill("browser-access-key")
        page.get_by_label("シークレットアクセスキー", exact=True).fill("browser-access-secret")
        page.get_by_label("リージョン", exact=True).fill("us-west-2")
        self.select(page, "実行環境", "Browser executor")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(ARTIFACTS / "connection-aws-access-key-ja.png"), full_page=True, animations="disabled")
        print("Rendered AWS keys: " + page.locator("main").inner_text(), flush=True)
        self.select(page, "言語", "English")
        expect(page.get_by_role("combobox", name="Authentication method", exact=True)).to_have_text("Access keys")
        page.set_viewport_size({"width": 390, "height": 844})
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.screenshot(path=str(ARTIFACTS / "connection-aws-access-key-en.png"), full_page=True, animations="disabled")
        self.select(page, "Language", "日本語")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_text("AWSの認証元", exact=True)).to_be_visible()
        expect(page.get_by_text("arn:aws:iam::123456789012:user/browser-operator", exact=True)).to_be_visible()
        self.accept_connection(page, "AWS keys")
        connection_path = page.url
        connection_id = connection_path.rsplit("/", 1)[1]
        resource = page.request.get(ORIGIN + "/api/resources/" + connection_id).json()
        self.assertEqual(resource["data"]["aws"], {"authentication": "access_key", "region": "us-west-2",
                         "sourceAccountId": "123456789012", "sourceArn": "arn:aws:iam::123456789012:user/browser-operator"})
        page.get_by_role("link", name="再接続", exact=True).click()
        expect(page.get_by_label("アクセスキーID", exact=True)).to_have_value("browser-access-key")
        expect(page.get_by_label("シークレットアクセスキー", exact=True)).to_have_value("")
        expect(page.get_by_label("リージョン", exact=True)).to_have_value("us-west-2")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AWS keys")
        self.assertEqual(page.url, connection_path)
        page.get_by_role("link", name="再接続", exact=True).click()
        page.get_by_label("アクセスキーID", exact=True).fill("updated-access-key")
        page.get_by_label("シークレットアクセスキー", exact=True).fill("updated-access-secret")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AWS keys")
        requests = page.request.get(ORIGIN + "/__test/executor/" + environment_id + "/aws").json()
        self.assertEqual([item["authentication"] for item in requests], [
            {"kind": "access_key", "accessKeyId": "browser-access-key", "secretAccessKey": "browser-access-secret"},
            {"kind": "access_key", "accessKeyId": "browser-access-key", "secretAccessKey": "browser-access-secret"},
            {"kind": "access_key", "accessKeyId": "updated-access-key", "secretAccessKey": "updated-access-secret"}])

    def test_AWS一時認証情報で追加ロールを保存し期限切れ時に再接続を案内する(self):
        from datetime import datetime, timezone
        page, principal = self.passkey_account("AWS temporary credentials owner")
        environment_id = self.executor(page, principal).rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        self.select(page, "認証方法", "一時認証情報")
        page.get_by_role("textbox", name="名前", exact=True).fill("AWS temporary role")
        page.get_by_label("アクセスキーID", exact=True).fill("temporary-key")
        page.get_by_label("シークレットアクセスキー", exact=True).fill("temporary-secret")
        page.get_by_label("セッショントークン", exact=True).fill("temporary-session")
        expiration = datetime.fromtimestamp(time.time() + 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M")
        page.get_by_label("有効期限", exact=True).fill(expiration)
        page.get_by_role("checkbox", name="別のIAMロールを使う", exact=True).check()
        page.get_by_label("IAMロールのARN", exact=True).fill("arn:aws:iam::999999999999:role/team/Example")
        self.select(page, "実行環境", "Browser executor")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(ARTIFACTS / "connection-aws-session-role-ja.png"), full_page=True, animations="disabled")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("heading", name="接続先と権限を確認して保存", exact=True)).to_be_visible(timeout=15000)
        expect(page.get_by_text("一時認証情報", exact=True)).to_be_visible()
        self.accept_connection(page, "AWS temporary role")
        page.get_by_role("link", name="再接続", exact=True).click()
        expect(page.get_by_label("有効期限", exact=True)).to_have_value(expiration)
        expect(page.get_by_label("IAMロールのARN", exact=True)).to_have_value("arn:aws:iam::999999999999:role/team/Example")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AWS temporary role")
        requests = page.request.get(ORIGIN + "/__test/executor/" + environment_id + "/aws").json()
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0], requests[1])
        page.get_by_role("link", name="再接続", exact=True).click()
        page.get_by_label("有効期限", exact=True).fill("2020-01-01T00:00")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("alert").filter(has_text="サービスに再接続してください。")).to_be_visible(timeout=15000)

    def test_実行環境のAWS認証で追加ロールを指定せず接続を保存する(self):
        page, principal = self.passkey_account("AWS environment credentials owner")
        environment_id = self.executor(page, principal).rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=aws:role")
        self.select(page, "認証方法", "実行環境のAWS認証")
        page.get_by_role("textbox", name="名前", exact=True).fill("AWS environment")
        self.select(page, "実行環境", "Browser executor")
        page.get_by_role("button", name="接続する", exact=True).click()
        self.accept_connection(page, "AWS environment")
        requests = page.request.get(ORIGIN + "/__test/executor/" + environment_id + "/aws").json()
        self.assertEqual(requests, [{"authentication": {"kind": "environment"}, "region": "ap-northeast-1"}])

    def test_スマホで初期値のまま実行環境を起動して停止する(self):
        owner, principal = self.passkey_account("Mobile environment owner")
        response = owner.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(response.ok, response.text())
        page = self.page(webkit=True, mobile=True)
        page.context.add_cookies(owner.context.cookies())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.wait_for_load_state("networkidle")
        start = page.get_by_role("button", name="起動", exact=True)
        for scroll in [0, 10000, 0]:
            page.evaluate("value => window.scrollTo(0, value)", scroll)
            box = start.bounding_box()
            self.assertIsNotNone(box)
            self.assertGreaterEqual(box["y"], 0)
            self.assertLessEqual(box["y"] + box["height"], page.evaluate("window.innerHeight"))
        start.click()
        page.wait_for_url(re.compile(r"/environments/[a-f0-9-]{36}$"))
        environment_id = page.url.rsplit("/", 1)[1]
        self.environments.append((page, environment_id))
        expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
        response = page.request.get(ORIGIN + "/api/resources/" + environment_id)
        self.assertTrue(response.ok, response.text())
        environment = response.json()
        self.assertTrue(environment["name"])
        self.assertEqual(environment["data"]["size"], "small")
        self.assertEqual(environment["data"]["lifetime"], {"idleSeconds": 3600, "maxSeconds": 3600})
        page.get_by_role("button", name="停止", exact=True).click()
        page.get_by_role("dialog").get_by_role("button", name="停止", exact=True).click()
        expect(page.get_by_text("停止済み", exact=True)).to_be_visible(timeout=15000)

    def test_スマホでSSH公開鍵を指定して接続情報を確認し公開鍵を変更する(self):
        import tempfile
        owner, principal = self.passkey_account("SSH environment owner")
        paid = owner.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        page = self.page(webkit=True, mobile=True)
        page.context.add_cookies(owner.context.cookies())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        keys = page.get_by_role("textbox", name="SSH公開鍵（任意）", exact=True)
        expect(keys).to_be_visible()
        keys.fill("invalid key")
        page.get_by_role("button", name="起動", exact=True).click()
        expect(page.get_by_role("alert").filter(has_text="SSH公開鍵を確認してください")).to_be_visible()
        with tempfile.TemporaryDirectory() as directory:
            public_keys = []
            for name in ["first", "second"]:
                path = Path(directory) / name
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
                public_keys.append(path.with_suffix(".pub").read_text().strip())
            keys.fill(public_keys[0])
            page.get_by_role("button", name="起動", exact=True).click()
            page.wait_for_url(re.compile(r"/environments/[a-f0-9-]{36}$"))
            environment_id = page.url.rsplit("/", 1)[1]
            self.environments.append((page, environment_id))
            expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
            expect(page.locator("code").filter(has_text="root@ssh.foundation.test")).to_be_visible()
            expect(page.get_by_text("SSHホスト鍵の指紋", exact=True)).to_be_visible(timeout=20000)
            editor = page.get_by_role("textbox", name="SSH公開鍵", exact=True)
            expect(editor).to_have_value(public_keys[0])
            editor.fill(public_keys[1])
            editor.locator("xpath=ancestor::form").get_by_role("button", name="保存", exact=True).click()
            expect(page.get_by_text("SSH公開鍵を保存しました。", exact=True)).to_be_visible()
            response = page.request.get(ORIGIN + "/api/environments/" + environment_id + "/ssh")
            self.assertTrue(response.ok, response.text())
            self.assertEqual(response.json()["authorizedKeys"], [public_keys[1]])
            self.assertEqual(response.json()["workingDirectory"], "/workspace")
            page.reload()
            expect(editor).to_have_value(public_keys[1])
            self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
            print("Rendered SSH: " + editor.locator("xpath=ancestor::*[@data-slot='card']").inner_text(), flush=True)
            self.select(page, "言語", "English")
            expect(page.get_by_text("SSH host key fingerprint", exact=True)).to_be_visible()

    def test_ファイルを保存して実行環境を起動して停止する(self):
        page, principal = self.passkey_account()
        response = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(response.ok, response.text())
        page.goto(f"{ORIGIN}/p/{principal['id']}/objects/new")
        page.locator('input[name="file"]').set_input_files({"name": "report.txt", "mimeType": "text/plain", "buffer": b"browser file"})
        page.get_by_role("button", name="アップロード", exact=True).click()
        expect(page.get_by_role("heading", name="report.txt", exact=True)).to_be_visible()
        breadcrumb = page.get_by_role("navigation", name="現在の位置", exact=True)
        expect(breadcrumb.get_by_text("report.txt", exact=True)).to_be_visible()
        breadcrumb.get_by_role("link", name="ファイル", exact=True).click()
        page.wait_for_url(f"**/p/{principal['id']}/objects")
        page.get_by_role("link", name="report.txt", exact=True).click()
        with page.expect_download() as download:
            page.get_by_role("link", name="ダウンロード", exact=True).click()
        self.assertEqual(Path(download.value.path()).read_text(), "browser file")
        self.executor(page, principal, "Worker")
        page.get_by_role("button", name="停止", exact=True).click()
        page.get_by_role("dialog").get_by_role("button", name="停止", exact=True).click()
        expect(page.get_by_text("停止済み", exact=True)).to_be_visible(timeout=15000)

    def test_スマホで一覧と詳細を行き来し削除中の表示を再読込後も確認して削除を完了する(self):
        owner, principal = self.passkey_account("Mobile deletion owner")
        path = self.executor(owner, principal, "Mobile deletion environment")
        environment_id = path.rsplit("/", 1)[1]
        page = self.page(webkit=True, mobile=True)
        page.context.add_cookies(owner.context.cookies())
        page.goto(path)
        page.wait_for_load_state("networkidle")
        page.get_by_role("link", name="実行環境の一覧へ戻る", exact=True).click()
        page.wait_for_url(f"**/p/{principal['id']}/environments")
        page.get_by_role("link", name="Mobile deletion environment", exact=True).click()
        breadcrumb = page.get_by_role("navigation", name="現在の位置", exact=True)
        expect(breadcrumb.get_by_text("Mobile deletion environment", exact=True)).to_be_visible()
        breadcrumb.get_by_role("link", name="実行環境", exact=True).click()
        page.wait_for_url(f"**/p/{principal['id']}/environments")
        page.get_by_role("link", name="Mobile deletion environment", exact=True).click()
        page.request.post(ORIGIN + "/__test/deletion/" + environment_id, data={"phase": "stop", "mode": "hold"})
        delete_requests = []
        page.on("request", lambda request: delete_requests.append(request) if request.method == "DELETE" and request.url.endswith(environment_id) else None)
        try:
            page.get_by_role("button", name="削除", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.get_by_role("button", name="削除", exact=True).click()
            expect(dialog.get_by_role("button", name="削除中…", exact=True)).to_be_disabled()
            expect(dialog.get_by_role("status")).to_contain_text("画面を閉じても処理は続きます")
            page.reload()
            expect(page.get_by_role("button", name="削除中…", exact=True)).to_be_disabled()
            expect(page.get_by_role("status")).to_contain_text("画面を閉じても処理は続きます")
            page.get_by_role("link", name="実行環境の一覧へ戻る", exact=True).click()
            expect(page.get_by_text("削除中", exact=True)).to_be_visible()
            page.get_by_role("link", name="Mobile deletion environment", exact=True).click()
            expect(page.get_by_role("button", name="削除中…", exact=True)).to_be_disabled()
            self.assertEqual(len(delete_requests), 1)
        finally:
            page.request.post(ORIGIN + "/__test/deletion/" + environment_id, data={"phase": "stop", "mode": "release"})
        page.wait_for_url(f"**/p/{principal['id']}/environments?deleted=1", timeout=15000)
        expect(page.get_by_role("alert")).to_contain_text("実行環境を削除しました")
        response = page.request.get(ORIGIN + "/api/resources/" + environment_id + "/deletion")
        self.assertEqual(response.json()["state"], "complete")

    def test_削除の失敗理由を確認画面に表示し再試行して一覧へ戻る(self):
        page, principal = self.passkey_account("Deletion retry owner")
        path = self.executor(page, principal, "Retry deletion environment")
        page.set_viewport_size({"width": 390, "height": 844})
        environment_id = path.rsplit("/", 1)[1]
        page.request.post(ORIGIN + "/__test/deletion/" + environment_id, data={"phase": "volume", "mode": "fail"})
        page.get_by_role("button", name="削除", exact=True).click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_role("button", name="削除", exact=True).click()
        expect(dialog.get_by_role("button", name="削除を再試行", exact=True)).to_be_enabled(timeout=15000)
        expect(dialog.get_by_role("alert")).to_contain_text("ディスクの削除を完了できませんでした")
        page.screenshot(path=str(ARTIFACTS / "environment-delete-error-ja.png"), full_page=True)
        page.reload()
        expect(page.get_by_role("alert")).to_contain_text("ディスクの削除を完了できませんでした")
        page.get_by_role("button", name="削除を再試行", exact=True).click()
        expect(dialog.get_by_role("button", name="削除を再試行", exact=True)).to_be_enabled()
        dialog.get_by_role("button", name="削除を再試行", exact=True).click()
        page.wait_for_url(f"**/p/{principal['id']}/environments?deleted=1", timeout=15000)
        expect(page.get_by_role("alert")).to_contain_text("実行環境を削除しました")

    def test_実行環境を作成してプリンシパルへ共有し権限を解除する(self):
        page, principal = self.passkey_account("Environment owner")
        recipient, other = self.passkey_account("Shared principal")
        page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(ARTIFACTS / "environment-create-ja.png"), full_page=True)
        page.get_by_role("button", name="起動", exact=True).click()
        page.wait_for_url(re.compile(r"/environments/[a-f0-9-]{36}$"))
        path = page.url
        environment_id = path.rsplit("/", 1)[1]
        self.environments.append((page, environment_id))
        expect(page.get_by_role("heading", name=re.compile(r"^実行環境 [a-f0-9]{8}$"))).to_be_visible()
        expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
        name = page.get_by_role("heading", level=1).inner_text()
        page.get_by_role("link", name="共有", exact=True).click()
        page.get_by_role("textbox", name="共有相手のプリンシパルID", exact=True).fill(other["id"])
        page.get_by_role("checkbox", name="実行する", exact=True).check()
        page.get_by_role("button", name="権限を保存", exact=True).click()
        expect(page.get_by_text("Shared principal", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="権限を付与したプリンシパル", exact=True)).to_be_visible()
        page.screenshot(path=str(ARTIFACTS / "environment-sharing-ja.png"), full_page=True)
        recipient.goto(path)
        expect(recipient.get_by_role("heading", name=name, exact=True)).to_be_visible()
        shared = recipient.request.get(ORIGIN + "/api/resources/" + environment_id)
        self.assertTrue(shared.ok, shared.text())
        self.assertIn("execute", shared.json()["permissions"])
        page.get_by_role("button", name="権限を解除", exact=True).click()
        expect(page.get_by_text("項目がありません。", exact=True)).to_be_visible()
        self.assertEqual(recipient.request.get(ORIGIN + "/api/resources/" + environment_id).status, 403)
        page.get_by_role("navigation", name="現在の位置", exact=True).get_by_role("link", name=name, exact=True).click()
        page.wait_for_url(path)
        page.get_by_role("navigation", name="現在の位置", exact=True).get_by_role("link", name="実行環境", exact=True).click()
        page.wait_for_url(f"**/p/{principal['id']}/environments")

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
