import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import urllib.request
import uuid
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright, expect

from browser_shards import select_shard


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
        page.get_by_role("button", name="アカウントを作成", exact=True).click()
        page.get_by_role("textbox", name="名前", exact=True).fill(name)
        page.get_by_role("button", name="パスキーを作成", exact=True).click()
        page.wait_for_url("**/p/**")
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
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
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
        path = page.url
        self.environments.append((page, path.rsplit('/', 1)[1]))
        fingerprint = page.request.get(ORIGIN + "/__test/executor/" + path.rsplit("/", 1)[1] + "/fingerprint").json()
        self.trust_fingerprint(page, fingerprint["id"], fingerprint["fingerprint"])
        return path

    def saved_connection(self, page, name):
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible(timeout=15000)
        page.wait_for_url("**/services/*")
        return page.request.get(ORIGIN + "/api/resources/" + page.url.rsplit("/", 1)[1]).json()

    def allow_environment(self, page, name="Browser executor"):
        page.get_by_text("実行環境での利用を許可する（任意）", exact=True).click()
        page.get_by_role("checkbox", name=name, exact=True).check()

    def test_AIが出した指紋付きのリンクで承認するとAIの公開鍵を検証して代理にし持ち主の変数を開かせる(self):
        owner, principal = self.passkey_account("Linked owner")
        variable_id = self.variable(owner, principal, "Linked variable", "linked-variable-value").rstrip("/").rsplit("/", 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = directory
            def cli(*arguments):
                result = subprocess.run(["node", "cli/dist/cli.mjs", *arguments], capture_output=True, text=True, env=environment, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout) if result.stdout.startswith("{") else result.stdout
            agent = cli("init", "--name", "Linked AI", "--origin", ORIGIN)
            url = cli("join", "--to", principal["id"])["url"]
            self.assertTrue(url.endswith("#fingerprint=" + agent["fingerprint"]), url)
            owner.goto(url.replace(agent["fingerprint"], "sha256:" + "0" * 64))
            owner.get_by_role("button", name="承認", exact=True).click()
            expect(owner.get_by_text("公開鍵の指紋が一致しません。相手に現在の指紋を確認してください。", exact=True)).to_be_visible()
            owner.goto(ORIGIN + "/account/trust?principal=" + agent["principal"]["id"] + "#fingerprint=" + agent["fingerprint"])
            expect(owner.get_by_role("textbox", name="公開鍵の指紋", exact=True)).to_have_value(agent["fingerprint"])
            owner.goto(url)
            owner.get_by_role("button", name="承認", exact=True).click()
            expect(owner.get_by_text("承諾済み", exact=True)).to_be_visible()
            owner.goto(ORIGIN + "/account/trust")
            owner_fingerprint = owner.get_by_text(re.compile(r"^sha256:[0-9a-f]{64}$")).inner_text()
            cli("trust", principal["id"], "--fingerprint", owner_fingerprint)
            self.assertEqual(cli("read", variable_id), "linked-variable-value")

    def test_所有するAIの実行結果を本人の鍵で表示しログイン後にも読み出す(self):
        owner, principal = self.passkey_account("Chancellor Rigel")
        paid = owner.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        response = owner.request.post(ORIGIN + "/api/principals", data={"ownerId": principal["id"], "name": "dev-us の AI"}, headers={"origin": ORIGIN})
        self.assertTrue(response.ok, response.text())
        agent = response.json()
        environment_id = self.executor(owner, agent, "dev-us").rsplit("/", 1)[1]
        owner.goto(f"{ORIGIN}/p/{agent['id']}/settings/credentials/new?kind=key")
        owner.get_by_role("textbox", name="名前", exact=True).fill("Execution agent")
        owner.get_by_role("button", name="追加", exact=True).click()
        token = owner.get_by_role("textbox", name="APIキー", exact=True).input_value()
        with tempfile.TemporaryDirectory() as directory:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = directory
            login = subprocess.run(["node", "cli/dist/cli.mjs", "login", "--key", "@-", "--origin", ORIGIN],
                capture_output=True, text=True, input=token, env=environment, timeout=30)
            self.assertEqual(login.returncode, 0, login.stderr)
            fingerprint = subprocess.run(["node", "--import", "tsx", "--input-type=module", "-e", """
                import { readFile } from 'node:fs/promises';
                import { join } from 'node:path';
                import { fingerprint } from './shared/authority.ts';
                const data = JSON.parse(await readFile(join(process.env.XDG_CONFIG_HOME, 'foundation/identity.json'), 'utf8'));
                console.log(await fingerprint(data.identities.find(item => item.principalId === data.current).binding));
            """], capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(fingerprint.returncode, 0, fingerprint.stderr)
            self.trust_fingerprint(owner, agent["id"], fingerprint.stdout.strip())
            owner.goto(ORIGIN + "/account/trust")
            owner_fingerprint = owner.get_by_text(re.compile(r"^sha256:[0-9a-f]{64}$")).inner_text()
            executor = owner.request.get(ORIGIN + "/__test/executor/" + environment_id + "/fingerprint").json()
            for identity_id, value in [(principal["id"], owner_fingerprint), (executor["id"], executor["fingerprint"])]:
                trusted = subprocess.run(["node", "cli/dist/cli.mjs", "trust", identity_id, "--fingerprint", value],
                    capture_output=True, text=True, env=environment, timeout=30)
                self.assertEqual(trusted.returncode, 0, trusted.stderr)
            executed = subprocess.run(["node", "cli/dist/cli.mjs", "run", "--environment", environment_id, "--wait", "--timeout", "20", "--",
                "node", "-e", 'console.log("本人の鍵で読める実行結果です。");'],
                capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            execution_id = json.loads(executed.stdout)["id"]
        owner.evaluate("""async id => {
            const db = await new Promise((resolve, reject) => {
                const request = indexedDB.open('foundation-keys', 2);
                request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
            });
            await new Promise((resolve, reject) => {
                const transaction = db.transaction('keys', 'readwrite');
                transaction.objectStore('keys').delete('v2:' + id);
                transaction.oncomplete = resolve; transaction.onerror = () => reject(transaction.error);
            });
            db.close();
        }""", agent["id"])
        path = ORIGIN + "/executions/" + execution_id
        owner.goto(path)
        expect(owner.get_by_role("heading", name="実行の詳細", exact=True)).to_be_visible()
        expect(owner.locator("main pre")).to_have_text("本人の鍵で読める実行結果です。\n")
        owner.screenshot(path=str(ARTIFACTS / "execution-owner-output-ja.png"), full_page=True)
        print("Rendered execution for its owner: " + owner.locator("main").inner_text(), flush=True)
        signed_out = owner.request.post(ORIGIN + "/api/auth/signout", data={}, headers={"origin": ORIGIN})
        self.assertTrue(signed_out.ok, signed_out.text())
        owner.evaluate("""async () => {
            const db = await new Promise(resolve => {
                const request = indexedDB.open('foundation-keys', 2); request.onsuccess = () => resolve(request.result);
            });
            await new Promise(resolve => {
                const transaction = db.transaction('keys', 'readwrite');
                transaction.objectStore('keys').clear(); transaction.oncomplete = resolve;
            });
            db.close();
        }""")
        owner.goto(path)
        owner.wait_for_url("**/signin?returnTo=**")
        owner.get_by_role("button", name="パスキーでログイン", exact=True).click()
        owner.wait_for_url(path)
        expect(owner.locator("main pre")).to_have_text("本人の鍵で読める実行結果です。\n")
        owner.set_viewport_size({"width": 390, "height": 844})
        owner.screenshot(path=str(ARTIFACTS / "execution-owner-output-after-signin-mobile-ja.png"), full_page=True)

    def test_完了した実行の処理と時刻を表示し鍵に応じて出力を案内する(self):
        page, principal = self.passkey_account("Execution initiator")
        environment_id = self.executor(page, principal, "dev-us").rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/credentials/new?kind=key")
        page.get_by_role("textbox", name="名前", exact=True).fill("Execution test key")
        page.get_by_role("button", name="追加", exact=True).click()
        token = page.get_by_role("textbox", name="APIキー", exact=True).input_value()
        with tempfile.TemporaryDirectory() as config_directory:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = config_directory
            login = subprocess.run(["node", "cli/dist/cli.mjs", "login", "--key", "@-", "--origin", ORIGIN],
                capture_output=True, text=True, input=token, env=environment, timeout=30)
            self.assertEqual(login.returncode, 0, login.stderr)
            fingerprint = page.request.get(ORIGIN + "/__test/executor/" + environment_id + "/fingerprint").json()
            trusted = subprocess.run(["node", "cli/dist/cli.mjs", "trust", fingerprint["id"], "--fingerprint", fingerprint["fingerprint"]],
                capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(trusted.returncode, 0, trusted.stderr)
            executed = subprocess.run(["node", "cli/dist/cli.mjs", "run", "--environment", environment_id, "--wait", "--timeout", "20", "--",
                "node", "-e", 'console.log("画面確認用の実行です。");console.error("補足の出力です。");'],
                capture_output=True, text=True, env=environment, timeout=30)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            execution_id = json.loads(executed.stdout)["id"]
        path = ORIGIN + "/executions/" + execution_id
        page.goto(path)
        expect(page.get_by_role("heading", name="実行の詳細", exact=True)).to_be_visible()
        expect(page.get_by_text("完了", exact=True)).to_be_visible()
        expect(page.get_by_text("コマンドの実行", exact=True)).to_be_visible()
        expect(page.locator("main").get_by_role("link", name="dev-us", exact=True)).to_be_visible()
        for label in ["開始日時", "終了日時", "所要時間"]:
            expect(page.locator("dt").filter(has_text=re.compile("^" + label + "$"))).to_be_visible()
        expect(page.locator("main pre").filter(has_text="画面確認用の実行です。")).to_have_text("画面確認用の実行です。\n")
        expect(page.locator("main pre").filter(has_text="補足の出力です。")).to_have_text("補足の出力です。\n")
        expect(page.locator("main dl").filter(has=page.locator("dt", has_text="終了コード")).locator("dd")).to_have_text("0")
        page.screenshot(path=str(ARTIFACTS / "execution-completed-output-ja.png"), full_page=True)
        print("Rendered completed execution: " + page.locator("main").inner_text(), flush=True)
        def change_receipt(route):
            response = route.fetch()
            task = response.json()
            sealed = task["receipt"]["content"]["sealed"] if "content" in task["receipt"] else task["receipt"]["sealed"]
            ciphertext = sealed["ciphertext"]
            sealed["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
            route.fulfill(response=response, json=task)
        page.route("**/api/runtime/runs/*", change_receipt)
        page.reload()
        expect(page.get_by_text("完了", exact=True)).to_be_visible()
        expect(page.get_by_role("alert")).to_have_text("出力を読み取れませんでした。ページを再読み込みしてください。")
        page.unroute("**/api/runtime/runs/*", change_receipt)
        reader, recipient = self.passkey_account("Execution viewer")
        for object_id in [principal["id"], environment_id]:
            granted = page.request.post(ORIGIN + "/api/relations", data={"subjectId": recipient["id"], "relation": "reader", "objectId": object_id}, headers={"origin": ORIGIN})
            self.assertTrue(granted.ok, granted.text())
        reader.goto(path)
        expect(reader.get_by_text("完了", exact=True)).to_be_visible()
        expect(reader.locator("main").get_by_role("link", name="dev-us", exact=True)).to_be_visible()
        notice = reader.get_by_role("alert")
        expect(notice).to_have_count(1)
        expect(notice).to_have_text("出力はこのアカウントに共有されていません。")
        reader.screenshot(path=str(ARTIFACTS / "execution-completed-locked-ja.png"), full_page=True)
        print("Rendered completed execution for viewer: " + reader.locator("main").inner_text(), flush=True)
        reader.reload()
        expect(reader.get_by_text("完了", exact=True)).to_be_visible()
        expect(notice).to_contain_text("出力はこのアカウントに共有されていません。")
        self.select(reader, "言語", "English")
        reader.set_viewport_size({"width": 390, "height": 844})
        expect(reader.get_by_role("heading", name="Execution details", exact=True)).to_be_visible()
        expect(reader.get_by_text("Completed", exact=True)).to_be_visible()
        expect(notice).to_have_text("The output has not been shared with this account.")
        reader.screenshot(path=str(ARTIFACTS / "execution-completed-locked-mobile-en.png"), full_page=True)
        print("Rendered execution detail (English): " + reader.locator("main").inner_text(), flush=True)

    def test_固定した関数を共有して秘密を使う処理の結果を受け取る(self):
        page, principal = self.passkey_account("Function owner")
        environment = self.executor(page, principal).rsplit("/", 1)[1]
        source = self.variable(page, principal, name="Function token", value="private-function-token").rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/functions/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Reusable function")
        self.select(page, "実行環境", "Browser executor")
        code = 'let text="";process.stdin.on("data",c=>text+=c);process.stdin.on("end",()=>{const args=JSON.parse(text);console.log(JSON.stringify({message:args.message,amount:args.amount,enabled:args.enabled,payload:args.payload,configured:!!process.env.TOKEN,secret:process.env.TOKEN}));});'
        page.get_by_role("textbox", name="プログラムと引数（JSON配列）", exact=True).fill(json.dumps(["node", "-e", code]))
        page.get_by_role("textbox", name="接続・変数の入力（JSON）", exact=True).fill(json.dumps([{"name": "TOKEN", "source": {"id": source}}]))
        page.get_by_role("textbox", name="パラメーター（JSON）", exact=True).fill(json.dumps([
            {"name": "message", "label": "Message"},
            {"name": "amount", "label": "Amount", "type": "number", "default": 0},
            {"name": "enabled", "label": "Enabled", "type": "boolean", "default": True},
            {"name": "payload", "label": "Payload", "type": "json", "default": {}},
        ]))
        page.screenshot(path=str(ARTIFACTS / "function-editor-desktop-ja.png"), full_page=True)
        print("Rendered function editor: " + page.locator("main").inner_text(), flush=True)
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Reusable function", exact=True)).to_be_visible(timeout=15000)
        function_path = page.url
        function_id = function_path.rsplit("/", 1)[1]
        reader, recipient = self.passkey_account("Function caller")
        reader.evaluate("""() => new Promise((resolve, reject) => {
          const request = indexedDB.open('foundation-keys', 2);
          request.onsuccess = () => {
            const db = request.result, transaction = db.transaction('keys', 'readwrite');
            transaction.objectStore('keys').clear();
            transaction.oncomplete = () => { db.close(); resolve(); };
            transaction.onerror = () => reject(transaction.error);
          };
          request.onerror = () => reject(request.error);
        })""")
        granted = page.request.post(ORIGIN + "/api/relations", data={"subjectId": recipient["id"], "relation": "runner", "objectId": function_id}, headers={"origin": ORIGIN})
        self.assertTrue(granted.ok, granted.text())
        reader.goto(function_path + "/run")
        reader.get_by_role("textbox", name="Message", exact=True).fill("Shared invocation")
        expect(reader.get_by_role("spinbutton", name="Amount", exact=True)).to_have_value("0")
        reader.get_by_role("spinbutton", name="Amount", exact=True).fill("12.5")
        expect(reader.get_by_role("checkbox", name="Enabled", exact=True)).to_be_checked()
        reader.get_by_role("checkbox", name="Enabled", exact=True).uncheck()
        reader.get_by_role("textbox", name="Payload", exact=True).fill(json.dumps({"items": [1, False, None]}))
        reader.screenshot(path=str(ARTIFACTS / "function-run-desktop-ja.png"), full_page=True)
        reader.get_by_role("button", name="実行", exact=True).click()
        reader.wait_for_url("**/executions/*")
        expect(reader.locator("main")).to_contain_text("Shared invocation", timeout=15000)
        expect(reader.locator("main")).to_contain_text('"configured": true')
        expect(reader.locator("main")).to_contain_text('"amount": 12.5')
        expect(reader.locator("main")).to_contain_text('"enabled": false')
        expect(reader.locator("main")).to_contain_text('"items": [')
        expect(reader.locator("main")).to_contain_text("[redacted]")
        reader.screenshot(path=str(ARTIFACTS / "function-result-desktop-ja.png"), full_page=True)
        print("Rendered function result: " + reader.locator("main").inner_text(), flush=True)
        self.assertEqual(reader.request.get(ORIGIN + "/api/resources/" + source + "/custody").status, 403)
        self.assertEqual(reader.request.get(ORIGIN + "/api/environments/" + environment + "/registration").status, 403)
        page.goto(function_path + "/edit")
        self.select(page, "言語", "English")
        page.set_viewport_size({"width": 390, "height": 844})
        expect(page.get_by_role("textbox", name="Program and arguments (JSON array)", exact=True)).to_have_value(json.dumps(["node", "-e", code], ensure_ascii=False, indent=2))
        page.screenshot(path=str(ARTIFACTS / "function-editor-mobile-en.png"), full_page=True)
        print("Rendered function editor (English): " + page.locator("main").inner_text(), flush=True)
        page.get_by_role("textbox", name="Description", exact=True).fill("Reusable processing with a private token")
        page.get_by_role("button", name="Save", exact=True).click()
        expect(page.get_by_role("heading", name="Reusable function", exact=True)).to_be_visible(timeout=15000)
        page.get_by_role("button", name="Delete", exact=True).click()
        page.get_by_role("dialog").get_by_role("button", name="Delete", exact=True).click()
        page.wait_for_url(f"**/p/{principal['id']}/functions")
        expect(page.get_by_role("heading", name="Functions", exact=True)).to_be_visible()
        reader.reload()
        expect(reader.locator("main")).to_contain_text("Shared invocation")

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
        expect(page.get_by_text("この端末で暗号化された値を開けます。", exact=True)).to_be_visible()
        row = page.get_by_role("listitem").filter(has_text="Credentials viewer")
        expect(row.get_by_text("使用中", exact=True)).to_be_visible()
        expect(row.get_by_text("暗号化された値を開ける", exact=False)).to_be_visible()
        expect(row.get_by_role("button", name="削除", exact=True)).to_have_count(0)
        page.get_by_role("link", name="キーを発行", exact=True).click()
        expect(page.get_by_role("heading", name="キーを発行", exact=True)).to_be_visible()
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
        owner.wait_for_url("**/executions/*")
        change = "Shared project の所有者を Project successor に変更"
        expect(owner.get_by_text(change, exact=True)).to_be_visible()
        owner.screenshot(path=str(ARTIFACTS / "transfer-request-ja.png"), full_page=True)
        successor.goto(owner.url)
        expect(successor.get_by_text(change, exact=True)).to_be_visible()
        successor.screenshot(path=str(ARTIFACTS / "transfer-approve-ja.png"), full_page=True)
        successor.get_by_role("button", name="承認", exact=True).click()
        expect(successor.get_by_text("完了", exact=True).first).to_be_visible()
        successor.goto(variable_path)
        successor.get_by_role("button", name="内容を表示", exact=True).click()
        expect(successor.get_by_role("textbox", name="値", exact=True)).to_have_value("team-variable-value")

    def test_代理の線を引くと代理が持ち主の変数を開き線を外すと開けなくなる(self):
        owner, principal = self.passkey_account("Key owner")
        agent, delegate = self.passkey_account("Key agent")
        self.trust(owner, agent, delegate)
        self.trust(agent, owner, principal)
        variable_path = self.variable(owner, principal, "Agent variable", "agent-variable-value")
        owner.goto(f"{ORIGIN}/p/{principal['id']}/principals")
        owner.get_by_role("textbox", name="相手のプリンシパルID").fill(delegate["id"])
        owner.get_by_role("button", name="追加", exact=True).click()
        line = owner.get_by_role("listitem").filter(has_text="Key agent は Key owner の代理")
        expect(line).to_be_visible()
        print("Rendered principals: " + owner.locator("main").inner_text(), flush=True)
        agent.goto(variable_path)
        agent.get_by_role("button", name="内容を表示", exact=True).click()
        expect(agent.get_by_role("textbox", name="値", exact=True)).to_have_value("agent-variable-value")
        line.get_by_role("button", name="権限を解除", exact=True).click()
        expect(owner.get_by_text("Key agent は Key owner の代理", exact=True)).to_be_hidden()
        agent.goto(variable_path)
        expect(agent.get_by_text("この操作を行う権限がありません。", exact=True)).to_be_visible()
        expect(agent.get_by_role("button", name="内容を表示", exact=True)).to_be_hidden()

    def test_サービス接続とプリンシパルを作成して委任する(self):
        page, principal = self.passkey_account()
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new")
        self.select(page, "サービス", "AWS")
        self.select(page, "サービス", "GitHub")
        page.get_by_role("textbox", name="名前", exact=True).fill("GitHub test")
        page.get_by_label("Personal access token").fill("test-provider-token")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("heading", name="GitHub test", exact=True)).to_be_visible()
        expect(page.get_by_text("GitHub", exact=True)).to_be_visible()
        page.goto(f"{ORIGIN}/p/{principal['id']}/principals/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Automation")
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Automation", exact=True)).to_be_visible()
        child_id = page.url.rsplit("/", 1)[1]
        page.goto(f"{ORIGIN}/p/{principal['id']}/principals")
        page.get_by_role("textbox", name="相手のプリンシパルID").fill(child_id)
        page.get_by_role("button", name="追加", exact=True).click()
        expect(page.get_by_text("Automation は Browser account の代理", exact=True)).to_be_visible()

    def test_VultrとRunPodのAPIキー接続を画面から作成する(self):
        page, principal = self.passkey_account("Compute account")
        for service in ["Vultr", "RunPod"]:
            with self.subTest(service=service):
                page.goto(f"{ORIGIN}/p/{principal['id']}/services/new")
                self.select(page, "サービス", service)
                name = service + " API"
                page.get_by_role("textbox", name="名前", exact=True).fill(name)
                page.get_by_label("APIキー", exact=True).fill(service.lower() + "-browser-test-key")
                page.screenshot(path=str(ARTIFACTS / (service.lower() + "-connection-input-ja.png")), full_page=True)
                print("Rendered " + service + " connection: " + page.locator("main").inner_text(), flush=True)
                page.get_by_role("button", name="接続する", exact=True).click()
                expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
                expect(page.get_by_text("接続済み", exact=True)).to_be_visible()
                expect(page.get_by_text(service, exact=True)).to_be_visible()

    def test_HFの登録を依頼して所有者の画面で完了しAIへ使用許可を渡して履歴を確認する(self):
        import tempfile
        sender, _ = self.passkey_account("HF requester")
        owner, principal = self.passkey_account("Chancellor Rigel")
        response = sender.request.post(ORIGIN + "/api/requests", data={"to": principal["id"],
            "message": "Hugging Faceに接続してください。", "operations": [{"name": "connection.connect", "input": {
                "ownerId": principal["id"], "methodId": "huggingface:token", "name": "Hugging Face"
            }}]}, headers={"origin": ORIGIN})
        self.assertTrue(response.ok, response.text())
        asked = response.json()
        owner.goto(asked["url"])
        expect(owner.get_by_text("Chancellor Rigel", exact=True).last).to_be_visible()
        owner.get_by_label("ユーザーアクセストークン", exact=True).fill("hf_browser_registration")
        owner.screenshot(path=str(ARTIFACTS / "hf-request-input-ja.png"), full_page=True)
        print("Rendered HF request: " + owner.locator("main").inner_text(), flush=True)
        owner.get_by_role("button", name="承認", exact=True).click()
        expect(owner.get_by_text("承諾済み", exact=True)).to_be_visible()
        expect(owner.get_by_text("完了", exact=True)).to_be_visible()
        completed = sender.request.get(ORIGIN + "/api/executions/" + asked["executionId"]).json()
        self.assertEqual(completed["state"], "succeeded")
        connection_id = completed["results"][0]["id"]
        connection_path = f"{ORIGIN}/p/{principal['id']}/services/{connection_id}"
        owner.goto(connection_path)
        expect(owner.get_by_role("heading", name="Hugging Face", exact=True)).to_be_visible()
        owner.screenshot(path=str(ARTIFACTS / "hf-connection-ja.png"), full_page=True)
        paid = owner.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        created = owner.request.post(ORIGIN + "/api/principals", data={"ownerId": principal["id"], "name": "dev-us の AI"}, headers={"origin": ORIGIN})
        self.assertTrue(created.ok, created.text())
        agent = created.json()
        owner.goto(f"{ORIGIN}/p/{agent['id']}/settings/credentials/new?kind=key")
        owner.get_by_role("textbox", name="名前", exact=True).fill("Agent key")
        owner.get_by_role("button", name="追加", exact=True).click()
        token = owner.get_by_role("textbox", name="APIキー", exact=True).input_value()
        with tempfile.TemporaryDirectory() as home:
            environment = {key: value for key, value in os.environ.items() if not key.startswith("FOUNDATION_")}
            environment["XDG_CONFIG_HOME"] = home
            login = subprocess.run(["node", "cli/dist/cli.mjs", "login", "--key", "@-", "--origin", ORIGIN],
                capture_output=True, text=True, input=token, env=environment)
            self.assertEqual(login.returncode, 0, login.stderr)
            fingerprint = subprocess.run(["node", "--import", "tsx", "--input-type=module", "-e", """
                import { readFile } from 'node:fs/promises';
                import { join } from 'node:path';
                import { fingerprint } from './shared/authority.ts';
                const identity = JSON.parse(await readFile(join(process.env.XDG_CONFIG_HOME, 'foundation/identity.json'), 'utf8'));
                console.log(await fingerprint(identity.identities.find(item => item.principalId === identity.current).binding));
            """], capture_output=True, text=True, env=environment)
            self.assertEqual(fingerprint.returncode, 0, fingerprint.stderr)
            self.trust_fingerprint(owner, agent["id"], fingerprint.stdout.strip())
            owner.goto(ORIGIN + "/account/trust")
            owner_fingerprint = owner.get_by_text(re.compile(r"^sha256:[0-9a-f]{64}$")).inner_text()
            trusted = subprocess.run(["node", "cli/dist/cli.mjs", "trust", principal["id"], "--fingerprint", owner_fingerprint],
                capture_output=True, text=True, env=environment)
            self.assertEqual(trusted.returncode, 0, trusted.stderr)
            connection = owner.request.get(ORIGIN + "/api/resources/" + connection_id).json()
            permission = subprocess.run(["node", "cli/dist/cli.mjs", "execution", "start", "--body", json.dumps({
                "responderId": principal["id"], "message": "dev-us の AIでモデルを保存・取得します。",
                "operations": [{"name": "connection.authorize", "input": {
                    "ownerId": principal["id"], "connectionId": connection_id,
                    "version": connection["version"], "users": [agent["id"]]
                }}]
            })], capture_output=True, text=True, env=environment)
            self.assertEqual(permission.returncode, 0, permission.stderr)
            permission_execution = json.loads(permission.stdout)
            owner.goto(ORIGIN + "/requests/" + permission_execution["requests"][0])
            expect(owner.get_by_text("Hugging Face", exact=True)).to_be_visible()
            expect(owner.get_by_text("dev-us の AI", exact=True).last).to_be_visible()
            expect(owner.get_by_text("使用を許可する人・AI", exact=True)).to_be_visible()
            owner.screenshot(path=str(ARTIFACTS / "hf-use-permissions-ja.png"), full_page=True)
            print("Rendered connection permissions: " + owner.locator("main").inner_text(), flush=True)
            owner.get_by_role("button", name="承認", exact=True).click()
            expect(owner.get_by_text("完了", exact=True).first).to_be_visible()
            connection = owner.request.get(ORIGIN + "/api/resources/" + connection_id).json()
            self.assertEqual(connection["ownerId"], principal["id"])
            used = subprocess.run(["node", "cli/dist/cli.mjs", "exec", "--inputs", json.dumps([
                {"name": "HF_TOKEN", "source": {"id": connection_id, "output": "HF_TOKEN"}}
            ]), "--", "node", "-e", "console.log(process.env.HF_TOKEN === 'hf_browser_registration' ? 'Configured' : 'Missing')"],
                capture_output=True, text=True, env=environment)
            self.assertEqual(used.returncode, 0, used.stderr)
            self.assertEqual(used.stdout, "Configured\n")
        owner.goto(f"{ORIGIN}/p/{principal['id']}/runs")
        execution_link = owner.locator(f'a[href="/executions/{asked["executionId"]}"]')
        expect(execution_link).to_have_count(1)
        expect(execution_link).to_contain_text("サービスに接続する")
        owner.screenshot(path=str(ARTIFACTS / "unified-execution-history-ja.png"), full_page=True)
        self.select(owner, "言語", "English")
        owner.set_viewport_size({"width": 390, "height": 844})
        expect(owner.locator("html")).to_have_attribute("lang", "en")
        self.assertLessEqual(owner.evaluate("document.documentElement.scrollWidth"), 391)
        owner.screenshot(path=str(ARTIFACTS / "unified-execution-history-mobile-en.png"), full_page=True)

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
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("heading", name="AI GitHub connection", exact=True)).to_be_visible()
        connection_path = page.url
        page.goto(f"{ORIGIN}/p/{principal['id']}/services")
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
        expect(row.get_by_text("Owner:", exact=False)).to_be_visible()
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.screenshot(path=str(ARTIFACTS / "owned-connections-mobile-en.png"), full_page=True, animations="disabled")
        row.get_by_role("link", name="AI GitHub connection", exact=True).click()
        expect(page.get_by_role("heading", name="AI GitHub connection", exact=True)).to_be_visible()
        self.assertEqual(page.url, connection_path)

    def test_独立した接続方法を登録しOAuthアプリを対応する方法に結び付ける(self):
        page, principal = self.passkey_account("Method owner")
        self.executor(page, principal)
        root = f"{ORIGIN}/p/{principal['id']}"
        page.goto(root + "/methods/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Workspace sign-in")
        page.get_by_role("textbox", name="定義（JSON）", exact=True).fill(json.dumps({"kind": "oauth", "config": {
            "authorizeUrl": "https://provider.example/authorize", "tokenUrl": "https://provider.example/token",
            "fields": [{"name": "workspace", "label": "Workspace", "required": True}],
        }}))
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("heading", name="Workspace sign-in", exact=True)).to_be_visible()
        method_id = page.url.rsplit("/", 1)[1]
        page.goto(root + "/apps/new")
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
        expect(page.get_by_role("combobox", name="接続方法", exact=True)).to_have_text("Workspace sign-in")
        expect(page.get_by_role("combobox", name="接続用アプリ", exact=True)).to_have_text("Workspace application")
        expect(page.get_by_role("button", name="接続する", exact=True)).to_be_enabled()
        page.screenshot(path=str(ARTIFACTS / "connection-oauth-app-ja.png"), full_page=True, animations="disabled")
        catalog = page.request.get(ORIGIN + "/api/connection-methods").json()
        catalog["items"] = [method for method in catalog["items"] if method["id"] != method_id]
        page.route(ORIGIN + "/api/connection-methods", lambda route: route.fulfill(json=catalog))
        page.goto(application_edit_path)
        expect(page.get_by_label("クライアントID", exact=True)).to_have_value("browser-client")
        expect(page.get_by_label("クライアントシークレット", exact=True)).to_be_visible()
        expect(page.get_by_label("コールバックURL", exact=True)).to_have_value(ORIGIN + "/oauth/callback")

    def test_スマホで初期値のまま実行環境を作成して停止する(self):
        owner, principal = self.passkey_account("Mobile environment owner")
        response = owner.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(response.ok, response.text())
        page = self.page(webkit=True, mobile=True)
        page.context.add_cookies(owner.context.cookies())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        expect(page.get_by_text("必要な利用枠 60分", exact=True)).to_be_visible()
        expect(page.get_by_text("今月の残り 60分", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="作成", exact=True)).to_be_enabled()
        start = page.get_by_role("button", name="作成", exact=True)
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

    def test_構成と停止条件に応じた利用枠を確認して実行環境を作成する(self):
        page, principal = self.passkey_account("Quota environment owner")
        paid = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.get_by_role("textbox", name="名前", exact=True).fill("Medium environment")
        page.get_by_role("radio", name="Medium — 2 CPU / 2 GB", exact=True).check()
        expect(page.get_by_text("必要な利用枠 120分", exact=True)).to_be_visible()
        expect(page.get_by_role("alert").filter(has_text="利用枠が60分不足しています")).to_be_visible()
        expect(page.get_by_role("button", name="作成", exact=True)).to_be_disabled()
        page.get_by_text("停止条件", exact=True).click()
        page.get_by_role("spinbutton", name="最長稼働時間（分）", exact=True).fill("20")
        expect(page.get_by_role("alert").filter(has_text="操作がないときの停止時間は、最長稼働時間以下にしてください")).to_be_visible()
        page.get_by_role("spinbutton", name="操作がないときの停止時間（分）", exact=True).fill("15")
        expect(page.get_by_text("必要な利用枠 40分", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="作成", exact=True)).to_be_enabled()
        page.screenshot(path=str(ARTIFACTS / "environment-create-lifetime-desktop-ja.png"), full_page=True)
        page.get_by_role("button", name="作成", exact=True).click()
        page.wait_for_url(re.compile(r"/environments/[a-f0-9-]{36}$"))
        environment_id = page.url.rsplit("/", 1)[1]
        self.environments.append((page, environment_id))
        expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
        response = page.request.get(ORIGIN + "/api/resources/" + environment_id)
        self.assertTrue(response.ok, response.text())
        environment = response.json()
        self.assertEqual(environment["data"]["size"], "medium")
        self.assertEqual(environment["data"]["lifetime"], {"idleSeconds": 900, "maxSeconds": 1200})
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        expect(page.get_by_text("今月の残り 20分", exact=True)).to_be_visible()
        expect(page.get_by_role("alert").filter(has_text="利用枠が40分不足しています")).to_be_visible()
        expect(page.get_by_role("button", name="作成", exact=True)).to_be_disabled()
        page.screenshot(path=str(ARTIFACTS / "environment-create-quota-mobile-ja.png"), full_page=True)
        self.select(page, "言語", "English")
        expect(page.get_by_text("Remaining this month: 20 minutes", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Create", exact=True)).to_be_disabled()
        page.screenshot(path=str(ARTIFACTS / "environment-create-quota-mobile-en.png"), full_page=True)

    def test_スマホでSSH公開鍵を指定して接続情報を確認し公開鍵を変更する(self):
        import tempfile
        owner, principal = self.passkey_account("SSH environment owner")
        paid = owner.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        page = self.page(webkit=True, mobile=True)
        page.context.add_cookies(owner.context.cookies())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        page.get_by_text("SSH接続", exact=True).click()
        page.get_by_role("button", name="公開鍵を追加", exact=True).click()
        keys = page.get_by_role("textbox", name="公開鍵 1", exact=True)
        expect(keys).to_be_visible()
        keys.fill("invalid key")
        page.get_by_role("button", name="作成", exact=True).click()
        expect(page.get_by_role("alert").filter(has_text="SSH公開鍵を確認してください")).to_be_visible()
        with tempfile.TemporaryDirectory() as directory:
            public_keys = []
            for name in ["first", "second"]:
                path = Path(directory) / name
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
                public_keys.append(path.with_suffix(".pub").read_text().strip())
            keys.fill(public_keys[0])
            page.get_by_role("button", name="作成", exact=True).click()
            page.wait_for_url(re.compile(r"/environments/[a-f0-9-]{36}$"))
            environment_id = page.url.rsplit("/", 1)[1]
            self.environments.append((page, environment_id))
            expect(page.get_by_text("稼働中", exact=True)).to_be_visible(timeout=15000)
            expect(page.locator("code").filter(has_text=".ssh.foundation.test")).to_be_visible()
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

    def test_PCで公開鍵ファイルと入力から追加した鍵を確認して実行環境を作成する(self):
        page, principal = self.passkey_account("SSH key account")
        paid = page.request.post(ORIGIN + "/__test/payment", data={"principalId": principal["id"]})
        self.assertTrue(paid.ok, paid.text())
        page.goto(f"{ORIGIN}/p/{principal['id']}/environments/new")
        expect(page.get_by_role("button", name="作成", exact=True)).to_be_enabled()
        page.screenshot(path=str(ARTIFACTS / "environment-create-desktop-ja.png"), full_page=True)
        page.get_by_text("SSH接続", exact=True).click()
        with tempfile.TemporaryDirectory() as directory:
            paths, public_keys = [], []
            for name in ["first", "second"]:
                path = Path(directory) / name
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-C", name, "-N", "", "-f", str(path)], check=True)
                paths.append(path.with_suffix(".pub"))
                public_keys.append(paths[-1].read_text().strip())
            with page.expect_file_chooser() as chooser:
                page.get_by_role("button", name="ファイルから追加", exact=True).click()
            chooser.value.set_files([str(path) for path in paths])
            expect(page.get_by_role("textbox", name="公開鍵 1", exact=True)).to_have_value(public_keys[0])
            expect(page.get_by_role("textbox", name="公開鍵 2", exact=True)).to_have_value(public_keys[1])
            page.get_by_role("button", name="公開鍵 1を削除", exact=True).click()
            expect(page.get_by_role("textbox", name="公開鍵 1", exact=True)).to_have_value(public_keys[1])
            page.get_by_role("button", name="公開鍵を追加", exact=True).click()
            page.get_by_role("textbox", name="公開鍵 2", exact=True).fill(public_keys[0])
            expect(page.get_by_role("button", name="作成", exact=True)).to_be_enabled()
            page.screenshot(path=str(ARTIFACTS / "environment-create-keys-desktop-ja.png"), full_page=True)
            self.select(page, "言語", "English")
            expect(page.get_by_role("textbox", name="Public key 1", exact=True)).to_have_value(public_keys[1])
            expect(page.get_by_role("button", name="Remove public key 2", exact=True)).to_be_visible()
            page.screenshot(path=str(ARTIFACTS / "environment-create-keys-desktop-en.png"), full_page=True)
            page.get_by_role("button", name="Create", exact=True).click()
            page.wait_for_url(re.compile(r"/environments/[a-f0-9-]{36}$"))
            environment_id = page.url.rsplit("/", 1)[1]
            self.environments.append((page, environment_id))
            expect(page.get_by_text("Running", exact=True)).to_be_visible(timeout=15000)
            response = page.request.get(ORIGIN + "/api/environments/" + environment_id + "/ssh")
            self.assertTrue(response.ok, response.text())
            self.assertEqual(response.json()["authorizedKeys"], [public_keys[1], public_keys[0]])

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
        expect(page.get_by_role("button", name="作成", exact=True)).to_be_enabled()
        page.screenshot(path=str(ARTIFACTS / "environment-create-ja.png"), full_page=True)
        page.get_by_role("button", name="作成", exact=True).click()
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

    def test_依頼画面で機密の変数を入力して承認すると暗号化して保存する(self):
        sender, _ = self.passkey_account("Value requester")
        receiver, principal = self.passkey_account("Value approver")
        response = sender.request.post(ORIGIN + "/api/requests", data={"to": principal["id"], "operations": [{
            "name": "variable.save", "input": {
                "ownerId": "$approver", "name": "Requested variable", "value": "", "environmentIds": []
            }, "inputs": [{"pointer": "/value", "label": "Private value", "secret": True}]
        }]}, headers={"origin": ORIGIN})
        self.assertTrue(response.ok, response.text())
        asked = response.json()
        receiver.goto(asked["url"])
        receiver.get_by_role("textbox", name="値", exact=True).fill("requested-private-value")
        receiver.get_by_role("button", name="承認", exact=True).click()
        expect(receiver.get_by_text("承諾済み", exact=True)).to_be_visible(timeout=15000)
        result = sender.request.get(ORIGIN + "/api/executions/" + asked["executionId"]).json()["results"][0]
        receiver.goto(f"{ORIGIN}/p/{principal['id']}/variables/{result['id']}")
        receiver.get_by_role("button", name="内容を表示", exact=True).click()
        expect(receiver.get_by_role("textbox", name="値", exact=True)).to_have_value("requested-private-value")

    def test_依頼内容を確認して承認し新しいプリンシパルを作成する(self):
        sender, _ = self.passkey_account("Requester")
        receiver, principal = self.passkey_account("Approver")
        sender.goto(ORIGIN + "/requests/new")
        sender.get_by_role("textbox", name="依頼先のプリンシパルID").fill(principal["id"])
        sender.get_by_role("textbox", name="メッセージ", exact=True).fill("Create a project account")
        sender.get_by_role("textbox", name="操作（JSON）", exact=True).fill(json.dumps([{"name": "principal.create", "input": {"name": "Approved project", "ownerId": "$approver"}}]))
        sender.get_by_role("button", name="作成", exact=True).click()
        sender.wait_for_url("**/requests/*")
        expect(sender.get_by_text("確認待ち", exact=True)).to_be_visible()
        receiver.goto(sender.url)
        expect(receiver.get_by_role("heading", name="プリンシパルを作る", exact=True)).to_be_visible()
        receiver.screenshot(path=str(ARTIFACTS / "request-approval-ja.png"), full_page=True)
        receiver.get_by_role("button", name="承認", exact=True).click()
        expect(receiver.get_by_text("承諾済み", exact=True)).to_be_visible()
        projects = receiver.request.get(ORIGIN + "/api/principals").json()["items"]
        self.assertIn("Approved project", [item["name"] for item in projects])

    def test_通常のログインがある端末で依頼専用リンクを開いて依頼を承認する(self):
        sender, _ = self.passkey_account("Link requester")
        owner, principal = self.passkey_account("Link approver")
        viewer, _ = self.passkey_account("Existing session")
        sender.goto(ORIGIN + "/requests/new")
        sender.get_by_role("textbox", name="依頼先のプリンシパルID").fill(principal["id"])
        sender.get_by_role("textbox", name="操作（JSON）", exact=True).fill(json.dumps([{"name": "principal.create", "input": {"name": "Link project", "ownerId": "$approver"}}]))
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
        expect(viewer.get_by_text("承諾済み", exact=True)).to_be_visible()
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
        page.get_by_role("radio", name="Medium — 2 CPU / 2 GB", exact=True).check()
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.get_by_role("link", name="Cancel", exact=True).click()
        expect(page.get_by_role("heading", name="Environments", exact=True)).to_be_visible()
        page.reload()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()

    def test_外部連携の完了URLとやり直し用URLを保存して表示する(self):
        page, principal = self.passkey_account("URL settings account")
        page.goto(f"{ORIGIN}/p/{principal['id']}/settings/integrations")
        page.get_by_role("textbox", name="完了後のURL", exact=True).fill("https://client.example/complete")
        page.get_by_role("textbox", name="やり直し用のURL", exact=True).fill("https://client.example/retry")
        page.get_by_role("button", name="保存", exact=True).click()
        expect(page.get_by_role("alert")).to_contain_text("保存しました")
        page.reload()
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

    def test_ブラウザだけで各方式の認証情報を登録して保存内容を編集する(self):
        page, principal = self.passkey_account("Credential owner")
        root = f"{ORIGIN}/p/{principal['id']}"
        cases = [
            ("ovh:api_key", "OVH keys", {"Application Key": "browser-application", "Application Secret": "browser-secret", "Consumer Key": "browser-consumer"}),
            ("ovh:pat", "OVH personal token", {"Personal Access Token（PAT）": "browser-personal-token"}),
            ("ovh:client_credentials", "OVH application", {"クライアントID": "browser-client", "クライアントシークレット": "browser-client-secret"}),
            ("github:token", "GitHub key", {"Personal access token": "browser-github-token"}),
        ]
        bodies = []
        page.on("request", lambda request: bodies.append(request.post_data or "")
                if request.url.startswith(ORIGIN + "/api/") and request.method in ("POST", "PUT", "PATCH") else None)
        for method_id, name, values in cases:
            with self.subTest(method=method_id):
                page.goto(root + "/services/new?method=" + method_id)
                page.get_by_role("textbox", name="名前", exact=True).fill(name)
                if method_id.startswith("ovh:"):
                    self.select(page, "アカウントのAPI接続先", "CA")
                for label, value in values.items():
                    page.get_by_label(label, exact=True).fill(value)
                page.screenshot(path=str(ARTIFACTS / (method_id.replace(":", "-") + "-registration-ja.png")), full_page=True)
                page.get_by_role("button", name="接続する", exact=True).click()
                saved = self.saved_connection(page, name)
                self.assertEqual(saved["data"]["methodId"], method_id)
                if method_id.startswith("ovh:"):
                    self.assertEqual(saved["data"]["fields"], {"apiRegion": "ca"})
                for label, value in values.items():
                    if label not in ("クライアントID", "Application Key"):
                        self.assertNotIn(value, "".join(bodies), "Credentials travel encrypted to Foundation")
                path = page.url
                page.get_by_role("link", name="再接続", exact=True).click()
                page.get_by_role("button", name="接続する", exact=True).click()
                self.saved_connection(page, name)
                self.assertEqual(page.url, path)

    def test_AWSキーとロール設定をブラウザで保存して更新する(self):
        page, principal = self.passkey_account("AWS credential owner")
        root = f"{ORIGIN}/p/{principal['id']}"
        page.goto(root + "/services/new?method=aws:authentication")
        page.get_by_role("textbox", name="名前", exact=True).fill("AWS keys")
        page.get_by_label("アクセスキーID", exact=True).fill("AKIABROWSERTEST")
        page.get_by_label("シークレットアクセスキー", exact=True).fill("browser-aws-secret")
        page.get_by_role("checkbox", name="別のIAMロールを使う", exact=True).check()
        page.get_by_label("IAMロールのARN", exact=True).fill("arn:aws:iam::123456789012:role/Example")
        page.get_by_label("External ID", exact=True).fill("browser-external-id")
        page.get_by_role("button", name="接続する", exact=True).click()
        saved = self.saved_connection(page, "AWS keys")
        self.assertEqual(saved["data"]["aws"]["roleArn"], "arn:aws:iam::123456789012:role/Example")
        path = page.url
        page.get_by_role("link", name="再接続", exact=True).click()
        expect(page.get_by_label("アクセスキーID", exact=True)).to_have_value("AKIABROWSERTEST")
        expect(page.get_by_label("IAMロールのARN", exact=True)).to_have_value("arn:aws:iam::123456789012:role/Example")
        page.get_by_label("シークレットアクセスキー", exact=True).fill("updated-browser-secret")
        page.set_viewport_size({"width": 390, "height": 844})
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
        page.screenshot(path=str(ARTIFACTS / "aws-registration-mobile-ja.png"), full_page=True)
        page.get_by_role("button", name="接続する", exact=True).click()
        self.saved_connection(page, "AWS keys")
        self.assertEqual(page.url, path)

    def test_Googleの認可をブラウザで交換して接続を保存する(self):
        page, principal = self.passkey_account("Browser authorization owner")
        exchanges = []
        def exchange(route):
            exchanges.append(route.request.post_data)
            route.fulfill(json={"access_token": "browser-google-token", "refresh_token": "browser-google-refresh", "token_type": "Bearer", "expires_in": 3600},
                          headers={"access-control-allow-origin": ORIGIN, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "*"})
        page.context.route("https://oauth2.googleapis.com/token", exchange)
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=google:oauth")
        page.get_by_role("textbox", name="名前", exact=True).fill("Google account")
        page.get_by_label("クライアントID", exact=True).fill("browser-google-client")
        page.get_by_label("クライアントシークレット", exact=True).fill("browser-google-secret")
        page.get_by_role("button", name="接続する", exact=True).click()
        link = page.get_by_role("link", name="サービスで認可する", exact=True)
        expect(link).to_be_visible()
        state = parse_qs(urlparse(link.get_attribute("href")).query)["state"][0]
        page.goto(ORIGIN + "/oauth/callback?state=" + state + "&code=browser-google-code")
        saved = self.saved_connection(page, "Google account")
        self.assertEqual(saved["data"]["methodId"], "google:oauth")
        self.assertEqual(len(exchanges), 1)
        self.assertEqual(parse_qs(exchanges[0])["code"], ["browser-google-code"])
        page.screenshot(path=str(ARTIFACTS / "google-browser-registration-ja.png"), full_page=True)

    def test_OVHのブラウザ認可で取得したConsumerKeyを保存する(self):
        page, principal = self.passkey_account("OVH browser owner")
        issued = []
        def issue(route):
            if route.request.method == "OPTIONS":
                route.fulfill(status=204, headers={"access-control-allow-origin": ORIGIN, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "*"})
                return
            issued.append(json.loads(route.request.post_data))
            route.fulfill(json={"state": "pendingValidation", "consumerKey": "browser-consumer-key", "validationUrl": "https://auth.ca.ovhcloud.com/api/auth?credentialToken=browser"},
                          headers={"access-control-allow-origin": ORIGIN})
        page.context.route("https://ca.api.ovh.com/1.0/auth/credential", issue)
        page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?method=ovh:consumer_key")
        self.select(page, "アカウントのAPI接続先", "CA")
        page.get_by_role("textbox", name="名前", exact=True).fill("OVH browser account")
        page.get_by_label("Application Key", exact=True).fill("browser-application")
        page.get_by_label("Application Secret", exact=True).fill("browser-secret")
        page.get_by_label("OVHcloudのAPI権限", exact=True).fill("GET /vps\nPOST /vps/*")
        page.get_by_role("button", name="接続する", exact=True).click()
        expect(page.get_by_role("link", name="サービスで認可する", exact=True)).to_be_visible()
        self.assertEqual(issued[0]["accessRules"], [{"method": "GET", "path": "/vps"}, {"method": "POST", "path": "/vps/*"}])
        page.goto(issued[0]["redirection"])
        saved = self.saved_connection(page, "OVH browser account")
        self.assertEqual(saved["data"]["scopes"], ["GET /vps", "POST /vps/*"])
        page.screenshot(path=str(ARTIFACTS / "ovh-browser-registration-ja.png"), full_page=True)

    def test_CLIが必要な方式を認可前に案内し暗号化した入力からCLIへ引き継ぐ(self):
        page, principal = self.passkey_account("CLI authorization owner")
        for service in ["github", "vultr"]:
            with self.subTest(service=service):
                page.goto(f"{ORIGIN}/p/{principal['id']}/services/new?service={service}&method={service}:oauth")
                expect(page.get_by_text("この方式の認可は、同じ端末のFoundation CLIで続けます。", exact=True)).to_be_visible()
                expect(page.get_by_text("APIキーやアクセストークンを入力する方式は、ブラウザで保存できます。", exact=True)).to_be_visible()
                page.get_by_label("クライアントID", exact=True).fill(service + "-client")
                page.get_by_label("クライアントシークレット", exact=True).fill(service + "-client-secret")
                if service == "vultr":
                    page.get_by_label("OIDCプロバイダーID", exact=True).fill("vultr-test-provider")
                    page.get_by_label("認可URL", exact=True).fill("https://console.vultr.com/oauth/authorize")
                page.screenshot(path=str(ARTIFACTS / (service + "-oauth-input-ja.png")), full_page=True)
                print("Rendered " + service + " OAuth: " + page.locator("main").inner_text(), flush=True)
                page.get_by_role("button", name="接続する", exact=True).click()
                expect(page.locator("code").filter(has_text="foundation execution continue")).to_be_visible()
                page.screenshot(path=str(ARTIFACTS / (service + "-oauth-cli-registration-ja.png")), full_page=True)

    def test_OVH接続の依頼を受け手のブラウザで入力して完了する(self):
        owner, principal = self.passkey_account("OVH request owner")
        sender, requester = self.passkey_account("OVH requester")
        asked = sender.request.post(ORIGIN + "/api/requests", data={"to": principal["id"], "operations": [{"name": "connection.connect", "input": {
            "ownerId": "$approver", "methodId": "ovh:api_key", "fields": {"apiRegion": "ca"}, "name": "Requested OVH"
        }}]}, headers={"origin": ORIGIN})
        self.assertTrue(asked.ok, asked.text())
        request = asked.json()
        owner.goto(ORIGIN + "/requests/" + request["id"])
        owner.get_by_label("Application Key", exact=True).fill("request-application")
        owner.get_by_label("Application Secret", exact=True).fill("request-secret")
        owner.get_by_label("Consumer Key", exact=True).fill("request-consumer")
        owner.get_by_role("button", name="承認", exact=True).click()
        expect(owner.get_by_text("完了", exact=True).first).to_be_visible()
        completed = sender.request.get(ORIGIN + "/api/executions/" + request["executionId"]).json()
        self.assertEqual(completed["state"], "succeeded")
        saved = owner.request.get(ORIGIN + "/api/resources/" + completed["results"][0]["id"]).json()
        self.assertEqual(saved["data"]["methodId"], "ovh:api_key")
        owner.screenshot(path=str(ARTIFACTS / "ovh-request-registration-ja.png"), full_page=True)



if __name__ == "__main__":
    shard = os.environ.get("FOUNDATION_BROWSER_SHARD", "1/1")
    names = select_shard(unittest.defaultTestLoader.getTestCaseNames(BrowserTests), shard)
    print(f"Browser shard {shard}: {len(names)} tests", flush=True)
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
        unittest.main(defaultTest=["BrowserTests." + name for name in names], verbosity=2)
    finally:
        if server:
            server.terminate()
            server.wait(timeout=20)
            server_output.close()
