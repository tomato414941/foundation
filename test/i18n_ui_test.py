"""Run against test/fixture-server.mjs; all accounts and requests are disposable fixtures."""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright, expect
from ui_flows import virtual_authenticator

parser = argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--screenshots', required=True)
parser.add_argument('--executable', help='Optional locally installed Chromium executable')
args = parser.parse_args()
args.base = args.base.replace('127.0.0.1', 'localhost')
root = Path(__file__).resolve().parents[1]
shots = Path(args.screenshots)
shots.mkdir(parents=True, exist_ok=True)
resources = json.loads(subprocess.check_output([
    'node', '--input-type=module', '-e',
    "import {resources} from './web/i18n.js'; console.log(JSON.stringify(resources))",
], cwd=root, text=True))


def tr(locale, key):
    return resources[locale]['translation'][key]


def check_display(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    assert not page.locator('body').inner_text().count('client.'), 'unresolved translation key'


with tempfile.TemporaryDirectory(prefix='foundation-i18n-ui-') as temporary, sync_playwright() as p:
    browser = p.chromium.launch(headless=True, **({'executable_path': args.executable} if args.executable else {}))
    for locale in ['ja', 'en']:
        other = 'en' if locale == 'ja' else 'ja'
        context = browser.new_context(locale='ja-JP' if locale == 'ja' else 'en-US', viewport={'width': 1280, 'height': 900})
        page = context.new_page()
        virtual_authenticator(context, page)
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        response = context.request.get(args.base)
        assert f'<html lang="{locale}">' in response.text(), 'server and client must start in the same locale'
        page.goto(args.base, wait_until='networkidle')
        expect(page.get_by_role('heading', name=tr(locale, 'client.signin.title'), exact=True)).to_be_visible()
        expect(page.locator('html')).to_have_attribute('lang', locale)

        # Browser preferences select the initial language; an explicit switch preserves entered email.
        email = f'i18n-{locale}-{time.time_ns()}@example.test'
        page.get_by_label(tr(locale, 'client.signin.emailAddress'), exact=True).fill(email)
        page.locator('[data-action="change-language"]').select_option(other)
        expect(page.locator('html')).to_have_attribute('lang', other)
        expect(page.get_by_label(tr(other, 'client.signin.emailAddress'), exact=True)).to_have_value(email)
        expect(page.get_by_role('link', name=tr(other, 'server.docs.api'), exact=True)).to_be_visible()
        assert any(cookie['name'] == 'foundation_locale' and cookie['value'] == other for cookie in context.cookies())
        page.locator('[data-action="change-language"]').select_option(locale)
        expect(page.locator('html')).to_have_attribute('lang', locale)

        # A real error from the local server is localized, and an expired confirmation can still switch.
        page.goto(args.base + '/signin/confirm#' + urlencode({'token': 'z' * 43, 'email': email}), wait_until='networkidle')
        page.get_by_role('button', name=tr(locale, 'client.signin.title'), exact=True).click()
        expect(page.get_by_role('alert')).not_to_be_empty()
        page.locator('[data-action="change-language"]').select_option(other)
        expect(page.locator('html')).to_have_attribute('lang', other)
        page.locator('[data-action="change-language"]').select_option(locale)
        expect(page.locator('html')).to_have_attribute('lang', locale)

        page.goto(args.base, wait_until='networkidle')
        page.get_by_label(tr(locale, 'client.signin.emailAddress'), exact=True).fill(email)
        page.get_by_role('button', name=tr(locale, 'client.signin.sendEmail'), exact=True).click()
        expect(page.get_by_role('heading', name=tr(locale, 'client.signin.checkEmail'), exact=True)).to_be_visible()
        token = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()
        page.goto(args.base + '/signin/confirm#' + urlencode({'token': token, 'email': email}), wait_until='networkidle')
        page.get_by_role('button', name=tr(locale, 'client.signin.title'), exact=True).click()
        expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()

        # Switching during the initial authenticated load must never fabricate a signed-out state.
        pending_overview = []
        page.route('**/v1/overview', lambda route: pending_overview.append(route))
        page.goto(args.base + '/services', wait_until='domcontentloaded')
        page.locator('[data-action="change-language"]').select_option(other)
        expect(page.locator('html')).to_have_attribute('lang', locale)
        assert pending_overview, 'overview is held while the SSR language picker is used'
        for route in pending_overview:
            route.continue_()
        page.unroute('**/v1/overview')
        expect(page.get_by_role('heading', name=tr(other, 'nav.services'), exact=True)).to_be_visible()
        expect(page.locator('#signin-form')).to_have_count(0)
        page.locator('[data-action="change-language"]').select_option(locale)
        expect(page.locator('html')).to_have_attribute('lang', locale)

        # A PRF-backed passkey keeps navigation in-page; successful signin must release its busy guard.
        page.goto(args.base + '/account', wait_until='networkidle')
        page.get_by_role('button', name=tr(locale, 'client.passkey.add'), exact=True).click()
        dialog = page.get_by_role('dialog')
        dialog.get_by_label(tr(locale, 'client.common.name'), exact=True).fill('i18n device')
        dialog.get_by_role('button', name=tr(locale, 'client.common.add'), exact=True).click()
        expect(dialog).to_be_hidden()
        page.get_by_role('button', name=tr(locale, 'nav.signout'), exact=True).click()
        page.get_by_role('button', name=tr(locale, 'client.signin.withPasskey'), exact=True).click()
        expect(page.get_by_role('heading', name=tr(locale, 'nav.account'), exact=True)).to_be_visible()
        page.locator('[data-action="change-language"]').select_option(other)
        expect(page.get_by_role('heading', name=tr(other, 'nav.account'), exact=True)).to_be_visible()
        page.locator('[data-action="change-language"]').select_option(locale)
        expect(page.locator('html')).to_have_attribute('lang', locale)

        # All primary pages, history, accessible titles, desktop and narrow mobile layouts.
        for width in [1280, 390, 320]:
            page.set_viewport_size({'width': width, 'height': 900})
            for path in ['services', 'secrets', 'objects', 'principals', 'functions']:
                label = tr(locale, 'nav.' + path)
                page.get_by_role('navigation').get_by_role('link', name=label, exact=True).click()
                expect(page.get_by_role('heading', name=label, exact=True)).to_be_visible()
                expect(page).to_have_title(label + ' · Foundation')
                expect(page.get_by_role('navigation').get_by_role('link', name=label, exact=True)).to_have_attribute('aria-current', 'page')
                check_display(page)
            page.go_back(wait_until='networkidle')
            expect(page.get_by_role('heading', name=tr(locale, 'nav.principals'), exact=True)).to_be_visible()
            page.go_forward(wait_until='networkidle')
            expect(page.get_by_role('heading', name=tr(locale, 'nav.functions'), exact=True)).to_be_visible()
            page.screenshot(path=str(shots / f'i18n-{locale}-{width}.png'), full_page=True)

        # Consent uses real fixture requests. Dirty confirmation input is retained until the user finishes.
        env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': str(Path(temporary) / f'{locale}.key')}
        result = subprocess.run(['node', 'cli/runtime.mjs', 'connect', '--name', 'Test AI'], cwd=root,
                                env=env, capture_output=True, text=True, timeout=30, check=True)
        request = json.loads(result.stdout.split('\n\nKey file')[0])['request']
        page.goto(request['verification_uri'], wait_until='networkidle')
        expect(page.get_by_role('heading', name=tr(locale, 'client.access.allowAccess'), exact=True)).to_be_visible()
        code = page.get_by_label(tr(locale, 'client.request.confirmationCode'), exact=True)
        code.fill('0000-0000')
        page.locator('[data-action="change-language"]').select_option(other)
        expect(page.locator('.language-status')).to_be_visible()
        expect(page.locator('html')).to_have_attribute('lang', locale)
        expect(code).to_have_value('0000-0000')
        page.locator('[data-action="change-language"]').select_option(locale)
        expect(page.locator('.language-status')).to_be_hidden()
        code.fill(request['user_code'])
        page.get_by_role('button', name=tr(locale, 'client.access.allow'), exact=True).click()
        expect(page.get_by_role('heading', name=tr(locale, 'request.result.agentGranted'), exact=True)).to_be_visible()
        page.locator('[data-action="change-language"]').select_option(other)
        expect(page.get_by_role('heading', name=tr(other, 'request.result.agentGranted'), exact=True)).to_be_visible()
        assert not errors, errors
        context.close()
    browser.close()
    print('JA/EN locale detection, switching, email authentication, errors, consent, history and mobile layout passed.')
