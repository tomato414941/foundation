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
PICKER = '[data-action="change-language"]'


def tr(locale, key):
    return resources[locale]['translation'][key]


def check_display(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'horizontal overflow'
    assert not page.locator('body').inner_text().count('client.'), 'unresolved translation key'


def no_language_picker(page):
    expect(page.locator(PICKER)).to_have_count(0)


def open_menu(page, locale):
    """On a narrow screen the menu is behind its button."""
    button = page.get_by_role('button', name=tr(locale, 'nav.menu'), exact=True)
    if button.is_visible() and button.get_attribute('aria-expanded') != 'true':
        button.click()


def close_menu(page, locale):
    button = page.get_by_role('button', name=tr(locale, 'nav.menu'), exact=True)
    if button.is_visible() and button.get_attribute('aria-expanded') == 'true':
        button.click()


def account_language_picker(page, locale):
    expect(page).to_have_url(args.base + '/account')
    expect(page.get_by_role('heading', name=tr(locale, 'nav.account'), exact=True)).to_be_visible()
    expect(page.locator(PICKER)).to_have_count(1)
    expect(page.locator('.topbar').locator(PICKER)).to_have_count(0)
    picker = page.get_by_role('main').get_by_role('combobox', name=tr(locale, 'language.label'), exact=True)
    expect(picker).to_be_visible()
    expect(picker).to_have_value(locale)
    return picker


def switch_account_language(page, context, current, target):
    account_language_picker(page, current).select_option(target)
    expect(page.locator('html')).to_have_attribute('lang', target)
    account_language_picker(page, target)
    expect(page).to_have_title(tr(target, 'nav.account') + ' · Foundation')
    assert any(cookie['name'] == 'foundation_locale' and cookie['value'] == target for cookie in context.cookies())


with tempfile.TemporaryDirectory(prefix='foundation-i18n-ui-') as temporary, sync_playwright() as p:
    browser = p.chromium.launch(headless=True, **({'executable_path': args.executable} if args.executable else {}))

    # With no supported browser preference or cookie, Japanese remains the fallback.
    fallback = browser.new_context(locale='fr-FR')
    fallback_page = fallback.new_page()
    response = fallback_page.goto(args.base, wait_until='networkidle')
    assert '<html lang="ja">' in response.text()
    expect(fallback_page.locator('html')).to_have_attribute('lang', 'ja')
    expect(fallback_page.get_by_role('heading', name=tr('ja', 'client.signin.title'), exact=True)).to_be_visible()
    no_language_picker(fallback_page)
    fallback.close()

    for locale in ['ja', 'en']:
        other = 'en' if locale == 'ja' else 'ja'
        context = browser.new_context(locale='ja-JP' if locale == 'ja' else 'en-US', viewport={'width': 1280, 'height': 900}, permissions=['clipboard-read', 'clipboard-write'])
        page = context.new_page()
        virtual_authenticator(context, page)
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        response = page.goto(args.base, wait_until='networkidle')
        assert f'<html lang="{locale}">' in response.text(), 'server and client must start in the same locale'
        assert 'data-action="change-language"' not in response.text(), 'the public server-rendered shell has no picker'
        expect(page.get_by_role('heading', name=tr(locale, 'client.signin.title'), exact=True)).to_be_visible()
        expect(page.locator('html')).to_have_attribute('lang', locale)
        expect(page.get_by_role('link', name=tr(locale, 'server.docs.api'), exact=True)).to_be_visible()
        no_language_picker(page)
        check_display(page)

        # Sign-in and confirmation rely on automatic locale detection, without a language control.
        email = f'i18n-{locale}-{time.time_ns()}@example.test'
        page.get_by_label(tr(locale, 'client.signin.emailAddress'), exact=True).fill(email)
        expect(page.get_by_label(tr(locale, 'client.signin.emailAddress'), exact=True)).to_have_value(email)
        page.goto(args.base + '/signin/confirm#' + urlencode({'token': 'z' * 43, 'email': email}), wait_until='networkidle')
        no_language_picker(page)
        page.get_by_role('button', name=tr(locale, 'client.signin.title'), exact=True).click()
        expect(page.get_by_role('alert')).to_have_text(tr(locale, 'server.error.signinLinkExpired'))
        expect(page.locator('html')).to_have_attribute('lang', locale)
        no_language_picker(page)
        page.reload(wait_until='networkidle')
        expect(page.get_by_role('heading', name=tr(locale, 'client.signin.checkLink'), exact=True)).to_be_visible()
        no_language_picker(page)

        page.goto(args.base, wait_until='networkidle')
        page.get_by_label(tr(locale, 'client.signin.emailAddress'), exact=True).fill(email)
        page.get_by_role('button', name=tr(locale, 'client.signin.sendEmail'), exact=True).click()
        expect(page.get_by_role('heading', name=tr(locale, 'client.signin.checkEmail'), exact=True)).to_be_visible()
        no_language_picker(page)
        token = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()).rstrip(b'=').decode()
        page.goto(args.base + '/signin/confirm#' + urlencode({'token': token, 'email': email}), wait_until='networkidle')
        no_language_picker(page)
        page.get_by_role('button', name=tr(locale, 'client.signin.title'), exact=True).click()
        expect(page.get_by_role('heading', name='Foundation', exact=True)).to_be_visible()
        no_language_picker(page)

        # Even /account has no picker until its signed-in content has loaded.
        for path in ['services', 'account']:
            pending_overview = []
            page.route('**/v1/principals/me', lambda route: pending_overview.append(route))
            with page.expect_request('**/v1/principals/me'):
                response = page.goto(args.base + '/' + path, wait_until='domcontentloaded')
            assert 'data-action="change-language"' not in response.text(), 'pending server-rendered shells have no picker'
            expect(page.get_by_role('main')).to_have_attribute('aria-busy', 'true')
            expect(page.locator('html')).to_have_attribute('lang', locale)
            no_language_picker(page)
            assert pending_overview, 'overview is held while checking the pending shell'
            for route in pending_overview:
                route.continue_()
            page.unroute('**/v1/principals/me')
            expect(page.get_by_role('main')).not_to_have_attribute('aria-busy', 'true')
            expect(page.get_by_role('heading', name=tr(locale, 'nav.' + path), exact=True)).to_be_visible()
            expect(page.locator('#signin-form')).to_have_count(0)
            if path == 'account':
                account_language_picker(page, locale)
            else:
                no_language_picker(page)

        # The account setting takes precedence over Accept-Language, including after a reload.
        switch_account_language(page, context, locale, other)
        response = page.reload(wait_until='networkidle')
        assert f'<html lang="{other}">' in response.text(), 'the explicit cookie overrides the browser preference'
        account_language_picker(page, other)
        page.get_by_role('navigation').get_by_role('link', name=tr(other, 'nav.services'), exact=True).click()
        expect(page.get_by_role('heading', name=tr(other, 'nav.services'), exact=True)).to_be_visible()
        no_language_picker(page)
        page.get_by_role('link', name=tr(other, 'nav.account'), exact=True).click()
        account_language_picker(page, other)

        # Existing account controls still work in the selected language and retain the account's ID.
        owner_id = context.request.get(args.base + '/v1/principals/me').json()['principal']['id']
        expect(page.get_by_role('region', name=tr(other, 'client.account.id'), exact=True).locator('code')).to_have_text(owner_id)
        page.get_by_role('button', name=tr(other, 'client.account.copyId'), exact=True).click()
        expect(page.locator('#notice')).to_have_text(tr(other, 'client.common.copied'))
        page.get_by_role('button', name=tr(other, 'client.handover.action'), exact=True).click()
        dialog = page.get_by_role('dialog')
        expect(dialog.get_by_role('heading', name=tr(other, 'client.handover.title'), exact=True)).to_be_visible()
        dialog.get_by_label(tr(other, 'client.handover.recipientId'), exact=True).fill('fixture-recipient')
        dialog.get_by_role('button', name=tr(other, 'client.common.close'), exact=True).click()
        expect(dialog).to_be_hidden()
        switch_account_language(page, context, other, locale)
        expect(page.get_by_role('region', name=tr(locale, 'client.account.id'), exact=True).locator('code')).to_have_text(owner_id)

        # A PRF-backed passkey keeps navigation in-page; successful sign-in releases its busy guard.
        page.get_by_role('button', name=tr(locale, 'client.passkey.add'), exact=True).click()
        dialog.get_by_label(tr(locale, 'client.common.name'), exact=True).fill('i18n device')
        dialog.get_by_role('button', name=tr(locale, 'client.common.add'), exact=True).click()
        expect(dialog).to_be_hidden()
        expect(page.get_by_role('heading', name='i18n device', exact=True)).to_be_visible()
        switch_account_language(page, context, locale, other)
        page.get_by_role('button', name=tr(other, 'nav.signout'), exact=True).click()
        expect(page.get_by_role('heading', name=tr(other, 'client.signin.title'), exact=True)).to_be_visible()
        no_language_picker(page)
        response = page.reload(wait_until='networkidle')
        assert f'<html lang="{other}">' in response.text(), 'the locale preference also persists when signed out'
        expect(page.get_by_role('heading', name=tr(other, 'client.signin.title'), exact=True)).to_be_visible()
        no_language_picker(page)
        page.get_by_role('button', name=tr(other, 'client.signin.withPasskey'), exact=True).click()
        account_language_picker(page, other)
        switch_account_language(page, context, other, locale)

        # All primary pages, history, accessible titles, desktop and narrow mobile layouts.
        for width in [1280, 390, 320]:
            page.set_viewport_size({'width': width, 'height': 900})
            open_menu(page, locale)
            page.get_by_role('link', name=tr(locale, 'nav.account'), exact=True).click()
            account_language_picker(page, locale)
            switch_account_language(page, context, locale, other)
            check_display(page)
            switch_account_language(page, context, other, locale)
            check_display(page)
            page.screenshot(path=str(shots / f'i18n-account-{locale}-{width}.png'), full_page=True)
            for path in ['services', 'secrets', 'objects', 'principals', 'functions']:
                label = tr(locale, 'nav.' + path)
                open_menu(page, locale)
                page.get_by_role('navigation').get_by_role('link', name=label, exact=True).click()
                expect(page.get_by_role('heading', name=label, exact=True)).to_be_visible()
                expect(page).to_have_title(label + ' · Foundation')
                open_menu(page, locale)
                expect(page.get_by_role('navigation').get_by_role('link', name=label, exact=True)).to_have_attribute('aria-current', 'page')
                close_menu(page, locale)
                no_language_picker(page)
                check_display(page)
            page.go_back(wait_until='networkidle')
            expect(page.get_by_role('heading', name=tr(locale, 'nav.principals'), exact=True)).to_be_visible()
            no_language_picker(page)
            page.go_forward(wait_until='networkidle')
            expect(page.get_by_role('heading', name=tr(locale, 'nav.functions'), exact=True)).to_be_visible()
            no_language_picker(page)
            page.screenshot(path=str(shots / f'i18n-{locale}-{width}.png'), full_page=True)

        # Consent uses real fixture requests in the saved locale, with no language control at any stage.
        env = {**os.environ, 'FOUNDATION_URL': args.base, 'FOUNDATION_RUNTIME_KEY_FILE': str(Path(temporary) / f'{locale}.key')}
        subprocess.run(['node', 'cli/runtime.mjs', 'init', '--name', 'Test AI'], cwd=root, env=env, capture_output=True, text=True, timeout=30, check=True)
        result = subprocess.run(['node', 'cli/runtime.mjs', 'join'], cwd=root, env=env, capture_output=True, text=True, timeout=30, check=True)
        request = json.loads(result.stdout)['request']
        page.goto(request['verification_uri'], wait_until='networkidle')
        expect(page.get_by_role('heading', name=tr(locale, 'client.access.allowAccess'), exact=True)).to_be_visible()
        expect(page.locator('html')).to_have_attribute('lang', locale)
        no_language_picker(page)
        code = page.get_by_label(tr(locale, 'client.request.confirmationCode'), exact=True)
        code.fill('0000-0000')
        expect(code).to_have_value('0000-0000')
        no_language_picker(page)
        code.fill(request['user_code'])
        pending_grant = []
        page.route('**/v1/requests/*/grant', lambda route: pending_grant.append(route))
        allow = page.get_by_role('button', name=tr(locale, 'client.access.allow'), exact=True)
        with page.expect_request('**/v1/requests/*/grant'):
            allow.click()
        expect(allow).to_be_disabled()
        expect(code).to_have_value(request['user_code'])
        no_language_picker(page)
        assert pending_grant, 'grant is held while checking the busy consent form'
        for route in pending_grant:
            route.continue_()
        page.unroute('**/v1/requests/*/grant')
        expect(page.get_by_role('heading', name=tr(locale, 'request.result.agentGranted'), exact=True)).to_be_visible()
        no_language_picker(page)
        page.reload(wait_until='networkidle')
        expect(page.get_by_role('heading', name=tr(locale, 'request.result.agentGranted'), exact=True)).to_be_visible()
        no_language_picker(page)
        check_display(page)
        assert not errors, errors
        context.close()
    browser.close()
    print('JA/EN detection, Japanese fallback, account-only switching, cookie persistence, authentication, account controls, consent, history and mobile layout passed.')
