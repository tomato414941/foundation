# Steps the browser tests share: starting a connection from the services page.


def start_connect(page, service, way=None):
    """Opens the service's connect dialog from the services page: add a service and choose it. The dialog opens on
    the first way; another way is chosen from the buttons under it."""
    page.get_by_role('button', name='サービスを追加', exact=True).click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_label('サービスを探す', exact=True).fill(service)
    dialog.get_by_role('button', name=service, exact=True).click()
    if way:
        dialog.get_by_role('button', name=way).click()
    return dialog


# Secrets are sealed by the browser with the owner's key, which a passkey yields; what a test places through the
# API is handed to Foundation's principal to seal, once the owner has made it their agent; and what is kept is read
# back the way a command gets it, injected.
import base64
import json
import types
from playwright.sync_api import expect


def open_menu(page):
    """On a narrow screen the menu is behind its button; on a wide one it is beside the page and there is no button."""
    button = page.get_by_role('button', name='メニュー', exact=True)
    if button.is_visible():
        button.click()


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def virtual_authenticator(context, page):
    """Chromium's virtual authenticator as the device's passkey, yielding a PRF so the owner's key can be made from it.
    WebAuthn needs a hostname: pages using this reach the fixture as localhost."""
    cdp = context.new_cdp_session(page)
    cdp.send('WebAuthn.enable')
    cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
                                                              'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True, 'hasPrf': True}})
    return cdp


def make_key(page, base, name='テスト端末'):
    """A passkey added from the account page makes the owner's key; the page keeps it open until it is loaded anew."""
    page.goto(base + '/account', wait_until='networkidle')
    page.get_by_role('button', name='パスキーを追加').click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_label('名前', exact=True).fill(name)
    dialog.get_by_role('button', name='追加', exact=True).click()
    expect(page.get_by_role('region', name='パスキー').get_by_role('heading', name=name, exact=True)).to_be_visible()


def unlock(page, base):
    """The secrets page: listing and adding need no key, and the page says nothing of one; a value asks the passkey."""
    page.goto(base + '/secrets', wait_until='networkidle')
    expect(page.get_by_role('button', name='追加', exact=True)).to_be_enabled()
    expect(page.get_by_text('鍵', exact=False)).to_have_count(0)


def hand_to_foundation(page):
    """Foundation made the owner's agent. The web offers no way to do it; it is a line drawn through the API."""
    base = page.url.split('/', 3)[0] + '//' + page.url.split('/', 3)[2]
    allow_foundation(page.request, base)
    page.reload(wait_until='networkidle')


def allow_foundation(request, base, headers=None):
    """The same, through the API, for a owner signed in without a key."""
    agent = request.get(base + '/v1/principals/agent', headers=headers or {}).json()['principal']['id']
    me = request.get(base + '/v1/principals/me', headers=headers or {}).json()['principal']['id']
    drawn = request.post(base + '/v1/relations', data=json.dumps({'subject': agent, 'relation': 'agent', 'object_type': 'principal', 'object_id': me}),
                         headers={'content-type': 'application/json', 'origin': base, **(headers or {})})
    assert drawn.ok, drawn.text()


def plain(value):
    """The body that places a secret unsealed, for Foundation's principal to seal."""
    return json.dumps({'plain': b64url(value if isinstance(value, bytes) else value.encode())})


def injected(request, base, name, headers=None, as_=None):
    """What is kept under a name, as a command would get it: the bytes, with status and text like a response."""
    response = request.post(base + '/v1/injections' + ('?as=' + as_ if as_ else ''), data=json.dumps({'names': [{'name': name, 'as': 'VALUE', 'filename': 'value'}]}),
                            headers={'content-type': 'application/json', 'origin': base, **(headers or {})})
    value = base64.b64decode(response.json()['injection']['files'][0]['content']) if response.ok else b''
    return types.SimpleNamespace(status=response.status, body=lambda: value, text=lambda: value.decode())
