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
