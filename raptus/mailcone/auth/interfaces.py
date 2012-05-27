from zope import schema
from zope import interface

from raptus.mailcone.auth import _





class ILoginForm(interface.Interface):
    login = schema.BytesLine(title=_('Username'), required=True)
    password = schema.Password(title=_('Password'), required=True)



