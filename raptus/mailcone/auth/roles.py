import grok

from raptus.mailcone.auth import _




class RoleLDAPAuthentication(grok.Role):
    grok.name('mailcone.ldap.authentication')
    grok.title(_('LDAP Authentication'))
    grok.permissions('zope.View')