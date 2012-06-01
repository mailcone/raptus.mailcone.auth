import os
import grok
import datetime
import ConfigParser

from BTrees.LOBTree import LOBTree

from zope.formlib.form import applyData
from zope.pluggableauth.interfaces import ICredentialsPlugin
from zope.securitypolicy.interfaces import IPrincipalRoleManager
from zope.app.authentication.session import SessionCredentialsPlugin
from zope.pluggableauth.interfaces import IAuthenticatorPlugin, IAuthenticatorPlugin
from zope.pluggableauth.interfaces import IAuthenticatedPrincipalCreated, IPrincipalsAddedToGroup

from ldapadapter.utility import LDAPAdapter
from ldappas.interfaces import ILDAPAuthentication
from ldappas.authentication import PrincipalInfo as LDAPPrincipalInfo
from ldappas.authentication import LDAPAuthentication as BaseLDAPAuthentication

from raptus.mailcone.app.config import local_configuration



def get_config():
        config_file = local_configuration['ldap'].get('config_file', '')
        if os.path.isfile(config_file):
            parser = ConfigParser.ConfigParser(allow_no_value=True)
            parser.readfp(open(config_file))
            return dict(parser.items('ldap'))
        else:
            return local_configuration['ldap']



def setup_authentication(pau):
    pau.credentialsPlugins = ('credentials',)
    pau.authenticatorPlugins = ('ldap-authenticator',)



class LDAPConfiguration(grok.GlobalUtility, LDAPAdapter):
    grok.name('mailcone-authentication-ldap')

    def __init__(self):
        config = get_config()
        bool_states = ConfigParser.ConfigParser._boolean_states
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 389)
        self.useSSL = bool_states.get(config.get('useSSL', 'False'), False)
        self.bindDN = config.get('bindDN', '')
        self.bindPassword = config.get('bindPassword', '')



class SessionCredentialsPlugin(grok.GlobalUtility, SessionCredentialsPlugin):
    grok.provides(ICredentialsPlugin)
    grok.name('credentials')

    loginpagename = 'login'
    loginfield = 'loginform.login'
    passwordfield = 'loginform.password'



class LDAPAuthentication(BaseLDAPAuthentication, grok.GlobalUtility):
    grok.provides(IAuthenticatorPlugin)
    grok.name('ldap-authenticator')
    
    cache = LOBTree()

    def __init__(self):
        super(LDAPAuthentication, self).__init__()
        config = dict()
        self._config = get_config()
        
        fields = dict([(i.lower(), i) for i in ILDAPAuthentication])
        for key, value in self._config.iteritems():
            if not key.lower() in fields.keys():
                continue
            if not value:
                value = ILDAPAuthentication[fields[key]].default
            config[fields[key]] = value
        applyData(self, grok.Fields(ILDAPAuthentication), config)
        self.adapterName = 'mailcone-authentication-ldap'

    def authenticateCredentials(self, credentials):
        return self.use_cache(credentials, 'authenticateCredentials')

    def principalInfo(self, id):
       return self.use_cache(id, 'principalInfo')

    def use_cache(self, attr, func):
        """ allow caching for predefined time "cache_expire".
        """
        if isinstance(attr, dict):
            attr_key = hash(tuple(attr.iteritems()))
        else:
            attr_key = hash(attr)
        delta = datetime.timedelta(seconds=int(self._config.get('cache_expire')))
        compare = datetime.datetime.now() - delta
        for key, value in self.cache.iteritems():
            principal, time = value
            if time < compare:
                del self.cache[key]
        
        if attr_key in self.cache:
            principal, time = self.cache[attr_key]
            self.cache[attr_key] = (principal, datetime.datetime.now(),)
            return principal
        principal = getattr(super(LDAPAuthentication, self), func)(attr)
        if principal is not None:
            self.cache[attr_key] = (principal, datetime.datetime.now(),)
        return principal



@grok.subscribe(IAuthenticatedPrincipalCreated)
def ldap_assing_role_to_manager(event):
    if isinstance(event.info, LDAPPrincipalInfo):
        manager = IPrincipalRoleManager(grok.getSite())
        manager.assignRoleToPrincipal('mailcone.ldap.authentication', event.principal.id)


