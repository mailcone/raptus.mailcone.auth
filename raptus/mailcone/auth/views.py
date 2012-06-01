import grok
from grokcore import message
from megrok import navigation

from zope import interface
from zope import component
from zope.authentication.interfaces import IAuthentication, IUnauthenticatedPrincipal, ILogout

from raptus.mailcone.layout.views import Page, FormPage
from raptus.mailcone.layout.interfaces import IHeaderNavigation

from raptus.mailcone.auth import _
from raptus.mailcone.auth import interfaces


grok.templatedir('templates')



class Login(FormPage):
    grok.context(interface.Interface)
    grok.require(grok.Public)

    label = _('Login')
    prefix = 'loginform'
    form_fields = grok.Fields(interfaces.ILoginForm)
    
    def setUpWidgets(self, ignore_request=False):
        super(Login, self).setUpWidgets(ignore_request)
        self.widgets['camefrom'].type = 'hidden'
        if 'camefrom' in self.request.form:
            self.widgets['camefrom']._data = self.request.form['camefrom']

    @grok.action(_(u'Login'), name='login')
    def handle_login(self, **data):
        if component.getUtility(IAuthentication).authenticate(self.request) is None:
            message.send(_('Wrong Login or Password'))
        else:
            message.send(_('Login successful'))
            if data.get('camefrom', None):
                self.redirect(data.get('camefrom', ''))
            else:
                self.redirect(self.url(grok.getSite()))



class Logout(Page):
    grok.context(interface.Interface)
    grok.require(grok.Public)
    navigation.menuitem(IHeaderNavigation, _('logout'), order=30)

    def update(self):
        if not IUnauthenticatedPrincipal.providedBy(self.request.principal):
            auth = component.getUtility(IAuthentication)
            ILogout(auth).logout(self.request)

