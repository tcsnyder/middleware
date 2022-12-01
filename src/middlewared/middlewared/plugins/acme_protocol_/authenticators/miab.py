import logging

import requests
from requests.auth import HTTPBasicAuth
from middlewared.schema import accepts, Dict, Str, ValidationErrors

from .base import Authenticator


logger = logging.getLogger(__name__)


class MiabAuthenticator(Authenticator):

    NAME = 'mail in a box'
    PROPAGATION_DELAY = 60
    SCHEMA = Dict(
        'miab',
        Str('server_url', empty=False, null=True, title='Server Url'),
        Str('username', empty=False, null=True, title='Username'),
        Str('password', empty=False, null=True, title='Password'),
    )

    def initialize_credentials(self):
        self.server_url = self.attributes.get('server_url')
        self.username = self.attributes.get('username')
        self.password = self.attributes.get('password')

    @staticmethod
    @accepts(SCHEMA)
    def validate_credentials(data):
        verrors = ValidationErrors()
        if not data.get('server_url'):
            verrors.add('server_url', 'Should be specified.')
        if not data.get('username'):
            verrors.add('username', 'Should be specified.')

        if not data.get('password'):
            verrors.add('password', 'Should be specified.')
        verrors.check()

    def _perform(self, domain, validation_name, validation_content):
        url = self.server_url + "/admin/dns/custom/_acme-challenge." + domain + "/txt"
        basic = HTTPBasicAuth(self.username, self.password)
        r = requests.post(url, validation_content, auth=basic)
        if r.status_code != 200:
            raise ValueError(url + '|' + str(r.status_code) + "|" + r.text)

    def _cleanup(self, domain, validation_name, validation_content):
        basic = HTTPBasicAuth(self.username, self.password)
        url = self.server_url + "/admin/dns/custom/_acme-challenge." + domain + "/txt"
        session.delete(url, auth=basic)
