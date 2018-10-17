
from . import ClientMechanism, AuthenticationCredentials, ClientResponse
from typing import Sequence


class OAuth2Mechanism(ClientMechanism):
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
