
from . import ClientMechanism, AuthenticationCredentials, ClientResponse
from typing import Sequence


class OAuth2Mechanism(ClientMechanism):
    @property
    def name(self) -> bytes: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
