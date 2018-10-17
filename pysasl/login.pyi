
from . import ClientMechanism, ServerMechanism, ServerChallenge, \
    AuthenticationCredentials, ClientResponse
from typing import Sequence


class LoginMechanism(ServerMechanism, ClientMechanism):
    def server_attempt(self, challenges: Sequence[ServerChallenge]) \
            -> AuthenticationCredentials: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
