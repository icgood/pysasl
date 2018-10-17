
from . import AuthenticationCredentials, ClientMechanism, ServerMechanism, \
    ServerChallenge, ClientResponse
from typing import Sequence, Optional


class ExternalResult(AuthenticationCredentials):
    def __init__(self, authzid: Optional[str]) -> None: ...

class ExternalMechanism(ServerMechanism, ClientMechanism):
    def server_attempt(self, challenges: Sequence[ServerChallenge]) \
            -> ExternalResult: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
