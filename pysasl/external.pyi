
from . import AuthenticationCredentials, ClientMechanism, ServerMechanism, \
    ServerChallenge, ClientResponse
from typing import Text, Optional, Tuple, Sequence


class ExternalResult(AuthenticationCredentials):
    def __init__(self, authzid: Optional[Text] = ...) -> None: ...

class ExternalMechanism(ServerMechanism, ClientMechanism):
    def server_attempt(self, challenges: Sequence[ServerChallenge]) \
            -> Tuple[ExternalResult, Optional[bytes]]: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
