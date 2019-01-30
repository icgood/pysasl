
from . import ClientMechanism, ServerMechanism, ServerChallenge, \
    AuthenticationCredentials, ClientResponse
from typing import Optional, Tuple, Sequence


class PlainMechanism(ServerMechanism, ClientMechanism):
    def server_attempt(self, challenges: Sequence[ServerChallenge]) \
            -> Tuple[AuthenticationCredentials, Optional[bytes]]: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
