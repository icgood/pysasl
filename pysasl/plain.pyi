
from . import ClientMechanism, ServerMechanism, ServerChallenge, \
    AuthenticationCredentials, ClientResponse
from typing import Sequence


class PlainMechanism(ServerMechanism, ClientMechanism):
    @property
    def name(self) -> bytes: ...
    @property
    def insecure(self) -> bool: ...
    @property
    def priority(self) -> int: ...
    def server_attempt(self, challenges: Sequence[ServerChallenge]) \
            -> AuthenticationCredentials: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
