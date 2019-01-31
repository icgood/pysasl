
from . import AuthenticationCredentials, ClientMechanism, ServerMechanism, \
    ServerChallenge, ClientResponse
from typing import Optional, Tuple, Sequence
from typing_extensions import Final


class CramMD5Result(AuthenticationCredentials):
    challenge: Final[bytes] = ...
    digest: Final[bytes] = ...
    def __init__(self, username: str, challenge: bytes,
                 digest: bytes) -> None: ...

class CramMD5Mechanism(ServerMechanism, ClientMechanism):
    def server_attempt(self, challenges: Sequence[ServerChallenge]) \
            -> Tuple[CramMD5Result, Optional[bytes]]: ...
    def client_attempt(self, creds: AuthenticationCredentials,
                       responses: Sequence[ClientResponse]) \
            -> ClientResponse: ...
