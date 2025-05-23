###############################################################
###############################################################
# START OIDC Base
###############################################################
###############################################################


import json
import pprint
import time
from collections.abc import Callable
from typing import NotRequired, TypedDict

import jwt
import requests
from requests.exceptions import HTTPError

from contextual.v2.base import File, Http, HttpClient, WriterFn, maybe


class OIDCConfig(HttpClient):
    def __init__(self, domain: str):
        self.domain = domain
        self.well_known_url = f"https://{self.domain}/.well-known/openid-configuration"
        self._result: dict | None = None

    def __call__(self, http: Http) -> dict:
        if self._result is not None:
            return self._result

        resp = self.get(http, self.well_known_url)
        resp.raise_for_status()
        self._result = resp.json()
        return self._result


class OIDCBase(HttpClient):
    def __init__(
        self,
        oidc_fn: Callable[[Http], dict],
    ):
        self.oidc_fn = oidc_fn

    def jwks_uri(self, http: Http) -> str:
        return self.oidc_fn(http)["jwks_uri"]

    def token_endpoint(self, http: Http) -> str:
        return self.oidc_fn(http)["token_endpoint"]

    def userinfo_endpoint(self, http: Http) -> str:
        return self.oidc_fn(http)["userinfo_endpoint"]

    def device_authorization_endpoint(self, http: Http) -> str:
        return self.oidc_fn(http)["device_authorization_endpoint"]


class OIDCClient(OIDCBase):
    def __init__(
        self,
        oidc_fn: Callable[[Http], dict],
        client_id: str,
        audience: str,
        scopes: str,
    ):
        super().__init__(oidc_fn)
        self.client_id = client_id
        self.audience = audience
        self.scopes = scopes


###############################################################
###############################################################
# End OIDC Base
###############################################################
###############################################################

###############################################################
###############################################################
# START Token
###############################################################
###############################################################


class RefreshTokenFile(TypedDict):
    refresh_token: str


class Token(TypedDict):
    access_token: str
    expires_in: int
    id_token: NotRequired[str]
    refresh_token: NotRequired[str]
    scope: str
    token_type: str


type MaybeTokenFn[T] = Callable[[T], Token | None]
type TokenFn[T] = Callable[[T], Token]

type TokenResolver[T, U] = Callable[[T], TokenFn[U]]
type TokenWriter[T] = Callable[[Token], WriterFn[T]]


class RefreshFromFileOrDeviceCode(OIDCClient):
    def __call__(self, file: File) -> TokenFn[Http]:
        def side_effect(http: Http) -> Token:
            token = maybe(
                RefreshTokenFromFile(
                    self.oidc_fn,
                    self.client_id,
                    self.audience,
                    self.scopes,
                )(file)
            )(http)
            if token:
                return token

            token = DeviceCodeLogin(
                self.oidc_fn,
                self.client_id,
                self.audience,
                self.scopes,
            )(save_refresh_token_to_file, file)(http)
            if not token:
                raise Exception("No token found")

            return token

        return side_effect


class RefreshTokenFromFile(OIDCClient):
    def __call__(self, file: File) -> MaybeTokenFn[Http]:
        def side_effect(http: Http) -> Token | None:
            file.seek(0)
            token_file: RefreshTokenFile = json.load(file)
            resp = self.refresh_token(http, token_file["refresh_token"])
            resp.raise_for_status()
            return resp.json()

        return side_effect

    def refresh_token(self, http: Http, refresh_token: str) -> requests.Response:
        return self.post(
            http,
            self.token_endpoint(http),
            data={
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )


class DeviceCodeLogin(OIDCClient):
    def __call__[T](
        self, token_writer: TokenWriter[T], storage: T
    ) -> MaybeTokenFn[Http]:
        def side_effect(http: Http) -> Token | None:
            token = self.login(http)
            token_writer(token)(storage)
            return token

        return side_effect

    def login(self, http: Http) -> Token:
        """
        Login the user via the device code grant
        """
        resp = self.generate_device_code(http)
        device_code_request = resp.json()
        resp.raise_for_status()

        print()
        print(device_code_request["verification_uri_complete"])
        pprint.pprint(device_code_request)
        print()

        tries = 900 / 5
        while tries:
            error_code = None
            try:
                resp = self.device_code(http, device_code_request)
                token = resp.json()
                resp.raise_for_status()
                if "token_type" in token and token["token_type"] == "Bearer":
                    print("\n===========\nToken Data:")
                    pprint.pprint(token)

                    return token
            except HTTPError:
                error_code = token.get(
                    "errorCode", token.get("error", token.get("code"))
                )

            if not isinstance(error_code, str):
                raise Exception("Invalid Device Code Response")

            match error_code:
                case "authorization_pending":
                    time.sleep(5.0)
                case "slow_down":
                    time.sleep(5.0)
                case "expired_token":
                    raise Exception("Token Expired, try again.")
                case "access_denied":
                    raise Exception("Access Denied")
                case _:
                    raise Exception(f"Invalid Error Code {error_code}")
            tries -= 1
        raise Exception("Timeout, try again.")

    def generate_device_code(self, http: Http) -> requests.Response:
        return self.post(
            http,
            self.device_authorization_endpoint(http),
            data={
                "client_id": self.client_id,
                "scope": self.scopes,
                "audience": self.audience,
            },
        )

    def device_code(self, http: Http, data: dict) -> requests.Response:
        """
        {
            "device_code": "Ag_EE...ko1p",
            "user_code": "QTZL-MCBW",
            "verification_uri": "https://accounts.acmetest.org/activate",
            "verification_uri_complete": "https://accounts.acmetest.org/activate?user_code=QTZL-MCBW",
            "expires_in": 900,
            "interval": 5
        }
        """
        return self.post(
            http,
            self.token_endpoint(http),
            data={
                "client_id": self.client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": data["device_code"],
            },
        )


def save_refresh_token_to_file(token: Token) -> WriterFn[File]:
    def side_effect(file: File) -> None:
        file.seek(0)
        json.dump({"refresh_token": token["refresh_token"]}, file)
        file.truncate()

    return side_effect


###############################################################
###############################################################
# END Token
###############################################################
###############################################################

###############################################################
###############################################################
# Start Claims
###############################################################
###############################################################


class Claims(TypedDict):
    aud: str
    azp: str
    exp: int
    iat: int
    iss: str
    scope: str
    sub: str


type ClaimsFn[T] = Callable[[T], Claims]
type JWKSFn[T] = Callable[[T], jwt.PyJWKSet]


class JKWS(OIDCBase):
    def __call__(self, http: Http) -> jwt.PyJWKSet:
        resp = self.get(http, self.jwks_uri(http))
        resp.raise_for_status()
        data = resp.json()

        return jwt.PyJWKSet.from_dict(data)


class VerifyAccessToken[T]:
    def __init__(self, jwks_fn: JWKSFn[T], audience: str):
        self.jwks_fn = jwks_fn
        self.audience = audience

    def __call__(self, token_fn: TokenFn[T]) -> ClaimsFn[T]:
        def side_effect(client: T) -> Claims:
            token = token_fn(client)
            access_token = token["access_token"]
            unverified = jwt.decode_complete(
                access_token,
                options={"verify_signature": False},
            )
            header = unverified["header"]

            jwks_set = self.jwks_fn(client)
            signing_key = jwks_set[header["kid"]]

            data = jwt.decode(
                access_token,
                key=signing_key,
                audience=self.audience,
                algorithms=["RS256"],  # signing_algos,
            )
            print("\n===========\nVerified Claims:")
            pprint.pprint(data)

            return data

        return side_effect


###############################################################
###############################################################
# END Claims
###############################################################
###############################################################

###############################################################
###############################################################
# START Profile
###############################################################
###############################################################


class Profile(TypedDict):
    email: NotRequired[str]
    email_verified: NotRequired[str]
    name: NotRequired[str]
    nickname: NotRequired[str]
    picture: NotRequired[str]
    sub: str
    updated_at: int


type ProfileFn[T] = Callable[[T], Profile]
type ProfileResolver[T] = Callable[[TokenFn[T]], ProfileFn[T]]


class GetProfile(OIDCBase):
    def get_profile(self, token_fn: TokenFn[Http]) -> ProfileFn[Http]:
        def side_effect(http: Http) -> Profile:
            url = self.userinfo_endpoint(http)
            token_data = token_fn(http)
            token = token_data["access_token"]
            resp = self.get(http, url, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()

            data: Profile = resp.json()
            if not isinstance(data, dict):
                raise ValueError(
                    "Invalid Profile Content. "
                    f"expected: dict, got: {type(data).__name__}"
                )

            print("\n===========\nUser Profile:")
            pprint.pprint(data)

            return data

        return side_effect


###############################################################
###############################################################
# End Profile
###############################################################
###############################################################
