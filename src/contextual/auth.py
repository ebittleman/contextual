#####################################################################
#####################################################################
# START Auth Module
#####################################################################
#####################################################################


import json
import pprint
import time
from collections.abc import Callable
from typing import Any, NotRequired, TextIO, TypedDict

import jwt
import requests
from requests import Session as HttpSession
from requests.exceptions import HTTPError

from contextual.base import (
    CacheReadContext,
    CacheWriteContext,
    Context,
    HttpContext,
    MaybeContext,
    Result,
    cache_read,
    cache_write,
    class_side_effect,
    safe_context,
    side_effect,
)


class DeviceCode(TypedDict):
    device_code: str
    expires_in: int
    interval: int
    user_code: str
    verification_uri: str
    verification_uri_complete: str


class OIDCToken(TypedDict):
    access_token: str
    expires_in: int
    id_token: NotRequired[str]
    refresh_token: NotRequired[str]
    scope: str
    token_type: str


class Claims(TypedDict):
    aud: str
    azp: str
    exp: int
    iat: int
    iss: str
    scope: str
    sub: str


class Profile(TypedDict):
    email: NotRequired[str]
    email_verified: NotRequired[str]
    name: NotRequired[str]
    nickname: NotRequired[str]
    picture: NotRequired[str]
    sub: str
    updated_at: int


class OIDCConfig:
    def __init__(self, domain: str):
        self.domain = domain
        self.well_known_url = f"https://{self.domain}/.well-known/openid-configuration"
        self._result: dict | None = None

    def __call__(self, http: HttpSession) -> Result[dict]:
        if self._result is not None:
            return Result(self._result)

        try:
            resp = http.get(self.well_known_url)
            resp.raise_for_status()
            self._result = resp.json()
            return Result(self._result)
        except Exception as exc:
            return Result(exc=exc)


@side_effect
def jwks(http: HttpSession, oidc: HttpContext[dict]) -> jwt.PyJWKSet:
    oidc_result = oidc(http).unwrap()
    if "jwks_uri" not in oidc_result:
        raise Exception("JWKS URI not available.")

    resp = http.get(oidc_result["jwks_uri"])
    resp.raise_for_status()
    data = resp.json()

    return jwt.PyJWKSet.from_dict(data)


@side_effect
def decode_access_token(
    http: HttpSession,
    jwks_ctx: HttpContext[jwt.PyJWKSet],
    token_ctx: HttpContext[dict],
    audience: str,
) -> Claims:
    token_data = token_ctx(http).unwrap()
    token = token_data["access_token"]
    unverified = jwt.decode_complete(
        token,
        options={"verify_signature": False},
    )
    header = unverified["header"]

    jwks_set = jwks_ctx(http).unwrap()
    signing_key = jwks_set[header["kid"]]

    data = jwt.decode(
        token,
        key=signing_key,
        audience=audience,
        algorithms=["RS256"],  # signing_algos,
    )
    print("\n===========\nVerified Claims:")
    pprint.pprint(data)

    return data


@side_effect
def get_user_profile(
    http: HttpSession,
    oidc_ctx: HttpContext[dict],
    token_ctx: HttpContext[dict],
) -> Profile:
    oidc = oidc_ctx(http).unwrap()

    if "userinfo_endpoint" not in oidc:
        raise Exception("Invalid OIDC payload")
    url = oidc["userinfo_endpoint"]

    token_data = token_ctx(http).unwrap()
    token = token_data["access_token"]
    resp = http.get(url, headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()

    data: Profile = resp.json()
    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid Profile Content. expected: dict, got: {type(data).__name__}"
        )

    print("\n===========\nUser Profile:")
    pprint.pprint(data)

    return data


class GetToken:
    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str | None = None,
        protocol: str = "https",
    ) -> None:
        self.protocol = protocol
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret

    def _post(
        self,
        session: HttpSession,
        url: str,
        data: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        return session.post(url, data=data, headers=headers)

    @class_side_effect
    def generate_device_code(
        self, session: HttpSession, scope: str, audience: str
    ) -> requests.Response:
        return self._post(
            session,
            f"{self.protocol}://{self.domain}/oauth/device/code",
            data={
                "client_id": self.client_id,
                "scope": scope,
                "audience": audience,
            },
        )

    @class_side_effect
    def device_code(self, session: HttpSession, data: dict) -> requests.Response:
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
        return self._post(
            session,
            f"{self.protocol}://{self.domain}/oauth/token",
            data={
                "client_id": self.client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": data["device_code"],
            },
        )

    @class_side_effect
    def refresh_token(
        self, session: HttpSession, refresh_token: str
    ) -> requests.Response:
        return self._post(
            session,
            f"{self.protocol}://{self.domain}/oauth/token",
            data={
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )


@side_effect
def use_refresh_token(
    session: HttpSession,
    get_token: GetToken,
    refresh_token: str,
) -> OIDCToken:
    """
    Trade a refresh token for a jwt
    """
    resp = get_token.refresh_token(refresh_token)(session).unwrap()
    resp.raise_for_status()

    token: OIDCToken = resp.json()
    if "refresh_token" not in token:
        token["refresh_token"] = refresh_token

    print("\n===========\nToken Data:")
    pprint.pprint(token)

    return token


@side_effect
def refresh_token_from_file(
    file: TextIO,
    get_token: GetToken,
) -> HttpContext[OIDCToken]:
    data = json.load(file)
    if "refresh_token" not in data:
        raise Exception("Refresh Token Not Found In File")
    return use_refresh_token(get_token, data["refresh_token"])


@side_effect
def device_code_login(
    session: HttpSession,
    get_token: GetToken,
    audience: str,
    scopes: str,
) -> OIDCToken:
    """
    Login the user via the device code grant
    """
    resp = get_token.generate_device_code(scopes, audience)(session).unwrap()
    device_code_request = resp.json()
    resp.raise_for_status()

    print()
    print(device_code_request["verification_uri_complete"])
    pprint.pprint(device_code_request)
    print()

    tries = 10
    while tries:
        error_code = None
        try:
            resp = get_token.device_code(device_code_request)(session).unwrap()
            token = resp.json()
            resp.raise_for_status()
            if "token_type" in token and token["token_type"] == "Bearer":
                print("\n===========\nToken Data:")
                pprint.pprint(token)

                return token
        except HTTPError:
            error_code = token.get("errorCode", token.get("error", token.get("code")))

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


@side_effect
def try_refresh_or_login[T](
    client: T,
    refresh_token_ctx: MaybeContext[T, OIDCToken],
    login_ctx: MaybeContext[T, OIDCToken],
) -> OIDCToken | None:
    token = refresh_token_ctx(client).unwrap()
    if token is not None:
        return token

    return login_ctx(client).unwrap()


@side_effect
def save_refresh_token(file: TextIO | None, token: OIDCToken) -> None:
    if not file:
        raise Exception("File not found")
    if "refresh_token" not in token:
        raise Exception("Cannot save refresh_token, not present in token")
    file.seek(0)
    json.dump({"refresh_token": token["refresh_token"]}, file)
    file.truncate()


def save_refresh_token_to_file[T](
    source: MaybeContext[T, OIDCToken],
) -> CacheWriteContext[T, TextIO, OIDCToken]:
    return cache_write(source, save_refresh_token)


def refresh_token_reader(
    get_token: GetToken,
) -> Callable[[HttpSession], Context[TextIO | None, OIDCToken | None]]:
    def context(http: HttpSession) -> Context[TextIO | None, OIDCToken | None]:
        def inner(file: TextIO | None) -> Result[OIDCToken | None]:
            if not file:
                return Result(None)

            try:
                refresh_token_ctx = refresh_token_from_file(get_token)(file).unwrap()
                return safe_context(
                    refresh_token_ctx,
                    "Problem using refresh token.",
                )(http)
            except Exception as exc:
                print("WARNING :: Problem Reading Refresh Token File.", str(exc))
                return Result(None)

        return inner

    return context


def token_context(
    get_token: GetToken,
    audience: str,
    scopes: str,
) -> CacheReadContext[HttpSession, TextIO | None, OIDCToken]:
    def context(http: HttpSession, file: TextIO | None) -> Result[OIDCToken | None]:
        refresh_token_ctx = refresh_token_reader(get_token)(http)
        login_ctx = safe_context(
            device_code_login(get_token, audience, scopes),
            "Problem logging in.",
        )
        login_writer_ctx = cache_write(login_ctx, save_refresh_token)

        return cache_read(login_writer_ctx, refresh_token_ctx)(http, file)

    return context


#####################################################################
#####################################################################
# END Auth Module
#####################################################################
#####################################################################
