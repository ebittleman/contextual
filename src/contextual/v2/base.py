import json
import os
import pprint
import time
from functools import wraps
from typing import Any, Callable, NotRequired, TextIO, TypedDict

import jwt
import requests
import sqlalchemy.orm
from requests.exceptions import HTTPError
from sqlalchemy import String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

###############################################################
###############################################################
# START Common
###############################################################
###############################################################


def remember[T, U](fn: Callable[[T], U]) -> Callable[[T], U]:
    result = None

    @wraps(fn)
    def side_effect(x: T) -> U:
        nonlocal result
        if result is None:
            result = fn(x)
        return result

    return side_effect


def maybe[**P, T](fn: Callable[P, T]) -> Callable[P, T | None]:
    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            print("Warning ::", str(exc))
            return None

    return wrapper


type Http = requests.Session
type File = TextIO
type Db = sqlalchemy.orm.Session

type WriterFn[T] = Callable[[T], None]

###############################################################
###############################################################
# END Common
###############################################################
###############################################################

###############################################################
###############################################################
# START Http
###############################################################
###############################################################


class HttpClient:
    @staticmethod
    def get(
        http: Http,
        url: str,
        params: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        """
        Gets a url.
        TODO: Add common error handling/retries
        """
        return http.get(url, params=params, headers=headers)

    @staticmethod
    def post(
        http: Http,
        url: str,
        data: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        """
        Posts to url.
        TODO: Add common error handling/retries
        """
        return http.post(url, data=data, headers=headers)


###############################################################
###############################################################
# END Http
###############################################################
###############################################################

###############################################################
###############################################################
# START OIDC Base
###############################################################
###############################################################


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


class OIDCClient(HttpClient):
    def __init__(
        self,
        oidc_fn: Callable[[Http], dict],
        client_id: str,
        audience: str,
        scopes: str,
    ):
        self.oidc_fn = oidc_fn
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
        url = self.oidc_fn(http)["token_endpoint"]
        return self.post(
            http,
            url,
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
        url = self.oidc_fn(http)["device_authorization_endpoint"]
        return self.post(
            http,
            url,
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
        url = self.oidc_fn(http)["token_endpoint"]
        return self.post(
            http,
            url,
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


class JKWS(HttpClient):
    def __init__(self, oidc_fn: OIDCConfig):
        self.oidc_fn = oidc_fn

    def __call__(self, http: Http) -> jwt.PyJWKSet:
        oidc_result = self.oidc_fn(http)
        if "jwks_uri" not in oidc_result:
            raise Exception("JWKS URI not available.")

        resp = self.get(http, oidc_result["jwks_uri"])
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


class GetProfile(HttpClient):
    def __init__(self, oidc_fn: OIDCConfig):
        self.oidc_fn = oidc_fn

    def get_profile(self, token_fn: TokenFn[Http]) -> ProfileFn[Http]:
        def side_effect(http: Http) -> Profile:
            oidc = self.oidc_fn(http)

            if "userinfo_endpoint" not in oidc:
                raise Exception("Invalid OIDC payload")
            url = oidc["userinfo_endpoint"]

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

###############################################################
###############################################################
# START User
###############################################################
###############################################################


class Base(DeclarativeBase):
    """Base class for ORM Models"""


class User(Base):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(primary_key=True)
    version_id: Mapped[int] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    email: Mapped[str] = mapped_column(String(256), nullable=False)
    external_id: Mapped[str] = mapped_column(String(256), nullable=True)

    __mapper_args__ = {"version_id_col": version_id}

    def __repr__(self) -> str:
        return (
            "User:\n"
            f"  id: {self.id}\n"
            f"  version: {self.version_id}\n"
            f"  name: {self.name}\n"
            f"  email: {self.email}\n"
            f"  external_id: {self.external_id}\n"
        )


type UserFn[T] = Callable[[T], User]
type MaybeUserFn[T, U] = Callable[[T, U], User | None]
type UserCacheFn[T, U] = Callable[[T, U], User]

type UserResolver[T, U] = Callable[[TokenFn[T], ProfileResolver[T]], UserCacheFn[T, U]]


def save_user_to_db(user) -> UserFn[Db]:
    def side_effect(db: Db) -> User:
        if not user.id:
            db.add(user)
        db.flush()
        return user

    return side_effect


###############################################################
###############################################################
# End User
###############################################################
###############################################################

###############################################################
###############################################################
# START User + Auth
###############################################################
###############################################################


def get_user_from_db[T](
    claims_fn: ClaimsFn[T],
) -> MaybeUserFn[T, Db]:
    def side_effect(client: T, db: Db) -> User | None:
        claims = claims_fn(client)
        stmt = select(User).where(User.external_id == claims["sub"])
        return db.scalars(stmt).one_or_none()

    return side_effect


def user_from_profile(profile: Profile) -> User:
    return User(
        name=profile["name"],
        email=profile["email"],
        external_id=profile["sub"],
    )


class DefaultUserResolver[T]:
    def __init__(self, jwks_fn: JWKSFn[T], audience: str):
        self.jwks_fn = jwks_fn
        self.audience = audience

    def __call__(
        self, token_fn: TokenFn[T], profile_fn: ProfileResolver[T]
    ) -> UserCacheFn[T, Db]:
        def side_effect(client: T, db: Db) -> User:
            claims_fn = VerifyAccessToken(self.jwks_fn, self.audience)(token_fn)
            user = get_user_from_db(claims_fn)(client, db)
            if user:
                return user
            user = user_from_profile(profile_fn(token_fn)(client))
            return save_user_to_db(user)(db)

        return side_effect


def get_user_from_token[T, U, V](
    token_resolver: TokenResolver[T, U],
    profile_resolver: ProfileResolver[U],
    user_resolver: UserResolver[U, V],
) -> Callable[[T, U, V], User]:
    def side_effect(token_storage: T, remote_client: U, user_storage: V) -> User:
        token_fn = remember(token_resolver(token_storage))
        fn = user_resolver(token_fn, profile_resolver)
        return fn(remote_client, user_storage)

    return side_effect


###############################################################
###############################################################
# End User + Auth
###############################################################
###############################################################


DOMAIN = os.getenv("DOMAIN")
CLIENT_ID = os.getenv("CLIENT_ID")
AUDIENCE = os.getenv("AUDIENCE")


engine = create_engine(
    "sqlite:///database.db",
    connect_args={"autocommit": False},
)


def main():
    Base.metadata.create_all(engine)

    refresh_token_file = "refresh_token.json"
    scopes = "openid profile email offline_access"

    oidc_fn = remember(OIDCConfig(DOMAIN))
    jwks_fn = remember(JKWS(oidc_fn))

    token_resolver = RefreshFromFileOrDeviceCode(
        oidc_fn,
        CLIENT_ID,
        AUDIENCE,
        scopes,
    )
    profile_resolver = GetProfile(oidc_fn)
    user_resolver = DefaultUserResolver(jwks_fn, AUDIENCE)

    authenticated_user = get_user_from_token(
        token_resolver, profile_resolver, user_resolver
    )

    with (
        open(refresh_token_file, mode="a+", encoding="utf8") as file,
        requests.Session() as http,
        sqlalchemy.orm.Session(engine) as db,
    ):
        user = authenticated_user(file, http, db)
        print(user)


if __name__ == "__main__":
    main()
