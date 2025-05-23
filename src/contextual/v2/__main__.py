import os

import requests
import sqlalchemy
from sqlalchemy import create_engine

from contextual.v2.app import (
    Base,
    DefaultUserResolver,
    get_user_from_token,
)
from contextual.v2.authentication import (
    JKWS,
    GetProfile,
    OIDCConfig,
    RefreshFromFileOrDeviceCode,
)
from contextual.v2.base import remember

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
