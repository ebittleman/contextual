import json
import os
from typing import Iterable, TextIO

from requests import Session as HttpSession
from sqlalchemy import String, create_engine, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from contextual.auth import (
    GetToken,
    OIDCConfig,
    Profile,
    decode_access_token,
    get_user_profile,
    jwks,
    token_context,
)
from contextual.base import (
    Base,
    CacheReadContext,
    CacheWriteContext,
    Context,
    DbContext,
    HttpContext,
    MaybeContext,
    Result,
    binop_swap,
    cache_read,
    cache_write,
    lazy_text_io,
    remember,
    side_effect,
)

#####################################################################
#####################################################################
# Start User Module
#####################################################################
#####################################################################


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


@side_effect
def get_user(session: Session, user_id: int) -> User | None:
    return session.get(User, user_id)


@side_effect
def get_user_by_email(session: Session, email: str) -> User | None:
    stmt = select(User).where(User.email == email)
    return session.scalars(stmt).one_or_none()


@side_effect
def get_user_by_external_id(session: Session, external_id: str) -> User | None:
    stmt = select(User).where(User.external_id == external_id)
    return session.scalars(stmt).one_or_none()


@side_effect
def get_user_by_name(session: Session, name: str) -> User | None:
    stmt = select(User).where(User.name == name)
    return session.scalars(stmt).one_or_none()


@side_effect
def save_users(session: Session, users: Iterable[User]) -> None:
    for user in users:
        if not user.id:
            session.add(user)
    session.flush()


def save_user(user: User) -> DbContext[None]:
    return save_users([user])


def save_user_to_db[T](
    source: MaybeContext[T, User],
) -> CacheWriteContext[T, Session, User]:
    return cache_write(source, save_user)


@side_effect
def load_user(file: TextIO, email: str) -> User | None:
    user_options = json.load(file)
    kwargs = user_options.copy()
    kwargs["email"] = email
    return User(**kwargs)


@side_effect
def user_from_profile[T](
    client: T,
    profile_ctx: Context[T, Profile],
) -> User | None:
    profile_data = profile_ctx(client).unwrap()
    return User(
        name=profile_data["name"],
        email=profile_data["email"],
        external_id=profile_data["sub"],
    )


#####################################################################
#####################################################################
# END User Module
#####################################################################
#####################################################################

#####################################################################
#####################################################################
# START Application Module
#####################################################################
#####################################################################

engine = create_engine(
    "sqlite:///database.db",
    connect_args={"autocommit": False},
)


def read_from_db_or_create_from_file(
    email: str,
) -> CacheReadContext[TextIO, Session, User]:
    file_user = cache_write(
        load_user(email),
        save_user,
    )
    database_user = get_user_by_email(email)

    return cache_read(file_user, database_user)


def read_from_db_or_create_from_external_profile(
    verified_claims_ctx: HttpContext[dict],
    source_user: CacheWriteContext[HttpSession, Session, User],
) -> CacheReadContext[HttpSession, Session, User]:
    def context(http: HttpSession, db: Session) -> Result[User | None]:
        verified_claims = verified_claims_ctx(http).unwrap()
        database_user = get_user_by_external_id(verified_claims["sub"])

        return cache_read(source_user, database_user)(http, db)

    return context


# REFRESH_TOKEN = ""


DOMAIN = os.getenv("DOMAIN")
CLIENT_ID = os.getenv("CLIENT_ID")
AUDIENCE = os.getenv("AUDIENCE")


def main():
    Base.metadata.create_all(engine)

    refresh_token_file = "refresh_token.json"
    scopes = "openid profile email offline_access"

    oidc_ctx = OIDCConfig(DOMAIN)
    get_token = GetToken(oidc_ctx.domain, CLIENT_ID)

    with (
        HttpSession() as http,
        lazy_text_io(refresh_token_file) as refresh_token_file,
    ):
        token_ctx = remember(
            binop_swap(
                token_context(get_token, AUDIENCE, scopes),
                refresh_token_file,
            )
        )
        token_ctx(http).unwrap()

    # refresh_token_ctx = use_refresh_token(get_token, REFRESH_TOKEN)
    # refresh_token_ctx = safe_context(refresh_token_ctx, "Problem using refresh token.")
    # login_ctx = device_code_login(get_token, audience, scopes)
    # token_ctx = try_refresh_or_login(refresh_token_ctx, login_ctx)
    # token_ctx = remember(token_ctx)

    jwks_ctx = jwks(oidc_ctx)
    verified_claims_ctx = decode_access_token(jwks_ctx, token_ctx, AUDIENCE)

    profile_ctx = get_user_profile(oidc_ctx, token_ctx)
    http_user_ctx = user_from_profile(profile_ctx)
    saved_http_user_ctx = save_user_to_db(http_user_ctx)

    user_ctx = read_from_db_or_create_from_external_profile(
        verified_claims_ctx,
        saved_http_user_ctx,
    )

    with HttpSession() as http, Session(engine) as db:
        user = user_ctx(http, db).unwrap()
        if not user:
            raise Exception("user couldnt be resolved")
        print("\n")
        print(user)
        db.commit()


if __name__ == "__main__":
    main()

#####################################################################
#####################################################################
# END Application Module
#####################################################################
#####################################################################
