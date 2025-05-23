###############################################################
###############################################################
# START User
###############################################################
###############################################################


from collections.abc import Callable

from sqlalchemy import String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from contextual.v2.authentication import (
    ClaimsFn,
    JWKSFn,
    Profile,
    ProfileResolver,
    TokenFn,
    TokenResolver,
    VerifyAccessToken,
)
from contextual.v2.base import Db, remember


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

type UserResolver[T, U] = Callable[
    [
        TokenFn[T],
        ProfileResolver[T],
    ],
    UserCacheFn[T, U],
]


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
