from functools import wraps
from typing import Any, Callable, TextIO

import requests
import sqlalchemy.orm

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
