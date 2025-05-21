import enum
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import Any, Concatenate, Iterator, TextIO, cast

from requests import Session as HttpSession
from sqlalchemy.orm import DeclarativeBase, Session


class StateError(enum.Enum):
    NotSet = enum.auto()


@dataclass
class Result[T]:
    """
    Wrapper that holds the result of executing a contextual function. This is
    useful because it gives the caller the optionality of how to handle any
    errors. This also allows for a more explicit definition of return values
    in terms of 'Optionality'.
    """

    result: T | StateError = StateError.NotSet
    exc: Exception | None = None

    def unwrap(self) -> T:
        if self.exc:
            raise self.exc
        if self.result is StateError.NotSet:
            raise ValueError("Result not set")

        return self.result


"""
A function that takes a side-effect client as its argument, operations on it and
returns a Result object to be interpreted by the caller.
"""
type Context[T, U] = Callable[[T], Result[U]]


"""Wraps a Context so that its result is optional."""
type MaybeContext[T, U] = Context[T, U | None]


"""A function that is intended to write a resource to a side-effect client."""
type ContextWriter[T, U] = Callable[[U], Context[T, Any]]


def resolve[T, U](t: Context[T, U], ctx: T) -> U:
    """Helper function for executing a context and unwraping it."""
    return t(ctx).unwrap()


def remember[T, U](fn: Context[T, U]) -> Context[T, U]:
    result: Result[U] | None = None

    @wraps(fn)
    def wrapper(client: T) -> Result[U]:
        nonlocal result
        if result is None:
            result = fn(client)
        return result

    return wrapper


def side_effect[**P, T, U](
    fn: Callable[Concatenate[T, P], U],
) -> Callable[P, Context[T, U]]:
    """
    A decorator that handles the boilerplate of lazily calling generic clients.
    """

    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Context[T, U]:
        def exec(client: T) -> Result[U]:
            try:
                return Result(fn(client, *args, **kwargs), None)
            except Exception as exc:
                return Result(exc=exc)

        return exec

    return wrapper


def class_side_effect[**P, T, U](
    fn: Callable[Concatenate[Any, T, P], U],
) -> Callable[Concatenate[Any, P], Context[T, U]]:
    """
    Decorator that handles the boilerplate for lazily calling generic clients.
    """

    @wraps(fn)
    def wrapper(self, *args: P.args, **kwargs: P.kwargs) -> Context[T, U]:
        def exec(client: T) -> Result[U]:
            try:
                return Result(fn(self, client, *args, **kwargs), None)
            except Exception as exc:
                return Result(exc=exc)

        return exec

    return wrapper


@side_effect
def safe_context[T, U](
    client: T,
    source: Context[T, U],
    message: str,
) -> U | None:
    """Resolve context and supress expections as warnings"""
    result = source(client)
    if result.exc:
        print("WARNING ::", message, str(result.exc))
        return None
    return result.unwrap()


#####################################################################
#####################################################################
# START Composition Module
#####################################################################
#####################################################################

"""
A function that is intended to retrieve data from a source context  and write it
to a cache context.
"""
type CacheWriteContext[T, U, V] = Callable[[T], MaybeContext[U, V]]

"""
A function that attempts to read data from a cache context. If the data does not
exist in the cache context, an attempt to read the data from a source context is
performed.
"""
type CacheReadContext[T, U, V] = Callable[[T, U], Result[V | None]]


def cache_read[T, U, V](
    source_ctx: CacheWriteContext[T, U, V],
    cache_ctx: MaybeContext[U, V],
) -> CacheReadContext[T, U, V]:
    """
    Read data from the cache. If not found read it from the source.

    Creates a CacheReadContext from a CacheWriteContext (treated as the source
    context) and a MaybeContext (treated as the cache context). The cache
    side-effect client must be the same type betwen the CacheContext and the
    MaybeContext. This allows the CacheReadContext to first attempt to read from
    the cache and on a miss reteive from the source and ALSO write to the cache.
    """

    def compose(source_client: T, cache_client: U) -> Result[V | None]:
        result = cache_ctx(cache_client)
        data = result.unwrap()
        if data is not None:
            return result
        return source_ctx(source_client)(cache_client)

    return compose


def cache_write[T, U, V](
    source_ctx: MaybeContext[T, V],
    writer_ctx: ContextWriter[U, V],
) -> CacheWriteContext[T, U, V]:
    """
    Read record from the source context and if not `None` write it to the
    writer (cache) context.

    Creates a CacheWriteContext from a MaybeContext (treated as the source
    context) and a ContextWriter (treated as the sink to write the retreived
    source data to).

    """

    def top(source_client: T) -> MaybeContext[U, V]:
        def inner(write_client: U) -> Result[V | None]:
            result = source_ctx(source_client)
            resource = result.unwrap()
            if resource is None:
                return result
            writer_ctx(resource)(write_client).unwrap()
            return result

        return inner

    return top


def binop_swap[T, U, V](fn: Callable[[T, U], V], b: U) -> Callable[[T], V]:
    @wraps(fn)
    def wrapper(a: T) -> V:
        return fn(a, b)

    return wrapper


#####################################################################
#####################################################################
# End Composition Module
#####################################################################
#####################################################################


#####################################################################
#####################################################################
# START HTTP Module
#####################################################################
#####################################################################

type HttpContext[T] = Callable[[HttpSession], Result[T]]


#####################################################################
#####################################################################
# END HTTP Module
#####################################################################
#####################################################################


#####################################################################
#####################################################################
# START FILE Module
#####################################################################
#####################################################################

type TextContext[T] = Callable[[TextIO], Result[T]]


@contextmanager
def lazy_text_io(
    filename: str, mode: str = "a+", encoding: str = "utf8"
) -> Iterator[TextIO | None]:
    try:
        with open(filename, mode=mode, encoding=encoding) as file:
            file.seek(0)
            yield cast(TextIO, file)
    except Exception as exc:
        print("WARNING :: Problem opening file", str(exc))
        yield None


#####################################################################
#####################################################################
# END FILE Module
#####################################################################
#####################################################################

#####################################################################
#####################################################################
# START DB Module
#####################################################################
#####################################################################

type DbContext[T] = Callable[[Session], Result[T]]


class Base(DeclarativeBase):
    """Base class for ORM Models"""


#####################################################################
#####################################################################
# END DB Module
#####################################################################
#####################################################################
