import base64
from types import SimpleNamespace
import hashlib
import pickle
import gzip
from typing import MutableMapping

from cryptography.fernet import Fernet
import contextlib
import pathlib


class PAK(SimpleNamespace):
    def __getattr__(self, item):
        return self.__dict__.setdefault(item, PAK())

    def __reduce_ex__(self, protocol):
        def sweep(self):
            for k, v in self.__dict__.copy().items():
                if isinstance(v, PAK):
                    sweep(v)
                    if not v:
                        del self.__dict__[k]

        sweep(self)
        return (PAK, (), contain_state(self.__dict__.copy()))

    def __setstate__(self, state):
        self.__dict__.update(release_state(state))

    def __bytes__(self):
        return pickle.dumps(self)
    
    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], bytes):
            return pickle.loads(args[0])
        else:
            return super().__new__(cls)

    def __init__(self, *_, **kwargs):
        super().__init__(**kwargs)

    def __contains__(self, key):
        return key in self.__dict__

    def __bool__(self):
        return bool(self.__dict__)
    
    def __neg__(self):
        self.__dict__.clear()

def contain_state(state):
    state["__hash__"] = hashlib.sha256(str(state).encode()).hexdigest()
    return state


def release_state(state):
    hash = state.pop("__hash__")
    if hash != hashlib.sha256(str(state).encode()).hexdigest():
        raise ValueError("Invalid hash")
    return state


def encode_password(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def fernet(password):
    return Fernet(encode_password(password))


@contextlib.contextmanager
def open_pak(path, password=None, create=False):
    yield (data := load(path, password, create))
    save(data, path, password)


def save(data, path, password=None):
    with open(path, "wb") as f:
        f.write(fernet(password).encrypt(bytes(data)))


def load(path, password=None, create=False):
    try:
        with open(path, "rb") as f:
            return PAK(fernet(password).decrypt(f.read()))
    except FileNotFoundError:
        if create:
            return PAK()
        else:
            raise


