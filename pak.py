import base64
from types import SimpleNamespace
import hashlib
import pickle
import gzip
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

def contain_state(state):
    state["__hash__"] = hashlib.sha256(str(state).encode()).hexdigest()
    return state

def release_state(state):
    hash = state.pop("__hash__")
    if hash != hashlib.sha256(str(state).encode()).hexdigest():
        raise ValueError("Invalid hash")
    return state

def load(path, password=None, create = False) -> PAK:
    path = pathlib.Path(path)
    if not path.exists():
        if create:
            return PAK()
        else:
            raise FileNotFoundError(path)
    if password is None:
        return PAK(gzip.decompress(path.read_bytes()))
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())).decrypt(gzip.decompress(path.read_bytes()))

def save(data: PAK, path, password=None):
    path = pathlib.Path(path)
    path.parent.mkdir(parents = True, exist_ok = True)
    if password is None:
        return path.write_bytes(gzip.compress(bytes(data)))
    path.write_bytes(Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())).encrypt(gzip.compress(bytes(data))))

@contextlib.contextmanager
def open(path, password=None, create = False):
    data = load(path, password, create)
    yield PAK(data)
    save(data, path, password)

