import base64
import pathlib
from types import SimpleNamespace
import hashlib
import pickle
from cryptography.fernet import Fernet
import contextlib
import gzip

PAK_VERSION = 1, 0, 0

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
        return (PAK, (), add_meta(self.__dict__.copy()))

    def __setstate__(self, state):
        self.__dict__.update(check_meta(state))

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

def add_meta(state):
    state["__hash__"] = hashlib.sha256(str(state).encode()).hexdigest()
    state["__version__"] = PAK_VERSION
    return state

def check_version(version):
    if not all(a >= b for a, b in zip(version, PAK_VERSION)):
        raise ValueError("Invalid version")

def check_meta(state):
    check_version(state.pop("__version__"))
    check_hash(state.pop("__hash__"), str(state))
    return state


def check_hash(hash, state_str):
    if hash != hashlib.sha256(state_str.encode()).hexdigest():
        raise ValueError("Invalid hash")


def encode_password(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def fernet(password):
    return Fernet(encode_password(password))


def save(data, path, password=None):
    path = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as f:
        f.write(fernet(password).encrypt(bytes(data)))


def load(path, password=None, create=False):
    path = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    try:
        with gzip.open(path, "rb") as f:
            return PAK(fernet(password).decrypt(f.read()))
    except FileNotFoundError:
        if create:
            return PAK()
        else:
            raise


@contextlib.contextmanager
def open_pak(path, password=None, create=False):
    yield (data := load(path, password, create))
    save(data, path, password)
