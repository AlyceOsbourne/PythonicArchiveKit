"""PAK is a simple, recursive namespace that can be pickled and encrypted."""

import base64
import pathlib
from types import SimpleNamespace
import hashlib
import pickle
import contextlib
import gzip
from .utils import __VERSION__ as PAK_VERSION, _hash_state, _sweep
import cryptography
from cryptography.fernet import Fernet

class PAK(SimpleNamespace):
    """This is the core of the PAK system. It is a recursive namespace that can be pickled and encrypted."""
    def __getattr__(self, item):
        """If the attribute does not exist, create a new PAK object."""
        return self.__dict__.setdefault(item, PAK())

    def __reduce_ex__(self, protocol):
        """Reduce the PAK object to a picklable state.
            Injects the version and hash of the state into the state itself.
        """
        state = _sweep(self).__dict__.copy()
        state.update(__hash__=_hash_state(state), __version__=PAK_VERSION)
        return (PAK, (), state)

    def __setstate__(self, state):
        """Restore the PAK object from a pickled state.
            Checks the version and hash of the state before restoring.
        """
        if not all(a >= b for a, b in zip(state.pop("__version__"), PAK_VERSION)):
            raise ValueError("Invalid version")
        if state.pop("__hash__") != _hash_state(state):
            raise ValueError("Invalid hash")
        self.__dict__.update(state)

    def __bytes__(self):
        """Convert the PAK object to bytes."""
        return pickle.dumps(self)

    def __new__(cls, *args, **kwargs):
        """Create a new PAK object from bytes or kwargs."""
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
    
    __getitem__ = __getattr__
    __setitem__ = SimpleNamespace.__setattr__
    __delitem__ = SimpleNamespace.__delattr__

def _fernet(password):
    """Generate a Fernet object from a password."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()))


def save_pak(data, path, password=None):
    """Save a PAK file to disk."""
    path = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as f:
        if password is None:
            return f.write(bytes(data))
        f.write(_fernet(password).encrypt(bytes(data)))


def load_pak(path, password=None, create=True):
    """Load a PAK file from disk. If create is True, a new PAK file will be created if one does not exist."""
    path = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    try:
        with gzip.open(path, "rb") as f:
            if password is None:
                pak = PAK(f.read())
            else:
                pak =  PAK(_fernet(password).decrypt(f.read()))
    except FileNotFoundError:
        if create:
            pak = PAK()
        else:
            raise
    except cryptography.fernet.InvalidToken:
        raise ValueError("Invalid password")
    return pak
    

@contextlib.contextmanager
def open_pak(path, password=None, create=True):
    """Open a PAK file from disk. If create is True, a new PAK file will be created if one does not exist. Saves the PAK file on exit."""
    yield (data := load_pak(path, password, create))
    save_pak(data, path, password)



if __name__ == "__main__":
    with open_pak("test.pak") as pak:
        pak.a.b.c = 1
        
    with open_pak("test.pak") as pak:
        print(pak.a.b.c)
        
    with open_pak("encrypted.pak", password="test") as pak:
        pak.a.b.c = 2
        
    with open_pak("encrypted.pak", password="test") as pak:
        print(pak.a.b.c)
        
    print(dir(PAK()))