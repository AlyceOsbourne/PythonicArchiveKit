import pickle
import types
import contextlib

from pythonic_archive_kit.pak import PAK_VERSION

from pythonic_archive_kit.utils import _hash_state, _sweep


# this is a requested feature from the original pak.py
# this is just a stripped down version of pak.py
# with no encryption, compression, or hashing

class MiniPak(types.SimpleNamespace):
    def __init__(self, *_, **kwargs):
        super().__init__(**kwargs)
        
    def __getattr__(self, item):
        """If the attribute does not exist, create a new PAK object."""
        return self.__dict__.setdefault(item, MiniPak())

    def __reduce_ex__(self, protocol):
        """Reduce the PAK object to a picklable state.
            Injects the version and hash of the state into the state itself.
        """
        state = _sweep(self).__dict__.copy()
        state.update(__hash__=_hash_state(state), __version__=PAK_VERSION)
        return (MiniPak, (), state)

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
        return pickle.dumps(self)

    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], bytes):
            return pickle.loads(args[0])
        else:
            return super().__new__(cls)
        
    def __contains__(self, key):
        return key in self.__dict__
    
    def __bool__(self):
        return bool(self.__dict__)
    
    __getitem__ = __getattr__
    __setitem__ = types.SimpleNamespace.__setattr__
    __delitem__ = types.SimpleNamespace.__delattr__

def save_pak(pak, path):
    with open(path, "wb") as f:
        f.write(bytes(pak))
        
def load_pak(path):
    try:
        with open(path, "rb") as f:
            return MiniPak(f.read())
    except FileNotFoundError:
        return MiniPak()
    
@contextlib.contextmanager
def open_pak(path):
    yield (pak:= load_pak(path))
    save_pak(pak, path)
        
        
if __name__ == "__main__":
    with open_pak("test.pak") as pak:
        pak.a.b.c = 1
    with open_pak("test.pak") as pak:
        print(pak.a.b.c)