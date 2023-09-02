import logging
import pathlib
import pickle
import types
import contextlib
from typing import MutableMapping
import lzma
from .utils import __VERSION__ as PAK_VERSION
import hashlib
import sys
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


def _hash_state(state):
    """Generate a hash of the state of a PAK object."""
    logger.debug("Calculating hash of state")
    return hashlib.sha256(str(state).encode()).hexdigest()

def _sweep(pak):
    """Remove empty PAK objects from a PAK object."""
    logger.debug("Sweeping PAK object")
    for k, v in pak.__dict__.copy().items():
        if isinstance(v, PAK):
            _sweep(v)
            if not v:
                del pak.__dict__[k]
    return pak

class PAK(types.SimpleNamespace, MutableMapping):
    """
    This is the core of the PAK system. 
    It is a recursive namespace that can be pickled and encrypted.
    Because it is both a mutable mapping, and a namespace, it can be used like a dictionary, or like an object.
    These are both valid approaches and will modify the same underlying data structure.
    During pickling, the paks state is hashed and a pak version is stored in the state.
    If these don't match on unpickling, an error is raised.
    The idea is that this will help prevent unpickling of malicious or corrupted data, though it is not a guarantee.
    
    Example usage:
    >>> pak = PAK()
    >>> pak.foo = "bar"
    >>> pak["baz"] = "qux"
    >>> pak
    <PAK {'foo': 'bar', 'baz': 'qux'}>  
    >>> pak.foo
    'bar'
    >>> pak["baz"]
    'qux'
    >>> pak["quux"]
    PAK()
    >>> pak.quux.corge = "grault"
    >>> pak
    <PAK {'foo': 'bar', 'baz': 'qux', 'quux': <PAK {'corge': 'grault'}}
    >>> pak["quux"].corge
    'grault'
    
    As you can see, PAK objects can be nested arbitrarily deep.
    Any name in the namespace that is not defined will be a new PAK object if accessed.
    The system applies a culling algorithm to remove empty PAK objects.
    """

    def __getattr__(self, item):
        """If the attribute does not exist, create a new PAK object."""
        logger.debug(f"Getting attribute {item} from PAK object")
        return self.__dict__.setdefault(item, PAK())
                
    def __reduce_ex__(self, protocol):
        """Reduce the PAK object to a picklable state.
            Injects the version and hash of the state into the state itself.
        """
        logger.debug("Reducing PAK object to a picklable state")
        state = _sweep(self).__dict__.copy()
        state.update(__hash__=_hash_state(state), __version__=PAK_VERSION)
        return (PAK, (), state)

    def __setstate__(self, state):
        """Restore the PAK object from a pickled state.
            Checks the version and hash of the state before restoring.
        """
        logger.debug("Restoring PAK object from a pickled state")
        if not all(a >= b for a, b in zip(state.pop("__version__"), PAK_VERSION)):
            raise ValueError("Invalid version")
        if state.pop("__hash__") != _hash_state(state):
            raise ValueError("Invalid hash")
        self.__dict__.update(state)

    def __bytes__(self):
        """Convert the PAK object to bytes."""
        logger.debug("Converting PAK object to bytes")
        return pickle.dumps(self)

    def __new__(cls, *args, **kwargs):
        """Create a new PAK object from bytes or kwargs."""
        logger.debug("Creating a new PAK object")
        if args and isinstance(args[0], bytes):
            return pickle.loads(args[0])
        else:
            return super().__new__(cls)

    def __init__(self, *_, **kwargs):
        super().__init__(**kwargs)

    def __contains__(self, key):
        logger.debug(f"Checking if key {key} is in PAK object")
        return key in self.__dict__

    def __bool__(self):
        logger.debug("Checking if PAK object is empty")
        return bool(self.__dict__)

    def __eq__(self, other):
        if isinstance(other, PAK):
            return self.__dict__ == other.__dict__
        elif isinstance(other, dict):
            return self.__dict__ == other
        else:
            return False

    def __iter__(self):
        logger.debug("Iterating over PAK object")
        return iter(self.__dict__)

    def __len__(self):
        logger.debug("Getting the length of PAK object")
        return len(self.__dict__)

    def __repr__(self):
        return f"<PAK {self.__dict__}>"

    def setdefault(self, key, default):
        logger.debug(f"Setting default value for key {key} in PAK object")
        return self.__dict__.setdefault(key, default)

    def cull(self):
        logger.debug("Culling empty PAK objects")
        return _sweep(self)

    __getitem__ = __getattr__
    __setitem__ = types.SimpleNamespace.__setattr__
    __delitem__ = types.SimpleNamespace.__delattr__
    
def save_pak(pak, path):
    logger.debug(f"Saving PAK object to {path}")
    with lzma.open(path, "wb") as f:
        f.write(bytes(pak))

def load_pak(path, /, create=True, _pak_type=PAK):
    path  = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    logger.debug(f"Loading PAK object from {path}")
    try:
        with lzma.open(path, "rb") as f:
            return _pak_type(f.read())
    except FileNotFoundError:
        if create:
            logger.info("PAK file not found, creating a new one")
            return _pak_type()
        else:
            raise

@contextlib.contextmanager
def open_pak(path, /, create=True, _pak_type=PAK):
    path  = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    logger.debug(f"Opening PAK file {path}")
    yield (pak := load_pak(path, create, _pak_type))
    save_pak(pak, path)
    logger.debug(f"Saved PAK file {path}")
