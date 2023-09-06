import base64
import contextlib
import hashlib
import logging
import pathlib
import sys
import traceback
import types
from typing import MutableMapping

from .libraries import cryptography, Fernet, is_picklable, open, pickle
from .utils import __VERSION__ as PAK_VERSION

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


def _fernet(password):
    """Generate a Fernet object from a password."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()))


def _pak_except_hook(exc_type, value, tb):
    lines = traceback.format_tb(tb)
    if __file__ in lines[-1]:
        lines = lines[:-1]
    print(*lines, file = sys.stderr, end = "")
    print(f"{exc_type.__name__}: {value}", file = sys.stderr)


def pak_except_hook(func):
    def wrapper(exc_type, value, tb):
        if issubclass(exc_type, PAKAttributeError):
            _pak_except_hook(exc_type, value, tb)
        else:
            return func(exc_type, value, tb)
    return wrapper


class PAKError(Exception):
    """Base class for PAK errors."""
    pass


class PAKAttributeError(AttributeError):
    """Raised when an attribute is problematic."""

    def __init__(self, message, key, value):
        super().__init__(message)
        self.key = key
        self.value = value


class PAKAssignmentError(PAKAttributeError):
    """Raised when an attribute cannot be assigned."""
    pass


# noinspection PyArgumentList
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
        
    def __setattr__(self, key, value):
        """Set an attribute on the PAK object."""
        logger.debug(f"Setting attribute {key} on PAK object")
        if not is_picklable(value):
            raise PAKAssignmentError(f"Attribute {key} is not picklable with {type(value)}", key, value)
        self.__dict__[key] = value
            
    def __delattr__(self, item):
        """Delete an attribute from the PAK object."""
        logger.debug(f"Deleting attribute {item} from PAK object")
        del self.__dict__[item]
                
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
    
    def __str__(self):
        def _str(pak, indent=0):
            return "\n".join(
                    f"{' ' * indent}{k}: {v}" if not isinstance(v, PAK) else f"{' ' * indent}{k}:\n{_str(v, indent + 4)}"
                    for k, v in pak.__dict__.items()
            )
        return _str(self).strip()
    
    def __hash__(self):
        return hash(self.__dict__)
    

    def setdefault(self, key, default):
        logger.debug(f"Setting default value for key {key} in PAK object")
        return self.__dict__.setdefault(key, default)

    def cull(self):
        logger.debug("Culling empty PAK objects")
        return _sweep(self)

    __getitem__ = __getattr__
    __setitem__ = types.SimpleNamespace.__setattr__
    __delitem__ = types.SimpleNamespace.__delattr__


def save_pak(data, path, /, password = None):
    """Save a PAK file to disk."""
    path = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    path.parent.mkdir(parents = True, exist_ok = True)
    with open(
            path,
            "wb",
            preset = 9,
    ) as f:
        if password is None:
            return f.write(bytes(data))
        f.write(_fernet(password).encrypt(bytes(data)))


def load_pak(path, /, password = None, create = True, _pak_type = PAK):
    """Load a PAK file from disk. If create is True, a new PAK file will be created if one does not exist."""
    path = pathlib.Path(path)
    if not path.suffix:
        path = path.with_suffix(".pak")
    try:
        with open(
                path,
                "rb",
        ) as f:
            if password is None:
                pak = _pak_type(f.read())
            else:
                pak = _pak_type(_fernet(password).decrypt(f.read()))
    except FileNotFoundError:
        if create:
            pak = _pak_type()
        else:
            raise
    except cryptography.fernet.InvalidToken:
        raise ValueError("Invalid password")
    return pak


@contextlib.contextmanager
def open_pak(path, /, password = None, create = True, _pak_type = PAK):
    try:
        yield (data := load_pak(path, password, create, _pak_type))
    except Exception:
        raise
    else:
        save_pak(data, path, password)


sys.excepthook = pak_except_hook(sys.excepthook)
