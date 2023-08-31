"""PAK is a simple, recursive namespace that can be pickled and encrypted."""

import base64
import pathlib
import hashlib
import contextlib
import gzip

from pythonic_archive_kit.base import PAK
import cryptography
from cryptography.fernet import Fernet


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
