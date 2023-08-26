import base64
import datetime
import pickle
import hashlib
from contextlib import contextmanager
from pprint import pformat

from cryptography.fernet import Fernet
from collections import defaultdict, UserDict
from pathlib import Path
import zlib
import functools
DEFAULT_FILE_VERSION = (0, 0, 1)
PAK_VERSION = (0, 0, 1)



class PAK(dict):
    __slots__ = ("version", "pak_version")
    
    def __missing__(self, key):
        return self.setdefault(key, PAK())
    
    def __init__(self):
        super().__init__()
        
    def __getstate__(self):
        return dict(self)
    
    def __setstate__(self, state):
        self.update(state)
    
    def __repr__(self):
        return pformat(dict(self))
    
    def __str__(self):
        return pformat({k: v for k, v in self.items() if not k.startswith("__PAK_META__")})
    
    def save(self, filename, compress=True, password=None, file_version=DEFAULT_FILE_VERSION):
        self["__PAK_META__"].setdefault("created", datetime.datetime.now())
        self["__PAK_META__"].setdefault("pak_version", PAK_VERSION)
        self["__PAK_META__"].setdefault("version", file_version)
        self["__PAK_META__.modified"] = datetime.datetime.now()
        self["__PAK_META__.hash"] = self.calculate_hash()
        data = pickle.dumps(self)
        if password:
            password = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            data = Fernet(password).encrypt(data)
        if compress:
            data = zlib.compress(data)
        path = Path(filename)
        if not path.parent.exists():
            path.parent.mkdir(parents=True)
        path.write_bytes(data)
        
    @classmethod
    def load(cls, filename, compress=True, password=None, unsafe=False, file_version=DEFAULT_FILE_VERSION):
        path = Path(filename)
        if not path.exists():
            raise FileNotFoundError(filename)
        data = path.read_bytes()
        if data[:2] == b"\x78\x9c":
            compress = True
        if compress:
            data = zlib.decompress(data)
        if data[:2] == b"gA" and not password:
            raise ValueError("Password required")
        if password:
            password = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            data = Fernet(password).decrypt(data)
        obj =  pickle.loads(data)
        hash = obj["__PAK_META__"].pop("hash")
        if not hash and not unsafe:
            raise ValueError("Hash not found")
        if hash != obj.calculate_hash() and not unsafe:
            raise ValueError("Hash mismatch")
        if not obj.is_version_compatible(file_version = file_version) and not unsafe:
            raise ValueError("Version mismatch")
        return obj
    
    @classmethod
    @contextmanager
    def open(cls, filename, compress=True, password=None, file_version=DEFAULT_FILE_VERSION):
        try:
            obj = cls.load(filename, compress, password)
        except FileNotFoundError:
            obj = cls()
        yield obj
        obj.save(filename, compress, password, file_version)

    def calculate_hash(self):
        return hashlib.sha256(pformat(self).encode()).hexdigest()

    def is_version_compatible(self, file_version):
        for a, b in zip((self["__PAK_META__"]["pak_version"], self["__PAK_META__"]["version"]), (PAK_VERSION, file_version)):
            if not all(_a <= _b for _a, _b in zip(a, b)):
                return False
        return True
    
    def __getitem__(self, key):
        if "." in key:
            return functools.reduce(lambda a, b: a[b], key.split("."), self)
        return super().__getitem__(key)
    
    def __setitem__(self, key, value):
        if "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            _c = functools.reduce(lambda a, b: a[b], branches, self)[leaf] = value
        else:
            super().__setitem__(key, value)

def create_entry(pak, k, **default_entries):
    _c = pak[k]
    for k, v in default_entries.items():
        if isinstance(v, dict):
            _c.setdefault(k, create_entry(pak, k, **v))
        _c.setdefault(k, v)
    return _c


if __name__ == "__main__":
    with PAK.open("test.pak", password="test") as pak:    
        pak.clear()
    print(repr(pak))