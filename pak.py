import datetime
import pickle
import hashlib
from contextlib import contextmanager

from cryptography.fernet import Fernet
from collections import defaultdict
from pathlib import Path
import zlib

def calculate_hash(self):
    return hashlib.sha256(pickle.dumps(self)).hexdigest()

def is_version_compatible(self):
    return all(a <= b for a, b in zip(self.version, self.pak_version))

@contextmanager
def open(filename=None, compress=False, password=None):
    obj = PAK.load(filename, compress, password)
    yield obj
    obj.save(filename, compress, password)

class PAK(defaultdict):
    def __init__(self, file_version=(0, 0, 1), pak_version=(0, 0, 1)):
        super().__init__(PAK)
        self.version = file_version
        self.pak_version = pak_version
        self.setdefault("created", datetime.datetime.now())
        self.setdefault("modified", datetime.datetime.now())
        
    def __reduce_ex__(self, protocol):
        return (PAK, (), None, None, iter(self.items()))

    def __setstate__(self, state):
        self.update(state)
        
    def save(self, filename=None, compress=False, password=None):
        if not filename:
            raise ValueError("No filename specified")
        self["hash"] = calculate_hash(self)
        self["modified"] = datetime.datetime.now()
        data = pickle.dumps(self)
        if password:
            data = Fernet(password).encrypt(data)
        if compress:
            data = zlib.compress(data)
        with open(filename, "wb") as f:
            f.write(data)
        
    @classmethod
    def load(cls, filename=None, compress=False, password=None):
        if not filename:
            raise ValueError("No filename specified")
        if not Path(filename).exists():
            raise FileNotFoundError("File not found")
        with open(filename, "rb") as f:
            data = f.read()
        if compress:
            data = zlib.decompress(data)
        if password:
            data = Fernet(password).decrypt(data)
        obj =  pickle.loads(data)
        hash = obj.pop("hash")
        if hash != calculate_hash(obj):
            raise ValueError("Hash mismatch")
        if not is_version_compatible(obj):
            raise ValueError("Version mismatch")
        return obj

def serialize_directory(directory, compress=False, password=None):
    pak = PAK()
    for file in directory.iterdir():
        if file.is_dir():
            pak[file.name] = serialize_directory(file, compress, password)
        else:
            pak[file.name] = file.read_bytes()
    return pak

def deserialize_directory(pak, directory, compress=False, password=None):
    for key, value in pak.items():
        if isinstance(value, PAK):
            deserialize_directory(value, directory / key, compress, password)
        else:
            (directory / key).write_bytes(value)