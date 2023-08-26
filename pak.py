import base64
import contextlib
import functools
import hashlib
import sys
import zlib
import pickle
from enum import Enum

from cryptography.fernet import Fernet
import pathlib
import typing

NOT_SET = object()

PAK_OPTION = typing.Union[str, typing.Tuple[str, typing.Any]]

class PAK(dict):
    VERSION = (0, 0, 1)
    
    def _nested_p_format(self, _dict, indent = 0, line_separator = "\n", indent_width = 0):
        if line_separator == "\n" and indent_width == 0:
            indent_width = 2
        output = ""
        for k, v in _dict.items():
            if isinstance(v, dict):
                output += f"{' ' * indent}{k}:{line_separator}"
                output += self._nested_p_format(v, indent + indent_width, line_separator, indent_width)
            else:
                output += f"{' ' * indent}{k}: {v}{line_separator}"
        return output
    
    def _format(self):
        indent_width = 1
        if _output := (
                "\n".join([
                        f"{' ' * indent_width}{line}"
                        for line
                        in self._nested_p_format(
                                self,
                                indent = indent_width,
                                line_separator = "\n"
                        )
                                .split("\n")
                ])
                        .rstrip(" ")
                        .rstrip("\n")
        ):
            _output = f"\n{_output}\n"
        return _output
    
    def update(self, *mappings):
        functools.reduce(lambda m: functools.reduce(lambda a, b: a[b], m, self), mappings)
        
    def setdefault(self, key, default = NOT_SET):
        if default is NOT_SET:
            return self[key]
        if "." not in key:
            return super().setdefault(key, default)
        branch, leaf = key.split(".")[:-1], key.split(".")[-1]
        return self[".".join(branch)].setdefault(leaf, default)

    def __init__(self, mapping=(), /, **kwargs):
        super().__init__()
        kwargs.update(mapping)
        for k, v in kwargs.items():
            self[k] = v

    def __repr__(self):
        return f"PAK{{{self._format()}}}"
    
    def __str__(self):
        return self._nested_p_format(self)

    def __missing__(self, key):
        return self.setdefault(key, PAK())

    def __setstate__(self, state):
        self.update(state)

    def __getstate__(self):
        return dict(self)

    def __hash__(self):
        return hashlib.sha256(self._nested_p_format(dict(self), line_separator = "").encode()).hexdigest()

    def __getitem__(self, key):
        if isinstance(key, str) and "." in key:
            branches = key.split(".")
            return functools.reduce(lambda a, b: a[b], branches, self)
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if isinstance (key, str) and "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            functools.reduce(lambda a, b: a[b], branches, self)[leaf] = value
        else:
            super().__setitem__(key, value)
            
    def __delitem__(self, key):
        if isinstance(key, str) and "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            del functools.reduce(lambda a, b: a[b], branches, self)[leaf]
        else:
            super().__delitem__(key)
            
    def __contains__(self, key):
        if isinstance(key, str) and "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            return leaf in functools.reduce(lambda a, b: a[b], branches, self)
        return super().__contains__(key)
    
class PakFile(PAK):
    
    DEFAULT_PASSWORD = str(PAK.VERSION)
    DEFAULT_COMPRESS = True
    
    @functools.lru_cache(maxsize = None)
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls, *args, **kwargs)
    
    def __getstate__(self):
        state = super().__getstate__()
        state["__PAK_META_HASH__"] = self.__hash__()
        state["__PAK_META_VERSION__"] = self.VERSION
        state["__PAK_META_SIZE__"] = sys.getsizeof(state)
        return state

    def __setstate__(self, state):
        hash = state.pop("__PAK_META_HASH__")
        version = state.pop("__PAK_META_VERSION__")
        size = state.pop("__PAK_META_SIZE__")
        hash_to_compare = hashlib.sha256(
            self._nested_p_format(state, line_separator = "").encode()).hexdigest()
        version_to_compare = self.VERSION
        if hash != hash_to_compare:
            raise ValueError(f"Hash mismatch: {hash} != {hash_to_compare}")
        if not all(a >= b for a, b in zip(version, version_to_compare)):
            raise ValueError(f"Version mismatch: {version} > {version_to_compare}")
        if size != sys.getsizeof(state):
            raise ValueError(f"Size mismatch: {size} != {sys.getsizeof(state)}")
        super().__setstate__(state)

    def save(self, filename, compress = DEFAULT_COMPRESS, password = DEFAULT_PASSWORD):
        path = pathlib.Path(filename)
        if not path.suffix:
            path = path.with_suffix(".pak")
        path.parent.mkdir(parents = True, exist_ok = True)
        data = pickle.dumps(self)
        if password:
            data = Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())).encrypt(data)
        if compress:
            data = zlib.compress(data)
        path.write_bytes(data)

    @classmethod
    def load(cls, filename, compress = DEFAULT_PASSWORD, password = DEFAULT_PASSWORD):
        path = pathlib.Path(filename)
        if not path.suffix:
            path = path.with_suffix(".pak")
        if not path.exists():
            raise FileNotFoundError(f"File {filename} not found")
        data = path.read_bytes()
        if compress and data[:2] == b"\x78\x9c":
            data = zlib.decompress(data)
        if not password and data[:2] == b"\x80\x04":
            raise ValueError(f"Password required to decrypt file {filename}")
        if password:
            data = Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())).decrypt(data)
        return pickle.loads(data)
    
    @classmethod
    def delete(cls, filename):
        path = pathlib.Path(filename)
        if not path.exists():
            raise FileNotFoundError(f"File {filename} not found")
        path.unlink()

    @classmethod
    @contextlib.contextmanager
    def open(cls, filename, compress = DEFAULT_COMPRESS, password = DEFAULT_PASSWORD):
        try:
            pak = cls.load(filename, compress = compress, password = password)
        except FileNotFoundError:
            pak = cls()
        yield pak
        pak.save(filename, compress = compress, password = password)
    
    # a flatten function for PAK
    # converts into a dict of dot separated keys and values
    def flatten(self):
        def _flatten(_dict, parent_key = "", sep = "."):
            items = []
            for k, v in _dict.items():
                new_key = parent_key + sep + k if parent_key else k
                if isinstance(v, dict):
                    items.extend(_flatten(v, new_key, sep = sep).items())
                else:
                    items.append((new_key, v))
            return dict(items)
        return _flatten(self)
    
    @classmethod
    def unflatten(cls, _dict):
        pak = cls()
        for k, v in _dict.items():
            branches = k.split(".")
            functools.reduce(lambda a, b: a[b], branches[:-1], pak)[branches[-1]] = v
        return pak


