import base64
import contextlib
import functools
import hashlib
import sys
import zlib
import pickle
from cryptography.fernet import Fernet
import pathlib
import typing

NOT_SET = object()

PAK_OPTION = typing.Union[str, typing.Tuple[str, typing.Any]]


def sweep_dead_branches(pak):
    keys_to_delete = []

    for key, value in pak.items():
        if isinstance(value, dict):
            sweep_dead_branches(value)
            if not value:
                keys_to_delete.append(key)
        elif not value:
            keys_to_delete.append(key)

    for key in keys_to_delete:
        del pak[key]

    return pak


class PAK(dict):
    def _p_format(self, _dict, indent=0, line_separator= "\n", indent_width=0):
        if line_separator == "\n" and indent_width == 0:
            indent_width = 2
        output = ""
        for k, v in _dict.items():
            if isinstance(v, dict):
                output += f"{' ' * indent}{k}:{line_separator}"
                output += self._p_format(
                    v, indent + indent_width, line_separator, indent_width
                )
            else:
                output += f"{' ' * indent}{k}: {v}{line_separator}"
        return output

    def _format(self):
        indent_width = 1
        if _output := (
            "\n".join(
                [
                    f"{' ' * indent_width}{line}"
                    for line in self._p_format(
                        self, indent=indent_width, line_separator="\n"
                    ).split("\n")
                ]
            )
            .rstrip(" ")
            .rstrip("\n")
        ):
            _output = f"\n{_output}\n"
        return _output

    def update(self, *mappings):
        functools.reduce(
            lambda m: functools.reduce(lambda a, b: a[b], m, self), mappings
        )

    def setdefault(self, key, default=NOT_SET):
        if default is NOT_SET:
            return self[key]
        if "." not in key:
            return super().setdefault(key, default)
        branch, leaf = key.split(".")[:-1], key.split(".")[-1]
        return self[".".join(branch)].setdefault(leaf, default if not callable(default) else default())

    def __init__(self, mapping=(), /, **kwargs):
        super().__init__()
        kwargs.update(mapping)
        for k, v in kwargs.items():
            self[k] = v

    def __repr__(self):
        return f"PAK{{{self._format()}}}"

    def __str__(self):
        return self._p_format(self)

    def __missing__(self, key):
        return self.setdefault(key, PAK())

    def __setstate__(self, state):
        self.update(state)

    def __getstate__(self):
        return dict(sweep_dead_branches(self))

    def __hash__(self):
        return hashlib.sha256(
            self._p_format(dict(sweep_dead_branches(self)), line_separator= "").encode()
        ).hexdigest()

    def __getitem__(self, key):
        if isinstance(key, str) and "." in key:
            branches = key.split(".")
            return functools.reduce(lambda a, b: a[b], branches, self)
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if isinstance(key, str) and "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            functools.reduce(lambda a, b: a[b], branches, self)[leaf] = value
        else:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        if isinstance(key, str) and "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            del functools.reduce(lambda a, b: a[b], branches, self)[leaf]
            sweep_dead_branches(self)
        else:
            super().__delitem__(key)

    def __contains__(self, key):
        if isinstance(key, str) and "." in key:
            branches, leaf = key.split(".")[:-1], key.split(".")[-1]
            return leaf in functools.reduce(lambda a, b: a[b], branches, self)
        return super().__contains__(key)
    
    @property
    def flat(self):
        def _flat(pak, prefix=""):
            for key, value in pak.items():
                if isinstance(value, PAK):
                    yield from _flat(value, prefix=f"{prefix}{key}.")
                else:
                    yield f"{prefix}{key}", value
        return dict(_flat(self))
        
class PakFile(PAK):
    DEFAULT_PASSWORD = "PAK"
    DEFAULT_COMPRESS = True
    VERSION = (0, 0, 1)

    def save(self, filename, compress=DEFAULT_COMPRESS, password=DEFAULT_PASSWORD):
        path = pathlib.Path(filename)
        if not path.suffix:
            path = path.with_suffix(".pak")
        path.parent.mkdir(parents=True, exist_ok=True)
        data = pickle.dumps(self)
        if password:
            data = Fernet(
                base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            ).encrypt(data)
        if compress:
            data = zlib.compress(data)
        path.write_bytes(data)

    @classmethod
    def load(cls, filename, compress=DEFAULT_PASSWORD, password=DEFAULT_PASSWORD):
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
            data = Fernet(
                base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            ).decrypt(data)
        return pickle.loads(data)

    @classmethod
    def delete(cls, filename):
        path = pathlib.Path(filename)
        if not path.exists():
            raise FileNotFoundError(f"File {filename} not found")
        path.unlink()

    @classmethod
    @contextlib.contextmanager
    def open(cls, filename, compress=DEFAULT_COMPRESS, password=DEFAULT_PASSWORD):
        try:
            pak = cls.load(filename, compress=compress, password=password)
        except FileNotFoundError:
            pak = cls()
        yield pak
        pak.save(filename, compress=compress, password=password)
        
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
            self._p_format(state, line_separator= "").encode()
        ).hexdigest()
        version_to_compare = self.VERSION
        if hash != hash_to_compare:
            raise ValueError(f"Hash mismatch: {hash} != {hash_to_compare}")
        if not all(a >= b for a, b in zip(version, version_to_compare)):
            raise ValueError(f"Version mismatch: {version} > {version_to_compare}")
        if size != sys.getsizeof(state):
            raise ValueError(f"Size mismatch: {size} != {sys.getsizeof(state)}")
        super().__setstate__(state)

open = PakFile.open

