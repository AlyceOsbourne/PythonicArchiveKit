"""Pythonic Archive Kit (PAK) is a simple, lightweight, and easy to use save data management library."""

import functools
import hashlib
import pickle
import zlib
from datetime import datetime
from pathlib import Path
from pprint import pformat
from collections import defaultdict
from enum import Enum, EnumMeta
from typing import Callable, Generic, TypeVar, TypeGuard

DEFAULT_VERSION = (0, 0, 0)
DEFAULT_IS_UPGRADABLE = False

PAK_VERSION = (0, 1, 0)
BREAKING = False


def dict_hash(d):
    """Generate a hash value for a dictionary."""
    return hashlib.sha256(str(d).encode()).hexdigest()


def is_version_compatible(version1, version2):
    """
    Check if version1 is compatible with version2.
    Returns True if version1 is less than or equal to version2 in all components.
    """
    return all(a <= b for a, b in zip(version1, version2))


class SaveBlock(defaultdict):
    """An internal block for the save data.
    Getting keys that don't exist will return a new SaveBlock.
    """

    def __init__(self, **data):
        super().__init__(SaveBlock, **data)

    def __repr__(self):
        return f"{dict(self)!r}"

    def to_dict(self):
        """Convert the SaveBlock to a regular dictionary."""

        def to_d(d):
            return {k: to_d(v) if isinstance(v, dict) else v for k, v in d.items()}

        return to_d(self)

    def __str__(self):
        return pformat(self.to_dict(), indent = 4)

    def __reduce_ex__(self, *args):
        return (SaveBlock, (), self.__getstate__())

    def __setstate__(self, state):
        self.update(state)

    def __getstate__(self):
        return dict(self)

    def __setitem__(self, key, value):
        super().__setitem__(key, self._convert_value(value))

    def _convert_value(self, value):
        if isinstance(value, dict):
            return SaveBlock(**{k: self._convert_value(v) for k, v in value.items()})
        else:
            return value


class SaveData(SaveBlock):
    """Represents save data with added functionality for loading, saving, and managing versions."""

    @functools.cache
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls, *args, **kwargs)

    def __init__(self, filename, is_upgradable = DEFAULT_IS_UPGRADABLE, version = DEFAULT_VERSION):
        super().__init__()
        self.filename = filename
        self.is_upgradable = is_upgradable
        self.version = version

    def load(self):
        """Load save data from a file and perform version compatibility checks."""
        self._io(l = True)
        self.setdefault("created", datetime.now().isoformat())
        self.setdefault("version", self.version)
        self.setdefault("pak_version", PAK_VERSION)

        if not is_version_compatible(self["pak_version"], PAK_VERSION) and BREAKING:
            raise ValueError("Save pak_version is not compatible with current pak_version")

        if not is_version_compatible(self["version"], self.version):
            if self.is_upgradable:
                self["version"] = self.version
            else:
                raise ValueError("Save version is not compatible with current version")

        hash_value = self.pop("hash", None)
        if hash_value is None or hash_value == dict_hash(self):
            return self
        else:
            raise ValueError("Save hash is invalid")

    def save(self, *_):
        """Save the current state of the save data to a file."""
        self.update({"updated": datetime.now().isoformat()})
        self["hash"] = dict_hash(self)
        save = self._io(l = False)
        return self

    def delete(self):
        """Delete the save data file and related files."""
        for file in (path := Path(self.filename)).parent.glob(f"{path.name}*"):
            file.unlink()
        return self

    __enter__ = load
    __exit__ = save

    def _io(self, l = True):
        """Perform input/output operations for loading and saving data to a file."""
        if not self.filename.endswith(".pak"):
            self.filename += ".pak"
        Path(self.filename).parent.mkdir(parents = True, exist_ok = True)
        with open(self.filename, "wb" if l else "rb") as file:
            if l:
                pickle.dump(zlib.compress(pickle.dumps(self)), file)
            else:
                return pickle.loads(zlib.decompress(pickle.load(file)))

    def __hash__(self):
        return hash(self.filename)


class SaveDataSlots(Enum):
    """An enumeration of save data slots with associated filenames and version compatibility."""
    __getattr__: Callable
    _ignore_ = ("__getattr__", "_ignore_")

    def __new__(cls, filename, is_upgradable = DEFAULT_IS_UPGRADABLE, version=DEFAULT_VERSION) -> SaveData:
        return SaveData(filename, is_upgradable, version)


if __name__ == "__main__":
    # usage example
    class Slots(SaveDataSlots):
        """This defines the slots for the save data. The values themselves will be the filenames.
        The values get transformed into SaveData objects when accessed.
        """
        DEV = "s/dev"
        SLOT_1 = "s/slot1"
        SLOT_2 = "s/slot2"
        SLOT_3 = "s/slot3"


    with Slots["DEV"] as opened:
        player_meta = opened["player_meta"]
        player_meta.setdefault("name", "Player")
        player_meta.setdefault("level", 1)
        player_meta.setdefault("exp", 0)
        
        player_inventory = player_meta["inventory"]
        player_inventory.setdefault("gold", 0)
        player_inventory.setdefault("items", [])
        
        flags = opened["flags"]
        flags.setdefault("tutorial", False)
        flags.setdefault("intro", False)
        flags.setdefault("ending", False)
        flags.setdefault("credits", False)
        flags.setdefault("game_over", False)
        flags.setdefault("game_complete", False)
        flags.setdefault("game_complete_100", False)
        
        world = opened["world"]
        world.setdefault("current_area", "home")
        
        
        
