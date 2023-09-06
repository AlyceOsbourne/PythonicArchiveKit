"""The Pythonic Archive Kit"""
from .utils import __VERSION_STR__ as __version__

try:
    from . import pak
    
except ImportError:
    from . import base as pak
    print(
            "WARNING: cryptography is not installed. PAK files will not be encrypted.",
            "To install cryptography, run `pip install cryptography`",
            sep = "\n"
    )

PAK = pak.PAK
from .typing import TypedPAK

open_pak = pak.open_pak
load_pak = pak.load_pak
save_pak = pak.save_pak

__all__ = [
        "PAK",
        "TypedPAK",
        "open_pak",
        "load_pak",
        "save_pak",
]
