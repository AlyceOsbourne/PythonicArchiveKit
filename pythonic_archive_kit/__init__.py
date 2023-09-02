"""The Pythonic Archive Kit"""
from .utils import __VERSION_STR__

__version__ = __VERSION_STR__

try:
    from . import pak
except ImportError:
    from . import base as pak

    print(
            "WARNING: cryptography is not installed. PAK files will not be encrypted.",
            "To install cryptography, run `pip install cryptography`",
            sep = "\n"
    )


open_pak = pak.open_pak
load_pak = pak.load_pak
save_pak = pak.save_pak
