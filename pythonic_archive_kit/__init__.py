"""The Pythonic Archive Kit"""
from .utils import __VERSION_STR__

from . import mini_pak

try:
    from . import pak
    
except ImportError:
    pak = mini_pak
    print(
        "WARNING: cryptography is not installed. PAK files will not be encrypted.", 
        "To install cryptography, run `pip install cryptography`", 
        sep="\n"
    )
    
__version__ = __VERSION_STR__

open_pak = pak.open_pak
load_pak = pak.load_pak
save_pak = pak.save_pak