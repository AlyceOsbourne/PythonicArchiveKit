"""The Pythonic Archive Kit"""
__version__ = "1.0.0"
from . import mini_pak
try:
    from . import pak
except ImportError:
    pak = None
if pak is None:
    del pak