
try:
    import lzma as zip

    open = zip.open
    compress = zip.compress
    decompress = zip.decompress
except ImportError:
    try:
        import gzip as zip

        open = zip.open
        compress = zip.compress
        decompress = zip.decompress
    except ImportError:
        open = __builtins__.open
        compress = lambda x: x
        decompress = lambda x: x
        
try:
    import dill as pickle
    is_picklable = pickle.pickles
except ImportError:
    import pickle
    def is_picklable(obj):
        # we want to attempt duck typing here, so we don't want to use the pickle module's check_picklable function
        deserialize_method_names = ["__setstate__", "__setstate_ex__"]
        if any(
                hasattr(obj, method_name)
                for method_name
                in ["__getstate__", "__reduce__", "__reduce_ex__"]) or any(
                hasattr(obj, method_name) for method_name in deserialize_method_names):
            return True
        try:
            pickle.dumps(obj)
        except Exception:
            return False
        else:
            return True
        
try:
    import cryptography
    from cryptography.fernet import Fernet
except ImportError:
    from types import SimpleNamespace
    import base64
    import warnings

    class Fernet:
        # only provides obfuscation, not encryption, via the base64 module
        def __init__(self, *args, **kwargs):
            warnings.warn(
                    "The cryptography module is not installed, so PAK will not be able to encrypt or decrypt data.\n"
                    "to fix this, install the cryptography module with `pip install cryptography`.",
                    RuntimeWarning
            )

        def encrypt(self, *args, **kwargs):
            return base64.b64encode(args[0].encode())

        def decrypt(self, *args, **kwargs):
            return base64.b64decode(args[0]).decode()


    class InvalidToken(Exception):
        ...


    cryptography = SimpleNamespace(
            fernet = SimpleNamespace(
                    Fernet = Fernet,
                    InvalidToken = InvalidToken,
                    fake_module = True
            )
    )
