
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


    class Fernet:
        # only provides obfuscation, not encryption, via the base64 module
        def __init__(self, *args, **kwargs):
            ...

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
