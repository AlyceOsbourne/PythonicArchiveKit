try:
    import lzma
    open = lzma.open
    compress = lzma.compress
    decompress = lzma.decompress
except ImportError:
    try:
        import gzip
        open = gzip.open
        compress = gzip.compress
        decompress = gzip.decompress
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
    cryptography = None
    class Fernet:
        def __init__(self, *args, **kwargs):
            ...
        
        def encrypt(self, *args, **kwargs):
            return args[0]
        
        def decrypt(self, *args, **kwargs):
            return args[0]