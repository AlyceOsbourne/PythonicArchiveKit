import pickle
import types
import contextlib

# this is a requested feature from the original pak.py
# this is just a stripped down version of pak.py
# with no encryption, compression, or hashing

class MiniPak(types.SimpleNamespace):
    def __init__(self, *_, **kwargs):
        super().__init__(**kwargs)
    
    def __getattr__(self, item):
        return self.__dict__.setdefault(item, MiniPak())

    def __reduce_ex__(self, protocol):
        state = self.__dict__.copy()
        return (MiniPak, (), state)

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __bytes__(self):
        return pickle.dumps(self)

    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], bytes):
            return pickle.loads(args[0])
        else:
            return super().__new__(cls)

def save_pak(pak, path):
    with open(path, "wb") as f:
        f.write(bytes(pak))
        
def load_pak(path):
    try:
        with open(path, "rb") as f:
            return MiniPak(f.read())
    except FileNotFoundError:
        return MiniPak()
    
@contextlib.contextmanager
def pak_file(path):
    yield (pak:= load_pak(path))
    save_pak(pak, path)
        
        
if __name__ == "__main__":
    with pak_file("test.pak") as pak:
        pak.a.b.c = 1
    with pak_file("test.pak") as pak:
        print(pak.a.b.c)