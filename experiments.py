from collections import UserString
from pak import open
import weakref

class PAKPath(UserString):
    def __init__(self, path):
        super().__init__(path)
        
    def __truediv__(self, other):
        return PAKPath(f"{self.data}.{other}")
    
    def __rmatmul__(self, pak):
        """Attempts to get a weakref.proxy to the value at the path"""
        v = pak[self.data] if self.data in pak else None
        try:
            return weakref.proxy(v)
        except TypeError:
            return v
        
    def __ror__(self, other):
        pak, default = other
        return pak.setdefault(self.data, default)

with open("example.pak") as pak:
    print(pak)
    pak["a.b.c"] = 1
    print(pak)
    del pak["a.b.c"]
    print(pak)