import functools
from collections import UserString

__VERSION_STR__ = ".".join(map(str, (__VERSION__ := (2, 0, 1))))

class AttrPath(UserString):
    def __init__(self, path):
        super().__init__(path)
        
    def __truediv__(self, other):
        return AttrPath(".".join((self.data, other)))

    def __rtruediv__(self, other):
        return AttrPath(".".join((other, self.data)))

    def __repr__(self):
        return f"<AttrPath {self.data}>"
    
    def _do(self, obj, action, *args, **kwargs):
        *branches, leaf = self.data.split(".")
        return action(functools.reduce(getattr, branches, obj), leaf, *args, **kwargs)
    
    def get(self, obj, default = None):
        return self._do(obj, getattr, default)

    def set(self, obj, value):
        return self._do(obj, setattr, value)

    def del_(self, obj):
        return self._do(obj, delattr)
    
    def default(self, obj, default):
        return self._do(obj, lambda obj, leaf, default: obj.setdefault(leaf, default), default)
    
    __call__ = get
