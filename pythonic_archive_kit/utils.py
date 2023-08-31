__VERSION_STR__ = ".".join(map(str, (__VERSION__ := (1, 0, 9))))

import hashlib


def _hash_state(state):
    """Generate a hash of the state of a PAK object."""
    return hashlib.sha256(str(state).encode()).hexdigest()

def _sweep(pak):
    """Remove empty PAK objects from a PAK object."""
    for k, v in pak.__dict__.copy().items():
        if isinstance(v, PAK):
            _sweep(v)
            if not v:
                del pak.__dict__[k]
    return pak

