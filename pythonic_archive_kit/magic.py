import functools
import pathlib
import contextlib
import atexit
from .base import open_pak

MAGIC_FOLDER = pathlib.Path(".magic")
MAGIC_FOLDER.mkdir(parents=True, exist_ok=True)

magic_context_stack = contextlib.ExitStack()
magic_context_stack.__enter__()
atexit.register(magic_context_stack.__exit__, None, None, None)

def set_magic_folder(path):
    global MAGIC_FOLDER
    MAGIC_FOLDER = pathlib.Path(path)
    MAGIC_FOLDER.mkdir(parents=True, exist_ok=True)

@functools.cache
def __getattr__(name):
    if name in globals():
        return globals()[name]
    elif name == "__path__":
        return [str(MAGIC_FOLDER)]
    return grab_pak(name)

@functools.cache
def grab_pak(name):
    path = MAGIC_FOLDER / name.lower()
    path = path.with_suffix(".pak")
    path.parent.mkdir(parents = True, exist_ok = True)
    return magic_context_stack.enter_context(open_pak(path))
    
    
    