# PAK: Picklable and Encrypted Recursive Namespace

PAK is a simple, recursive namespace that can be pickled and encrypted.
## Installation

```commandline
pip install pythonic_archive_kit
```
if you wish to use the full implementation, you can run:

```commandline
pip install pythonic_archive_kit[encryption]
```

## Updating

```commandline
pip install --upgrade pythonic_archive_kit
```

## Requirements
Optionally the `cryptography` package can be installed to use the full implementation.

```commandline  
pip install cryptography
```

## Usage

The `PAK` class provides a way to create a recursive namespace that can be pickled and encrypted.

### Classes

#### `PAK`

```py
class PAK(SimpleNamespace):
    """This is the core of the PAK system. It is a recursive namespace that can be pickled and encrypted."""
    # ...
```

### Methods

#### `save(data, path, password=None)`

```py
def save(data, path, password=None):
    """Save a PAK file to disk."""
    # ...
```

#### `load(path, password=None, create=True)`

```py
def load(path, password=None, create=True):
    """Load a PAK file from disk. If create is True, a new PAK file will be created if one does not exist."""
    # ...
```

#### `open_pak(path, password=None, create=True)`

```py
@contextlib.contextmanager
def open_pak(path, password=None, create=True):
    """Open a PAK file from disk. If create is True, a new PAK file will be created if one does not exist. Saves the PAK file on exit."""
    # ...
```

## Examples

### Importing

```py
from pythonic_archive_kit import save_pak, load_pak, open_pak
```
This will import the standard interface. If `cryptography` is installed, this will use the main PAK implementation. 
If `cryptography` is not installed, this will use the fallback MiniPAK implementation.

```py
### RPG Save Data

Here's an example of using PAK to save and load player data for an RPG game:

```py
# Save player data
with open_pak("player_data.pak") as player_data:
    player_data.stats.level = 10
    player_data.inventory.gold = 500
    player_data.inventory.items = ["sword", "shield"]

# Load player data
with open_pak("player_data.pak") as player_data:
    print(player_data.stats.level)  # Output: 10
```

### Project Management

PAK can also be used for managing project data:

```py
# Save project data
with open_pak("project_data.pak") as project:
    project.name = "My Awesome Project"
    project.tasks = ["design", "implementation", "testing"]

# Load project data
with open_pak("project_data.pak") as project:
    print(project.name)  # Output: My Awesome Project
```

### Personal Notes

Even for personal note-taking, PAK can be useful:

```py
# Save personal notes
with open_pak("personal_notes.pak") as notes:
    notes.journal.day1 = "Visited the park"
    notes.reminders = ["Buy groceries", "Call mom"]

# Load personal notes
with open_pak("personal_notes.pak") as notes:
    print(notes.journal.day1)  # Output: Visited the park
```

