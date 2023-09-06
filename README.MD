# PAK: Picklable and Encrypted Recursive Namespace

PAK is a Python library that provides a simple, recursive namespace that can be pickled and encrypted. It allows you to manage structured data with ease.

## Features

- **Simple Interface**: PAK provides a simple interface for managing data. It can be used like a dictionary or an
  object. It automatically handles the creation of nested namespaces, this allows for structured data management.

- **Recursive Namespace**: PAK offers a recursive namespace that can be used like a dictionary or an object. This allows
  for flexible and structured data management.

- **Context Manager**: PAK provides a context manager that automatically saves and loads PAK objects. This makes it easy
  to manage your data.

- **Pickling**: PAK objects can be easily serialized, it utilizes pickle, or optionally dill, to serialize data. This
  allows you to save and load your PAK objects. This process is block hashed to help protect against data corruption
  and tampering.

- **Compression**: PAK supports compression of data using the `lzma' or 'gzip' packages. This
  reduces the size of your PAK files.

- **Encryption (Optional)**: PAK supports optional encryption of data using the `cryptography` package. This ensures the
  security of your PAK files.

## Installation

You can install PAK using pip:

```bash
pip install pythonic_archive_kit
```

This will provide the basic implementation of PAK. If you want to use encryption, you will need to install
the `cryptography` package:

```bash
pip install cryptography
# or
pip install pythonic_archive_kit[encryption]
```

And to include the more advanced serialization provided by `dill`:

```bash
pip install dill
# or
pip install pythonic_archive_kit[serialization]
```

## Usage

### Basic Usage

```python
from pythonic_archive_kit import load_pak, PAK, save_pak

# Create a PAK object
pak = PAK()
pak.foo = "bar"
pak["baz"] = "qux"

# Save and load PAK objects
save_pak(pak, "example.pak")
loaded_pak = load_pak("example.pak")
```

You can also make use of the paks context manager to automatically save and load PAK objects:

```python
from pythonic_archive_kit import open_pak

with open_pak("gamedata") as gamedata:
    ...
```

### Encryption (Optional)

To use encryption, ensure you have the `cryptography` package installed. You can encrypt PAK data by providing a
password:

```python
from pythonic_archive_kit import save_pak, load_pak, PAK

pak = PAK()
# Save an encrypted PAK file
save_pak(pak, "encrypted.pak", password = "mypassword")

# Load the encrypted PAK file
loaded_pak = load_pak("encrypted.pak", password = "mypassword")
```

A password can also be passed to the context manager:

```python
from pythonic_archive_kit import open_pak

with open_pak("gamedata", password = "mypassword") as gamedata:
    ...
```

### Examples

Here are some examples of how PAK can be used in different scenarios, including game development, project management,
and personal note-taking.

#### RPG Save Data

```python
# Save player data
from pythonic_archive_kit import open_pak

with open_pak("player_data.pak") as player_data:
    player_data.stats.level = 10
    player_data.inventory.gold = 500
    player_data.inventory.items = ["sword", "shield"]

# Load player data
with open_pak("player_data.pak") as player_data:
    print(player_data.stats.level)  # Output: 10
```

#### Project Management

```python
# Save project data
from pythonic_archive_kit import open_pak

with open_pak("project_data.pak") as project:
    project.name = "My Awesome Project"
    project.tasks = ["design", "implementation", "testing"]

# Load project data
with open_pak("project_data.pak") as project:
    print(project.name)  # Output: My Awesome Project
```

#### Personal Notes

```python
from pythonic_archive_kit import open_pak

# Save personal notes
with open_pak("personal_notes.pak") as notes:
  notes.journal.day1 = "Visited the park"
  notes.reminders = ["Buy groceries", "Call mom"]

# Load personal notes
with open_pak("personal_notes.pak") as notes:
  print(notes.journal.day1)  # Output: Visited the park
```

## Contributing

Feel free to contribute to PAK by opening an issue or pull request. If you have any questions, feel free to contact me
at via GitHub.

## License

#### GNU General Public License v3.0

PAK is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for more information.