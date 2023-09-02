# PAK: Picklable and Encrypted Recursive Namespace

PAK is a Python library that provides a simple, recursive namespace that can be pickled and encrypted. It allows you to manage structured data with ease.

## Features

- **Recursive Namespace**: PAK offers a recursive namespace that can be used like a dictionary or an object. This allows for flexible and structured data management.

- **Pickling**: PAK objects can be easily serialized using Python's built-in `pickle` module, making it convenient for saving and loading data.

- **Encryption (Optional)**: PAK supports optional encryption of data using the `cryptography` package. This ensures the security of your PAK files.

- **Magic Folder Integration**: With the magic folder feature, you can dynamically import and manage PAK files from a specified folder.

## Installation

You can install PAK using pip:

```bash
pip install pythonic_archive_kit
```

For the full implementation with encryption, use:

```bash
pip install pythonic_archive_kit[encryption]
```

## Usage

### Set the Magic Folder

Before importing any PAKs, you must set the magic folder using the `set_magic_folder` function:

```python
from pythonic_archive_kit import set_magic_folder

# Set the magic folder location
set_magic_folder("my_magic_folder")
```

### Basic Usage

Now that you've set the magic folder, you can use PAK as follows:

```python
from pythonic_archive_kit import PAK, save_pak, load_pak, open_pak

# Create a PAK object
pak = PAK()
pak.foo = "bar"
pak["baz"] = "qux"

# Save and load PAK objects
save_pak(pak, "example.pak")
loaded_pak = load_pak("example.pak")
```

### Encryption (Optional)

To use encryption, ensure you have the `cryptography` package installed. You can encrypt PAK data by providing a password:

```python
from pythonic_archive_kit import save_pak, load_pak

# Save an encrypted PAK file
save_pak(pak, "encrypted.pak", password="mypassword")

# Load the encrypted PAK file
loaded_pak = load_pak("encrypted.pak", password="mypassword")
```

### Examples

Here are some examples of how PAK can be used in different scenarios, including game development, project management, and personal note-taking.

#### RPG Save Data

```python
# Save player data
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
with open_pak("project_data.pak") as project:
    project.name = "My Awesome Project"
    project.tasks = ["design", "implementation", "testing"]

# Load project data
with open_pak("project_data.pak") as project:
    print(project.name)  # Output: My Awesome Project
```

#### Personal Notes

```python
# Save personal notes
with open_pak("personal_notes.pak") as notes:
    notes.journal.day1 = "Visited the park"
    notes.reminders = ["Buy groceries", "Call mom"]

# Load personal notes
with open_pak("personal_notes.pak") as notes:
    print(notes.journal.day1)  # Output: Visited the park
```

## Magic Folder Integration

The magic folder is `.magic` by default. Once you've set the magic folder, you can seamlessly work with PAK files located in that folder. Here's an example:

```python
from pythonic_archive_kit.magic import set_magic_folder

# Set the magic folder location
set_magic_folder("my_magic_folder")

# once set you can use PAK files as follows
from pythonic_archive_kit.magic import my_pak

# Access PAK files with attribute-style syntax
my_pak.example_data = "Hello, PAK!"

# PAK files are automatically managed
```

In this example, `my_pak` is automatically associated with a PAK file located in the magic folder. You can use it just like any other PAK object.
