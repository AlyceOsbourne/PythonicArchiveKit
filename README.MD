# PAK File Usage Documentation

The `PAK` class in this Python module empowers structured data management using hierarchical keys, similar to dictionary-style usage. This documentation offers insights into the class and its methods, supported by illustrative examples.

## `PAK` Class

The `PAK` class is designed for streamlined handling of organized data through nested keys, akin to dictionaries.

### Usage Example

```python
from pak_module import PAK

data = PAK()
data["user.name"] = "John"
data["user.age"] = 30
data["contact.email"] = "john@example.com"

# Nesting example
data["user.address.city"] = "New York"
data["user.address.zip"] = "10001"

print(data["user.name"])  # Output: John
print(data["user.address.city"])  # Output: New York
print(data)
```

In the example above, the `PAK` class enables hierarchical data structuring with dot-separated keys. This simplifies access and management of intricate nested data structures.

When you print the `data` object, it produces the following output:

```
user:
  name: John
  age: 30
  address:
    city: New York
    zip: 10001
contact:
  email: john@example.com
```

The `PAK` class automatically formats the nested keys and values to provide a human-readable representation.

## `PakFile` Class

The `PakFile` class builds upon the capabilities of the `PAK` class and provides methods for saving, loading, and handling PAK data in files. It also offers support for encryption and compression.

### Usage Examples

#### Saving and Loading PAK Data

```python
from pak_module import PakFile

data = PakFile()
data["user.name"] = "Alice"
data["user.age"] = 25

# Save to file
data.save("data.pak")

# Load from file
loaded_data = PakFile.load("data.pak")
print(loaded_data["user.name"])  # Output: Alice
```

In the above example, data is saved to a file using the `save` method and then loaded back using the `load` method.

#### Using the `open` Context Manager

```python
from pak_module import PakFile

with PakFile.open("data.pak") as data:
    data["user.name"] = "Bob"
    data["user.age"] = 28
    data["user.address.city"] = "Los Angeles"
    data["user.address.zip"] = "90001"
# Data is automatically saved when the context exits
```

The `open` method provides a convenient context manager for working with PAK data. Any changes made within the context are automatically saved upon exiting the context.
