# PAK - Python Object Persistence and Encryption Library

PAK is a Python library that provides a simple way to persist Python objects securely using encryption. It allows you to store and retrieve complex Python objects while keeping the data encrypted and protected. This library is particularly useful when you need to save sensitive data in a file, such as configuration settings or user-specific information.

## Usage

### Loading and Saving Data

PAK offers methods to load and save encrypted data. You can use these methods to read and write encrypted content to a file.

```python
def load(path, password, create=False) -> PAK:
    # Loading encrypted data from a file...

def save(path, password, data: PAK):
    # Saving encrypted data to a file...
```

### Context Management

The library also provides a context management feature for simplified data manipulation within a block.

```python
@contextlib.contextmanager
def open(path, password, create=False):
    # Loading encrypted data and providing a context for manipulation...
```

### Example Usage

```python
# Loading or creating encrypted data
with open("data.pak", "your_password_here", create=True) as pak:
    pak.my_data.key = "value"
    
# Encrypted data is automatically saved upon exiting the context
```

## Security Considerations

PAK uses encryption to protect your data. It's important to keep your encryption password safe and not expose it in your code or repository. Additionally, ensure that you're following best practices for handling sensitive data.

