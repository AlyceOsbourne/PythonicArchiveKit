# Pythonic Archive Kit (PAK) - Save Data Management Library

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Pythonic Archive Kit (PAK) is a lightweight and user-friendly library designed to simplify save data management. It provides a clean and intuitive interface for handling save data, making it easy to load, save, and manage different versions of your application's save files. PAK aims to streamline the process of integrating save data functionality into your projects.

## Features

- Efficiently manage save data using a simple and intuitive API.
- Seamlessly handle version compatibility between different save data instances.
- Automatic hashing and integrity checks to ensure the validity of save files.
- Easily upgrade save data structures while maintaining backward compatibility.
- Lightweight and self-contained with minimal dependencies.

## Example Usage

```python
from pak import SaveData, SaveDataSlots

# Define the slots for the save data
class Slots(SaveDataSlots):
    DEV = "s/dev"
    SLOT_1 = "s/slot1"
    SLOT_2 = "s/slot2"
    SLOT_3 = "s/slot3"

# Access a save data slot
with Slots["DEV"] as opened:
    player_meta = opened["player_meta"]
    player_meta.setdefault("name", "Player")
    player_meta.setdefault("level", 1)
    player_meta.setdefault("exp", 0)
    
    player_inventory = player_meta["inventory"]
    player_inventory.setdefault("gold", 0)
    player_inventory.setdefault("items", [])
    
    flags = opened["flags"]
    flags.setdefault("tutorial", False)
    flags.setdefault("intro", False)
    # ... (other flags)
    
    world = opened["world"]
    world.setdefault("current_area", "home")
```


