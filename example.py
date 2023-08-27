# PAK Module: Simplifying Data Management
# ------------------------------------------
# Import the required functions from the 'pak' module
from pak import open

# 1. Import the module
# from pak import open

# 2. Open a PAK file for data manipulation
with open("example.pak") as pak:
    # Assign values using dot-separated keys
    pak["a.b.c"] = 1
    pak["a.b.d"] = 2
    pak["a.b.e"] = 3
    pak["a.b.f"] = 4

    # Automatic nesting: 'pak' automatically creates nested dictionaries
    print(pak)
    # Output:
    # a:
    #   b:
    #     c: 1
    #     d: 2
    #     e: 3
    #     f: 4

    # Clear the data within the PAK
    pak.clear()
    print(pak)  # Output: {}