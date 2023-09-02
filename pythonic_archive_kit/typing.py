from pythonic_archive_kit.base import PAK


class TypedPAK(PAK):
    def __init__(self, **data):
        for k, v in data.items():
            if k not in self.__annotations__:
                raise AttributeError(f"Invalid attribute {k}")
        for k, v in self.__annotations__.items():
            if k not in data:
                if not hasattr(v, "__origin__"):
                    raise AttributeError(f"Missing attribute {k}")
        super().__init__(**data)
