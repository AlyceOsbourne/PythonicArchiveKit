from .base import PAK

def grab_annotations(cls):
    annotations = {}
    for base in filter(lambda base: issubclass(base, PAK), reversed(cls.__mro__)):
        annotations.update(base.__annotations__)
    return annotations

# noinspection PyTypeChecker,PyArgumentList
class TypedPAK(PAK):
    def __init__(self, **data):
        annotations = grab_annotations(self.__class__)
        for k, v in data.items():
            if k not in annotations:
                raise AttributeError(f"Invalid attribute {k}")
        for k, v in annotations.items():
            if k not in data:
                raise AttributeError(f"Missing attribute {k}")
        super().__init__(**data)