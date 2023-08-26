# mixin for dataclasses that stores the fields in a PAK, the init_subclass can take a pak argument as the parent dict (We then store entries in a nested fashion
import abc
import dataclasses


@dataclasses.dataclass
class PAKMixin(abc.ABCMeta):
    ...



