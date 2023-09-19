from abc import ABCMeta, abstractmethod
from typing import TypeVar, Generic

ProofT = TypeVar("ProofT")


class AbstractVDF(Generic[ProofT], metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, bits: int, T: int):
        pass

    @abstractmethod
    def prove(self, challenge: bytes) -> ProofT:
        pass

    @abstractmethod
    def verify(self, challenge: bytes, proof: ProofT) -> bool:
        pass

    @abstractmethod
    def extract_y(self, proof: ProofT) -> bytes:
        pass
