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


AccumulatorT = TypeVar("AccumulatorT")
AccumulationValueT = TypeVar("AccumulationValueT")
WitnessT = TypeVar("WitnessT")


class AbstractAccumulator(
    Generic[AccumulatorT, AccumulationValueT, WitnessT], metaclass=ABCMeta
):
    @abstractmethod
    def __init__(self, **kwargs):
        pass

    @abstractmethod
    def accumulate(self, X: list[bytes]) -> AccumulatorT:
        pass

    @abstractmethod
    def witgen(self, acc: AccumulatorT, X: list[bytes], index: int) -> WitnessT:
        pass

    @abstractmethod
    def verify(self, accval: AccumulationValueT, w: WitnessT, x: bytes) -> bool:
        pass

    @abstractmethod
    def get_accval(self, acc: AccumulatorT) -> AccumulationValueT:
        pass

    @abstractmethod
    def get_bytes(self, accval: AccumulationValueT) -> bytes:
        pass
