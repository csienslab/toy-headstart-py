from Crypto.Util.number import (
    getPrime,
    isPrime,
    getRandomNBitInteger,
    bytes_to_long,
    long_to_bytes,
)
from bqf import BinaryQF, qf_pow, qf_tobytes
from abstract import AbstractAccumulator
import chiavdf


class BQFAccumulator(AbstractAccumulator[BinaryQF, BinaryQF, BinaryQF]):
    def __init__(self, g: BinaryQF):
        self.d = g.discriminant()
        self.g = g

    def accumulate(self, X: list[bytes]) -> BinaryQF:
        r = self.g
        for x in X:
            r = qf_pow(r, bytes_to_long(x))
        return r

    def witgen(self, acc: BinaryQF, X: list[bytes], index: int) -> BinaryQF:
        r = self.g
        for i, x in enumerate(X):
            if i != index:
                r = qf_pow(r, bytes_to_long(x))
        return r

    def verify(self, acc: BinaryQF, w: BinaryQF, x: bytes) -> bool:
        return qf_pow(w, bytes_to_long(x)) == acc

    def get_accval(self, acc: BinaryQF) -> BinaryQF:
        return acc

    def get_bytes(self, acc: BinaryQF) -> bytes:
        return qf_tobytes(acc, self.d.bit_length())

    @classmethod
    def generate(cls, bits):
        while True:
            p = getPrime(bits)
            if p % 4 == 3:
                d = -p
                break
        while True:
            a = getRandomNBitInteger(bits)
            a |= 3
            if isPrime(a):
                if pow(d, (a - 1) // 2, a) == 1:
                    b = pow(d, (a + 1) // 4, a)
                    if b % 2 != 1:
                        b = a - b
                    c = (b * b - d) // (4 * a)
                    g = BinaryQF(a, b, c)
                    return cls(g)


def int2bytes(x):
    return int(x).to_bytes((x.bit_length() + 7) // 8, "big")


def bytes2int(x):
    return int.from_bytes(x, "big")


def chai_exp(g: BinaryQF, exps: list[bytes]):
    a, b, c = map(
        bytes2int, chiavdf.exp(int2bytes(g.a), int2bytes(g.b), int2bytes(g.c), exps)
    )
    return BinaryQF(a, b, c)


class ChiaBQFAccumulator(BQFAccumulator):
    def accumulate(self, X: list[bytes]) -> BinaryQF:
        return chai_exp(self.g, X)

    def witgen(self, acc: BinaryQF, X: list[bytes], index: int) -> BinaryQF:
        return chai_exp(self.g, X[:index] + X[index + 1 :])

    def verify(self, acc: BinaryQF, w: BinaryQF, x: bytes) -> bool:
        return chai_exp(w, [x]) == acc


if __name__ == "__main__":

    def test(acc):
        X = [b"peko", b"peko2", b"peko3"]
        accm = acc.accumulate(X)
        w = acc.witgen(accm, X, 1)
        accval = acc.get_accval(accm)
        assert acc.verify(accval, w, X[1])
        print(acc.get_bytes(accval).hex())

    g = BQFAccumulator.generate(1024).g
    test(BQFAccumulator(g))
    test(ChiaBQFAccumulator(g))
