from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from abstract import AbstractAccumulator


class RSAAccumulator(AbstractAccumulator[int, int, int]):
    def __init__(self, n: int, g: int):
        self.n = n
        self.g = g

    def accumulate(self, X: list[bytes]) -> int:
        r = self.g
        for x in X:
            r = pow(r, bytes_to_long(x), self.n)
        return r

    def witgen(self, acc: int, X: list[bytes], index: int) -> int:
        r = self.g
        for i, x in enumerate(X):
            if i != index:
                r = pow(r, bytes_to_long(x), self.n)
        return r

    def verify(self, acc: int, w: int, x: bytes) -> bool:
        return pow(w, bytes_to_long(x), self.n) == acc

    def get_accval(self, acc: int) -> int:
        return acc

    def get_bytes(self, acc: int) -> bytes:
        bl = (self.n.bit_length() + 7) // 8
        return acc.to_bytes(bl, "big")

    @staticmethod
    def generate(bits):
        # require trusted setup :(
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        g = pow(2, 65537, n)
        return RSAAccumulator(n, g)


if __name__ == "__main__":
    acc = RSAAccumulator.generate(1024)
    X = [b"peko", b"peko2", b"peko3"]
    accm = acc.accumulate(X)
    w = acc.witgen(accm, X, 1)
    accval = acc.get_accval(accm)
    assert acc.verify(accval, w, X[1])
    print(acc.get_bytes(accval))
