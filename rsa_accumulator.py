from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import gmpy2, math
from utils import H_P
from abstract import AbstractAccumulator


class RSAAccumulator(AbstractAccumulator[int, int, int]):
    def __init__(self, n: int, g: int):
        self.n = gmpy2.mpz(n)
        self.g = gmpy2.mpz(g)

    def accumulate(self, X: list[bytes]) -> int:
        r = self.g
        for x in X:
            r = gmpy2.powmod(r, H_P(x, 256), self.n)
        return int(r)

    def witgen(self, acc: int, X: list[bytes], index: int) -> int:
        r = self.g
        for i, x in enumerate(X):
            if i != index:
                r = gmpy2.powmod(r, H_P(x, 256), self.n)
        return int(r)

    def verify(self, acc: int, w: int, x: bytes) -> bool:
        return gmpy2.powmod(w, H_P(x, 256), self.n) == acc
    
    def nonmemwitgen(self, acc: int, X: list[bytes], x: bytes) -> tuple[int, int]:
        s = math.prod(H_P(x, 256) for x in X)
        _, a, b = gmpy2.gcdext(s, H_P(x, 256))
        B = gmpy2.powmod(self.g, b, self.n)
        return a, B
    
    def nonmemverify(self, acc: int, w: tuple[int, int], x: bytes) -> bool:
        a, B = w
        return gmpy2.powmod(acc, a, self.n) * gmpy2.powmod(B, H_P(x, 256), self.n) % self.n == self.g

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

    w = acc.nonmemwitgen(accm, X, b"peko4")
    assert acc.nonmemverify(accval, w, b"peko4")
    w = acc.nonmemwitgen(accm, X, X[0])
    assert not acc.nonmemverify(accval, w, X[0])
