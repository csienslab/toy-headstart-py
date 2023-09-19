from bqf import BinaryQF
import gmpy2
from hashlib import sha256, shake_256
from typing import Generator
from dataclasses import dataclass
from abstract import AbstractVDF


def H_kgen(x: bytes, k: int) -> Generator[int, None, None]:
    bl = (k + 7) // 8
    M = 1 << k
    while True:
        t = shake_256(x).digest(bl)
        r = int.from_bytes(t, "big")
        r |= 1 << (k - 1)
        yield r % M
        # not really important
        x = t


def H_P(x: bytes, k: int) -> int:
    # hash `x` to a k-bit prime
    for p in H_kgen(x, k):
        p |= 1
        if gmpy2.is_prime(p):
            return p


def H_D(x: bytes, k: int) -> int:
    # hash `x` to a k-bit discriminant for imaginary quadratic fields
    for d in H_kgen(x, k):
        d |= 7
        if gmpy2.is_prime(d):
            return -d


def H_QF(x: bytes, d: int, k: int) -> BinaryQF:
    # hash `x` to a k-bit quadratic form for imaginary quadratic fields
    for a in H_kgen(x, k):
        a |= 3
        if gmpy2.is_prime(a):
            if pow(d, (a - 1) // 2, a) == 1:
                b = pow(d, (a + 1) // 4, a)
                if b % 2 != 1:
                    b = a - b
                c = (b * b - d) // (4 * a)
                return BinaryQF(a, b, c)


def get_qf_principal_form(d: int) -> BinaryQF:
    # get the principal form of discriminant `d`
    # aka identity element
    # from https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf Definition 5.4
    k = d % 2
    return BinaryQF(1, k, (k**2 - d) // 4)


def qf_pow(x: BinaryQF, n: int) -> BinaryQF:
    r = get_qf_principal_form(x.discriminant())
    while n > 0:
        if n & 1:
            r = (r * x).reduced_form()
        x *= x
        n >>= 1
        x = x.reduced_form()
    return r


def qf_tobytes(x: BinaryQF, b: int) -> bytes:
    r = b""
    for v in x:
        r += int(v).to_bytes(b // 8, "big", signed=True)
    return r


def qf_frombytes(x: bytes, b: int) -> BinaryQF:
    r = []
    for i in range(0, len(x), b // 8):
        v = int.from_bytes(x[i : i + b // 8], "big", signed=True)
        r.append(v)
    return BinaryQF(*r)


def compute(g: BinaryQF, l: int, T: int) -> BinaryQF:
    # compute g^floor(2^T // l)
    # https://eprint.iacr.org/2018/623.pdf section 4.1 algorithm 4
    x = get_qf_principal_form(g.discriminant())
    r = 1
    for _ in range(T):
        b = 2 * r // l
        r = 2 * r % l
        x = (x * x * qf_pow(g, b)).reduced_form()
    return x


def vdf_eval(bits: int, g: BinaryQF, T: int):
    g = g.reduced_form()
    y = g
    for i in range(T):
        y = (y * y).reduced_form()
    y = y.reduced_form()
    l = H_P(qf_tobytes(g, bits) + qf_tobytes(y, bits), bits)
    pi = compute(g, l, T)
    return y, pi


def vdf_verify(bits: int, g: BinaryQF, y: BinaryQF, pi: BinaryQF, T: int):
    g = g.reduced_form()
    y = y.reduced_form()
    l = H_P(qf_tobytes(g, bits) + qf_tobytes(y, bits), bits)
    r = pow(2, T, l)
    lhs = qf_pow(pi, l) * qf_pow(g, r)
    return lhs.reduced_form() == y


@dataclass
class ToyProof:
    d: int
    g: BinaryQF
    y: BinaryQF
    pi: BinaryQF


class ToyVDF(AbstractVDF):
    def __init__(self, bits: int, T: int):
        self.bits = bits
        self.T = T

    def prove(self, challenge: bytes) -> ToyProof:
        d = H_D(challenge, self.bits)
        g = H_QF(challenge, d, self.bits)
        y, pi = vdf_eval(self.bits, g, self.T)
        return ToyProof(d, g, y, pi)

    def verify(self, challenge: bytes, proof: ToyProof) -> bool:
        d = H_D(challenge, self.bits)
        g = H_QF(challenge, d, self.bits)
        return vdf_verify(self.bits, g, proof.y, proof.pi, self.T)

    def extract_y(self, proof: ToyProof) -> bytes:
        return qf_tobytes(proof.y, self.bits)


if __name__ == "__main__":
    vdf = ToyVDF(256, 1 << 10)
    challenge = b"peko"
    proof = vdf.prove(challenge)
    print(proof)
    print(vdf.verify(challenge, proof))

    # bits = int(sys.argv[1])
    # x = bytes.fromhex(sys.argv[2])
    # T = int(sys.argv[3])

    # d = H_D(x, bits)
    # g = H_QF(x, d, bits)
    # y, pi = vdf_eval(bits, g, T)
    # assert vdf_verify(bits, g, y, pi, T)
    # sys.stdout.buffer.write(qf_tobytes(y, bits))
    # sys.stdout.buffer.write(qf_tobytes(pi, bits))
