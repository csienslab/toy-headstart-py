from bqf import BinaryQF
import gmpy2
from hashlib import sha256, shake_256
import sys
from typing import Generator


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
            r *= x
        x *= x
        n >>= 1
        x = x.reduced_form()
    return r.reduced_form()


def qf_tobytes(x: BinaryQF, b: int) -> bytes:
    r = b""
    for v in x:
        r += b"\x00" if v >= 0 else b"\x01"
        r += abs(int(v)).to_bytes(b // 8, "big")
    return r


def qf_frombytes(x: bytes, b: int) -> BinaryQF:
    r = []
    for i in range(0, len(x), b // 8 + 1):
        is_negative = x[i]
        v = int.from_bytes(x[i + 1 : i + 1 + b // 8], "big")
        if is_negative == 1:
            v = -v
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
        x = qf_pow(x, 2) * qf_pow(g, b)
    return x.reduced_form()


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


if __name__ == "__main__":
    bits = int(sys.argv[1])
    x = bytes.fromhex(sys.argv[2])
    T = int(sys.argv[3])

    d = H_D(x, bits)
    g = H_QF(x, d, bits)
    y, pi = vdf_eval(bits, g, T)
    sys.stdout.buffer.write(qf_tobytes(y, bits))
    sys.stdout.buffer.write(qf_tobytes(pi, bits))
