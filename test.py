from bqf import BinaryQF, qf_pow
from toy_vdf import H_D, H_QF
import chiavdf
import random


def int2bytes(x):
    return int(x).to_bytes((x.bit_length() + 7) // 8, "big")


def bytes2int(x):
    return int.from_bytes(x, "big")


seed = b"peko"
exp = 4

D = H_D(seed, 256)
g = H_QF(seed, D, 256)
print(g)
y = qf_pow(g, exp)
print(y.a, y.b, y.c)


ya, yb, yc = map(
    bytes2int,
    chiavdf.exp(int2bytes(g.a), int2bytes(g.b), int2bytes(g.c), [int2bytes(4)]),
)
print(ya, yb, yc)
