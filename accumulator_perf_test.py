from rsa_accumulator import RSAAccumulator
from bqf_accumulator import BQFAccumulator
from merkle_tree import MerkleHash, MerkleTreeAccumulator
from abstract import AbstractAccumulator
from hashlib import sha256
import os, timeit

def test_accumulator(accumulator: AbstractAccumulator, n_parties: int):
    data = [os.urandom(8) for _ in range(n_parties)]
    acc = accumulator.accumulate(data)
    target = n_parties // 2
    w = accumulator.witgen(acc, data, target)
    accval = accumulator.get_accval(acc)
    if not accumulator.verify(accval, w, data[target]):
        raise ValueError("accumulator verification failed")

accumulators = [MerkleTreeAccumulator(MerkleHash(sha256)), RSAAccumulator.generate(2048), BQFAccumulator.generate(256)]

number = 5
bits = 12

for accumulator in accumulators:
    print(f"Testing {accumulator} with 2^{bits} parties")
    print(timeit.timeit(lambda: test_accumulator(accumulator, 1 << bits), number=number) / number)

"""
Testing <merkle_tree.MerkleTreeAccumulator object at 0x7f7e06260950> with 2^12 parties
0.012250411801505833
Testing <rsa_accumulator.RSAAccumulator object at 0x7f7e06265250> with 2^12 parties
6.078687308396911
Testing <bqf_accumulator.BQFAccumulator object at 0x7f7e062659d0> with 2^12 parties
15.13127411819878
"""
