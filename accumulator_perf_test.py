from rsa_accumulator import RSAAccumulator, RSAPrimeAccumulator
from bqf_accumulator import BQFAccumulator, ChiaBQFAccumulator
from merkle_tree import MerkleHash, MerkleTreeAccumulator
from abstract import AbstractAccumulator
from hashlib import sha256
import os, timeit, random


def test_accumulator(accumulator: AbstractAccumulator, n_parties: int, n_witness: int):
    data = [os.urandom(16) for _ in range(n_parties)]
    acc = accumulator.accumulate(data)
    for _ in range(n_witness):
        target = random.randrange(n_parties)
        w = accumulator.witgen(acc, data, target)
        accval = accumulator.get_accval(acc)
        if not accumulator.verify(accval, w, data[target]):
            raise ValueError("accumulator verification failed")


accumulators = [
    MerkleTreeAccumulator(MerkleHash(sha256)),
    RSAAccumulator.generate(2048),
    RSAPrimeAccumulator.generate(2048),
    ChiaBQFAccumulator.generate(256),
    ChiaBQFAccumulator.generate(1024),
    BQFAccumulator.generate(256),
]

number = 3
bits = 10
n_witness = 1 << (bits // 2)

for accumulator in accumulators:
    print(f"Testing {accumulator} with 2^{bits} parties")
    print(
        timeit.timeit(
            lambda: test_accumulator(accumulator, 1 << bits, n_witness), number=number
        )
        / number
    )

"""
Testing <merkle_tree.MerkleTreeAccumulator object at 0x7f89f0c03dd0> with 2^10 parties
0.003026562000741251
Testing <rsa_accumulator.RSAAccumulator object at 0x7f89f1617010> with 2^10 parties
4.802891847333133
Testing <rsa_accumulator.RSAPrimeAccumulator object at 0x7f89f0c13ad0> with 2^10 parties
22.897864149330417
Testing <bqf_accumulator.ChiaBQFAccumulator object at 0x7f89f0c13d50> with 2^10 parties
16.257414020001306
Testing <bqf_accumulator.ChiaBQFAccumulator object at 0x7f89f0c13b90> with 2^10 parties
45.349081779665234
Testing <bqf_accumulator.BQFAccumulator object at 0x7f89f0c13b10> with 2^10 parties
133.76148696666738
"""
