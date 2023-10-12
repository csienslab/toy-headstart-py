from rsa_accumulator import RSAAccumulator, RSAPrimeAccumulator
from bqf_accumulator import BQFAccumulator, ChiaBQFAccumulator
from merkle_tree import MerkleHash, MerkleTreeAccumulator
from abstract import AbstractAccumulator
from hashlib import sha256
import os, timeit


def test_accumulator(accumulator: AbstractAccumulator, n_parties: int):
    data = [os.urandom(16) for _ in range(n_parties)]
    acc = accumulator.accumulate(data)
    target = n_parties // 2
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

number = 5
bits = 10

for accumulator in accumulators:
    print(f"Testing {accumulator} with 2^{bits} parties")
    print(
        timeit.timeit(lambda: test_accumulator(accumulator, 1 << bits), number=number)
        / number
    )

"""
Testing <merkle_tree.MerkleTreeAccumulator object at 0x7fa27a7d7110> with 2^10 parties
0.0026112950001333955
Testing <rsa_accumulator.RSAAccumulator object at 0x7fa279fccd10> with 2^10 parties
0.28713178819998575
Testing <rsa_accumulator.RSAPrimeAccumulator object at 0x7fa279fcdd90> with 2^10 parties
1.459612356800062
Testing <bqf_accumulator.ChiaBQFAccumulator object at 0x7fa279e14690> with 2^10 parties
0.9690345607999916
Testing <bqf_accumulator.ChiaBQFAccumulator object at 0x7fa279e0bc90> with 2^10 parties
2.810477917000026
Testing <bqf_accumulator.BQFAccumulator object at 0x7fa279e14990> with 2^10 parties
8.455923664200053
"""
