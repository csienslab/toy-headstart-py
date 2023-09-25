from hashlib import sha256
from abstract import AbstractAccumulator
from typing import Optional


class MerkleHash:
    # https://crypto.stackexchange.com/questions/2106/what-is-the-purpose-of-using-different-hash-functions-for-the-leaves-and-interna
    def __init__(self, hashfn):
        self.hashfn = hashfn

    def hash_leaf(self, x: bytes) -> bytes:
        return self.hashfn(b"\x00" + x).digest()

    def hash_node(self, x: bytes, y: bytes) -> bytes:
        return self.hashfn(b"\x01" + x + y).digest()


class MerkleTree:
    def __init__(
        self,
        H: MerkleHash,
        tree: list[bytes],
        data: Optional[list[bytes]] = None,
        *,
        verify_data=True
    ):
        self.H = H
        self.tree = tree
        self.lendata = (len(tree) + 1) // 2
        self.data = data
        if data is not None and verify_data:
            self.verify_data()

    @property
    def root(self):
        return self.tree[0]

    def verify_data(self):
        l = len(self.data)
        if l & (l - 1) != 0:
            raise ValueError("data length must be a power of 2")
        if len(self.tree) != 2 * len(self.data) - 1:
            raise ValueError("tree length must be 2 * len(data) - 1")
        if MerkleTree.compute_tree(self.H, self.data) != self.tree:
            raise ValueError("invalid tree")

    def check_present(self, index: int, x: bytes):
        x = self.H.hash_leaf(x)
        cur = index + self.lendata - 1
        while cur > 0:
            if cur & 1:  # left
                x = self.H.hash_node(x, self.tree[cur + 1])
            else:  # right
                x = self.H.hash_node(self.tree[cur - 1], x)
            cur = (cur - 1) // 2
        return x == self.root

    def get_proof(self, index: int) -> list[tuple[str, bytes]]:
        cur = index + self.lendata - 1
        ret = []
        while cur > 0:
            if cur & 1:
                ret.append(("R", self.tree[cur + 1]))
            else:
                ret.append(("L", self.tree[cur - 1]))
            cur = (cur - 1) // 2
        return ret

    @staticmethod
    def check_proof(
        H: MerkleHash, root: bytes, x: bytes, index: int, proof: list[tuple[str, bytes]]
    ):
        x = H.hash_leaf(x)
        for side, h in proof:
            if side == "R":
                x = H.hash_node(x, h)
            elif side == "L":
                x = H.hash_node(h, x)
            else:
                raise ValueError("invalid proof")
        return x == root

    @staticmethod
    def compute_tree(H: MerkleHash, data: list[bytes]):
        l = len(data)
        if l & (l - 1) != 0:
            raise ValueError("data length must be a power of 2")
        tree = [b""] * (2 * len(data) - 1)
        for i in range(len(data)):
            tree[i + len(data) - 1] = H.hash_leaf(data[i])
        for i in range(len(data) - 2, -1, -1):
            tree[i] = H.hash_node(tree[i * 2 + 1], tree[i * 2 + 2])
        return tree

    @staticmethod
    def from_data(H: MerkleHash, data: list[bytes]):
        data = list(data)
        l = len(data)
        if l & (l - 1) != 0:
            data.extend([b""] * (2 ** (l.bit_length()) - l))
        tree = MerkleTree.compute_tree(H, data)
        return MerkleTree(H, tree, data)


class MerkleTreeAccumulator(
    AbstractAccumulator[MerkleTree, bytes, list[tuple[str, bytes]]]
):
    def __init__(self, H: MerkleHash):
        self.H = H

    def accumulate(self, X: list[bytes]) -> MerkleTree:
        mkt = MerkleTree.from_data(self.H, X)
        return mkt

    def witgen(self, mkt: MerkleTree, X: list[bytes], index: int):
        return mkt.get_proof(index)

    def verify(self, root: bytes, w: list[tuple[str, bytes]], x: bytes):
        return MerkleTree.check_proof(self.H, root, x, 0, w)

    def get_accval(self, mkt: MerkleTree) -> bytes:
        return mkt.root

    def get_bytes(self, root: bytes) -> bytes:
        return root


if __name__ == "__main__":

    def int2bytes(n):
        return n.to_bytes((n.bit_length() + 7) // 8, "big")

    data = [int2bytes(i) for i in [1, 2, 3, 4, 5]]
    H = MerkleHash(sha256)
    mkt = MerkleTree.from_data(H, data)
    mkt2 = MerkleTree(H, mkt.tree)
    for i, x in enumerate(data):
        assert mkt2.check_present(i, x)
        proof = mkt2.get_proof(i)
        assert MerkleTree.check_proof(H, mkt2.root, x, i, proof)

    acc = MerkleTreeAccumulator(H)
    X = [b"peko", b"peko2", b"peko3"]
    accm = acc.accumulate(X)
    w = acc.witgen(accm, X, 1)
    accval = acc.get_accval(accm)
    assert acc.verify(accval, w, X[1])
    print(acc.get_bytes(accval))
