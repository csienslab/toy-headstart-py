from hashlib import sha256


class MerkleTree:
    def __init__(
        self, H, tree: list[bytes], data: list[bytes] = None, *, verify_data=True
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
        x = self.H(x).digest()
        cur = index + self.lendata - 1
        while cur > 0:
            if cur & 1:  # left
                x = self.H(x + self.tree[cur + 1]).digest()
            else:  # right
                x = self.H(self.tree[cur - 1] + x).digest()
            cur = (cur - 1) // 2
        return x == self.root

    @staticmethod
    def compute_tree(H, data: list[bytes]):
        l = len(data)
        if l & (l - 1) != 0:
            raise ValueError("data length must be a power of 2")
        tree = [None] * (2 * len(data) - 1)
        for i in range(len(data)):
            tree[i + len(data) - 1] = H(data[i]).digest()
        for i in range(len(data) - 2, -1, -1):
            tree[i] = H(tree[i * 2 + 1] + tree[i * 2 + 2]).digest()
        return tree

    @staticmethod
    def from_data(H, data: list[bytes]):
        data = list(data)
        l = len(data)
        if l & (l - 1) != 0:
            data.extend([b""] * (2 ** (l.bit_length()) - l))
        tree = MerkleTree.compute_tree(H, data)
        return MerkleTree(H, tree, data)


if __name__ == "__main__":

    def int2bytes(n):
        return n.to_bytes((n.bit_length() + 7) // 8, "big")

    data = [int2bytes(i) for i in [1, 2, 3, 4, 5]]
    mkt = MerkleTree.from_data(sha256, data)
    mkt2 = MerkleTree(sha256, mkt.tree)
    for i, x in enumerate(data):
        assert mkt2.check_present(i, x)
