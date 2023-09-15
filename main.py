from merkle_tree import MerkleTree
from vdf import H_D, H_QF, qf_tobytes, qf_frombytes, vdf_eval, vdf_verify
from hashlib import sha256
from enum import Enum
from threading import Thread
from subprocess import check_output
import sys, os, random, vdf

# This implements https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf special case L=1


class Phase(Enum):
    CONTRIBUTION = 1
    EVALUATION = 2


class Parameters:
    T = 2**14
    bits = 256


class VDFComputation:
    def __init__(self, x, T):
        self.x = x
        self.T = T
        self.done = False
        self.thread = Thread(target=self.run)
        self.thread.start()

    def run(self):
        # pari doesn't play nice with threads :(
        out = check_output([sys.executable, vdf.__file__, self.x.hex(), str(self.T)])
        ln = (Parameters.bits // 8 + 1) * 3
        self.y = qf_frombytes(out[:ln], Parameters.bits)
        self.pi = qf_frombytes(out[ln:], Parameters.bits)
        self.done = True

    def get(self):
        if not self.done:
            self.thread.join()
        return self.y, self.pi


class Server:
    def __init__(self):
        self.data: list[bytes] = []
        self.phase = Phase.CONTRIBUTION

    def contribute(self, x: bytes):
        if self.phase != Phase.CONTRIBUTION:
            raise ValueError("not in contribution phase")
        self.data.append(x)
        return len(self.data) - 1  # index of x in the data

    def stop_contribution(self):
        if self.phase != Phase.CONTRIBUTION:
            raise ValueError("not in contribution phase")
        self.phase = Phase.EVALUATION
        self.mkt = MerkleTree.from_data(sha256, self.data)
        self.vdf = VDFComputation(self.mkt.root, Parameters.T)

    def get_tree(self):
        if self.phase != Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return self.mkt.tree

    def get_verifydata(self):
        if self.phase != Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return self.vdf.get()

    def get_randomness(self):
        y, pi = self.get_verifydata()
        return sha256(qf_tobytes(y, Parameters.bits)).digest()


class Client:
    def __init__(self):
        self.id = os.urandom(4).hex()
        self.randomness = os.urandom(Parameters.bits // 8)

    def add_random_to(self, server: Server):
        self.index = server.contribute(self.randomness)

    def verify(self, server: Server):
        mkt = MerkleTree(sha256, server.get_tree())
        if not mkt.check_present(self.index, self.randomness):
            return False
        y, pi = server.get_verifydata()
        d = H_D(mkt.root, Parameters.bits)
        g = H_QF(mkt.root, d, Parameters.bits)
        if not vdf_verify(g, y, pi, Parameters.T):
            return False
        randomness = sha256(qf_tobytes(y, Parameters.bits)).digest()
        if randomness != server.get_randomness():
            return False
        return True


class MaliciousServer1(Server):
    def stop_contribution(self):
        self.data[random.choice(range(len(self.data)))] = os.urandom(
            Parameters.bits // 8
        )
        return super().stop_contribution()


class MaliciousServer2(Server):
    def get_randomness(self):
        return os.urandom(Parameters.bits // 8)


def protocol_test(server_cls, n_clients):
    print("=" * 40)
    print(f"Testing protocol for {server_cls.__name__} with {n_clients} clients")
    server = server_cls()
    clients = [Client() for _ in range(n_clients)]
    for c in clients:
        c.add_random_to(server)
    server.stop_contribution()
    print("Randomness published by server:", server.get_randomness())
    for i, c in enumerate(clients):
        if not c.verify(server):
            print(f"Client {i} failed verification")
            break
    else:
        print("All clients successfully verified the randomness is correct")
    print()


if __name__ == "__main__":
    protocol_test(Server, 10)
    protocol_test(MaliciousServer1, 10)
    protocol_test(MaliciousServer2, 10)
