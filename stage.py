from merkle_tree import MerkleHash, MerkleTreeAccumulator
from abstract import AbstractVDF
from chia_vdf import SerializableChiaVDF
from hashlib import sha256
from enum import Enum
from threading import Thread, Lock
import sys, os, random

# This implements https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf special case L=1


class Phase(Enum):
    CONTRIBUTION = 1
    EVALUATION = 2
    DONE = 3

    def __lt__(self, other):
        return self.value < other.value


class Parameters:
    accumulator = MerkleTreeAccumulator(MerkleHash(sha256))
    T = 2**16
    bits = 256
    vdf = SerializableChiaVDF(bits, T)


class VDFComputation:
    def __init__(self, vdf: AbstractVDF, challenge: bytes):
        self.vdf = vdf
        self.challenge = challenge
        self.done = False
        self.thread = Thread(target=self.run)
        self.thread.start()

    def run(self, callback=None):
        self.proof = self.vdf.eval_and_prove(self.challenge)
        self.done = True
        if callback:
            callback()

    def get(self):
        if not self.done:
            raise ValueError("not done yet")
        return self.proof


class Stage:
    def __init__(self):
        self.data: list[bytes] = [b"DUMMY VALUE"]  # to prevent some errors
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
        self.acc = Parameters.accumulator.accumulate(self.data)
        self.vdf = VDFComputation(
            Parameters.vdf, Parameters.accumulator.get_bytes(self.get_acc_val())
        )
        self.vdf.run(callback=self.vdf_callback)

    def vdf_callback(self):
        self.phase = Phase.DONE

    def get_acc_val(self):
        if self.phase < Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return Parameters.accumulator.get_accval(self.acc)

    def get_acc_proof(self, data_index: int):
        if self.phase < Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return Parameters.accumulator.witgen(self.acc, self.data, data_index)

    def get_vdf_proof(self):
        if self.phase < Phase.DONE:
            raise ValueError("not in done phase")
        return self.vdf.get()

    def get_final_randomness(self):
        proof = self.get_vdf_proof()
        return self.hash_y_to_randomness(Parameters.vdf.extract_y(proof))

    @staticmethod
    def hash_y_to_randomness(y: bytes):
        return sha256(y).digest()
