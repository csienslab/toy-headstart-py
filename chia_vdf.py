from chiavdf import create_discriminant, prove, verify_wesolowski
from dataclasses import dataclass
from abstract import AbstractVDF
import msgpack


@dataclass
class ChiaProof:
    discriminant_str: str
    result_y: bytes
    proof: bytes


class ChiaVDF(AbstractVDF):
    def __init__(self, bits: int, T: int):
        self.bits = bits
        self.T = T
        self.form_size = 100
        self.g = initial_el = b"\x08" + (b"\x00" * 99)

    def prove(self, challenge: bytes) -> ChiaProof:
        discriminant_str = create_discriminant(challenge, self.bits)
        blob = prove(challenge, self.g, self.bits, self.T)
        result_y = blob[: self.form_size]
        proof = blob[self.form_size :]
        return ChiaProof(discriminant_str, result_y, proof)

    def verify(self, challenge: bytes, proof: ChiaProof) -> bool:
        return verify_wesolowski(
            proof.discriminant_str,
            self.g,
            proof.result_y,
            proof.proof,
            self.T,
        )

    def extract_y(self, proof: ChiaProof) -> bytes:
        return proof.result_y


class SerializableChiaVDF(ChiaVDF):
    def prove(self, challenge: bytes) -> bytes:
        proof = super().prove(challenge)
        return msgpack.packb((proof.discriminant_str, proof.result_y, proof.proof))

    def verify(self, challenge: bytes, proof: bytes) -> bool:
        d, y, pi = msgpack.unpackb(proof)
        return super().verify(challenge, ChiaProof(d, y, pi))

    def extract_y(self, proof: bytes) -> bytes:
        d, y, pi = msgpack.unpackb(proof)
        return y


if __name__ == "__main__":
    for cls in [ChiaVDF, SerializableChiaVDF]:
        vdf = cls(256, 1 << 10)
        challenge = b"peko"
        proof = vdf.prove(challenge)
        print(proof)
        print(vdf.verify(challenge, proof))
        print(vdf.extract_y(proof))
