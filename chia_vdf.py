from chiavdf import create_discriminant, prove, verify_wesolowski
from dataclasses import dataclass
from abstract import AbstractVDF


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


if __name__ == "__main__":
    vdf = ChiaVDF(256, 1 << 10)
    challenge = b"peko"
    proof = vdf.prove(challenge)
    print(proof)
    print(vdf.verify(challenge, proof))
