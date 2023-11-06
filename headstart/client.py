from headstart.stage import Parameters, Phase, Stage
from dataclasses import dataclass
import httpx, base64, msgpack, time, headstart.public_key as public_key
from cryptography.hazmat.primitives import serialization


@dataclass
class Contribution:
    value: bytes
    stage: int
    data_index: int
    signature: bytes


@dataclass
class StageInfo:
    stage: int
    phase: Phase
    contributions: int

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        if isinstance(self.phase, str):
            self.phase = Phase[self.phase]


class HeadStartClient:
    @staticmethod
    def from_server_url(url: str) -> "HeadStartClient":
        client = httpx.Client(base_url=url)
        pub_bytes = client.get("/api/pubkey").content
        pub_key = serialization.load_pem_public_key(pub_bytes)
        return HeadStartClient(client, pub_key)

    def __init__(self, client: httpx.Client, pub_key: public_key.Ed25519PublicKey):
        self.client = client
        self.pub_key = pub_key

    def get_info(self) -> StageInfo:
        return StageInfo(**msgpack.unpackb(self.client.get("/api/info").content))

    def contribute(self, randomness: bytes) -> Contribution:
        ct = Contribution(
            value=randomness,
            **msgpack.unpackb(
                self.client.post(
                    "/api/contribute",
                    json={"randomness": base64.b64encode(randomness).decode()},
                ).content
            ),
        )
        if not public_key.verify(self.pub_key, ct.value, ct.signature):
            raise ValueError("invalid signature")
        return ct

    def get_stage(self, stage_idx: int) -> StageInfo:
        return StageInfo(
            **msgpack.unpackb(self.client.get(f"/api/stage/{stage_idx}").content)
        )

    def wait_for_phase(self, stage_idx: int, phase: Phase, polling_interval=1):
        while self.get_stage(stage_idx).phase < phase:
            time.sleep(polling_interval)

    def __accval(self, stage_idx: int) -> bytes:
        return msgpack.unpackb(
            self.client.get(f"/api/stage/{stage_idx}/accval").content
        )

    def __accproof(self, contribution: Contribution):
        return msgpack.unpackb(
            self.client.get(
                f"/api/stage/{contribution.stage}/accproof/{contribution.data_index}"
            ).content
        )

    def __vdfproof(self, stage: int) -> bytes:
        return msgpack.unpackb(self.client.get(f"/api/stage/{stage}/vdfproof").content)

    def __randomness(self, stage_idx: int) -> bytes:
        return msgpack.unpackb(
            self.client.get(f"/api/stage/{stage_idx}/randomness").content
        )

    def get_verified_randomness(
        self, contribution: Contribution, polling_interval=1
    ) -> bytes:
        self.wait_for_phase(contribution.stage, Phase.DONE, polling_interval)
        val = self.__accval(contribution.stage)
        accproof = self.__accproof(contribution)
        vdfproof = self.__vdfproof(contribution.stage)
        v1 = Parameters.accumulator.verify(val, accproof, contribution.value)
        prev_stage_y = (
            Parameters.vdf.extract_y(self.__vdfproof(contribution.stage - 1))
            if contribution.stage >= 1
            else b""
        )
        vdf_challenge = Stage.hash(val + prev_stage_y)
        v2 = Parameters.vdf.verify(vdf_challenge, vdfproof)
        if v1 and v2:
            randomness = self.__randomness(contribution.stage)
            computed_randomness = Stage.hash(Parameters.vdf.extract_y(vdfproof))
            if randomness == computed_randomness:
                return randomness
            else:
                raise ValueError(
                    "vdf verification succeeded, but randomness doesn't match"
                )
        else:
            raise ValueError("vdf verification failed")


if __name__ == "__main__":
    client = HeadStartClient.from_server_url("http://localhost:5000")
    print(client.get_info())
    print(ct1 := client.contribute(b"peko"))
    print(ct2 := client.contribute(b"miko"))
    print(client.get_verified_randomness(ct1))
    print(client.get_verified_randomness(ct2))
    print(client.get_stage(ct1.stage))
