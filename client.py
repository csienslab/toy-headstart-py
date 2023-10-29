from stage import Parameters, Phase, Stage
from dataclasses import dataclass
import httpx, base64, msgpack, time


@dataclass
class Contribution:
    value: bytes
    stage: int
    data_index: int


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
    def __init__(self, client: httpx.Client):
        self.client = client

    def get_info(self) -> StageInfo:
        return StageInfo(**self.client.get("/api/info").json())

    def contribute(self, randomness: bytes) -> Contribution:
        return Contribution(
            value=randomness,
            **self.client.post(
                "/api/contribute",
                json={"randomness": base64.b64encode(randomness).decode()},
            ).json(),
        )

    def get_stage(self, stage_idx: int) -> StageInfo:
        return StageInfo(**self.client.get(f"/api/stage/{stage_idx}").json())

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

    def __vdfproof(self, contribution: Contribution) -> bytes:
        return msgpack.unpackb(
            self.client.get(f"/api/stage/{contribution.stage}/vdfproof").content
        )

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
        vdfproof = self.__vdfproof(contribution)
        v1 = Parameters.accumulator.verify(val, accproof, contribution.value)
        v2 = Parameters.vdf.verify(val, vdfproof)
        if v1 and v2:
            randomness = self.__randomness(contribution.stage)
            computed_randomness = Stage.hash_y_to_randomness(
                Parameters.vdf.extract_y(vdfproof)
            )
            if randomness == computed_randomness:
                return randomness
            else:
                raise ValueError(
                    "vdf verification succeeded, but randomness doesn't match"
                )
        else:
            raise ValueError("vdf verification failed")


if __name__ == "__main__":
    client = HeadStartClient(httpx.Client(base_url="http://localhost:5000"))
    print(client.get_info())
    print(ct1 := client.contribute(b"peko"))
    print(ct2 := client.contribute(b"miko"))
    print(client.get_verified_randomness(ct1))
    print(client.get_verified_randomness(ct2))
    print(client.get_stage(ct1.stage))
