from flask import Flask, request, jsonify, make_response
from werkzeug.exceptions import HTTPException
from flask.json.provider import JSONProvider
from apscheduler.schedulers.background import BackgroundScheduler
import atexit, logging, base64, json, msgpack
from stage import Stage, Phase


class RandomnessBeacon:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.stages: list[Stage] = [Stage()]
        self.interval_seconds = 5

    @property
    def current_stage(self):
        return self.stages[-1]

    @property
    def current_stage_index(self):
        return len(self.stages) - 1

    def get_stage(self, stage_idx: int):
        if not (0 <= stage_idx <= self.current_stage_index):
            raise ValueError("invalid stage")
        return self.stages[stage_idx]

    def get_stage_after_phase(self, stage_idx: int, phase: Phase):
        stage = self.get_stage(stage_idx)
        if stage.phase < phase:
            raise ValueError("not in correct phase")
        return stage

    def contribute(self, x: bytes):
        self.logger.debug(
            f"Contribution received",
            extra={"x": x.hex(), "stage": self.current_stage_index},
        )
        data_idx = self.current_stage.contribute(x)
        stage_idx = self.current_stage_index
        return stage_idx, data_idx

    def next_stage(self):
        self.logger.info(
            f"Starting next stage", extra={"stage": self.current_stage_index + 1}
        )
        self.current_stage.stop_contribution()
        self.stages.append(Stage())

    def register_scheduler(self):
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=self.next_stage, trigger="interval", seconds=self.interval_seconds
        )
        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())
        self.scheduler = scheduler


def msgpackify(obj):
    resp = make_response(msgpack.packb(obj))
    resp.headers["Content-Type"] = "application/msgpack"
    return resp


app = Flask(__name__)
app.logger.setLevel(logging.INFO)


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps(
        {
            "code": e.code,
            "name": e.name,
            "description": e.description,
        }
    )
    response.content_type = "application/json"
    return response


beacon = RandomnessBeacon(app.logger)
beacon.register_scheduler()


@app.get("/api/info")
def info():
    return jsonify(
        {
            "stage": beacon.current_stage_index,
            "phase": beacon.current_stage.phase.name,
            "contributions": len(beacon.current_stage.data),
        }
    )


@app.post("/api/contribute")
def contribute():
    try:
        x = base64.b64decode(request.json["randomness"])
    except:
        return (
            jsonify(
                {"error": "no randomness provided or randomness isn't base64 encoded"}
            ),
            400,
        )
    stage_idx, data_idx = beacon.contribute(x)
    return jsonify({"stage": stage_idx, "data_index": data_idx})


@app.get("/api/stage/<int:stage_idx>")
def stage(stage_idx):
    stage = beacon.get_stage(stage_idx)
    return jsonify(
        {
            "stage": stage_idx,
            "phase": stage.phase.name,
            "contributions": len(stage.data),
        }
    )


@app.get("/api/stage/<int:stage_idx>/accval")
def accval(stage_idx):
    stage = beacon.get_stage_after_phase(stage_idx, Phase.EVALUATION)
    return msgpackify(stage.get_acc_val())


@app.get("/api/stage/<int:stage_idx>/accproof/<int:data_idx>")
def accproof(stage_idx, data_idx):
    stage = beacon.get_stage_after_phase(stage_idx, Phase.EVALUATION)
    return msgpackify(stage.get_acc_proof(data_idx))


@app.get("/api/stage/<int:stage_idx>/vdfproof")
def vdfproof(stage_idx):
    stage = beacon.get_stage_after_phase(stage_idx, Phase.DONE)
    return msgpackify(stage.get_vdf_proof())


@app.get("/api/stage/<int:stage_idx>/randomness")
def randomness(stage_idx):
    stage = beacon.get_stage_after_phase(stage_idx, Phase.DONE)
    return msgpackify(stage.get_final_randomness())
