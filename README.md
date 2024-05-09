# Toy implementation of [HeadStart: Efficiently Verifiable and Low-Latency Participatory Randomness Generation at Scale](https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf)

## Installation

```bash
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

## Run Server

```bash
./run_server.sh  # default port 5000, edit run_server.sh to change
```

## Test client

```bash
python -m headstart.client
# see headstart/client.py for example usage
```
