# Security Onion ML Log Scanning - `logscan`

`logscan` is a tool to detect anomalies in log files using pre-trained models. Currently the available models are built to only scan kratos logs, however this will likely expand in future iterations.

## Setting up Dev Environment

1. Create venv and activate it:
```sh
# For example
python3 -m venv ./venv
source ./venv/bin/activate
```

2. Install app:
```sh
pip3 install -e .[dev] # will need to escape [dev] as \[dev\] in zsh
```

3. Run tests:
```sh
pytest # config pytest using pytest.ini
```

4. Copy `logscan.conf.example` to `logscan.conf` and edit as necessary
```sh
cp logscan.conf.example logscan.conf
```

5. Run the project one of two ways:
```sh
so-logscan
# or
docker compose up --build "so-logscan"
```

## Running in Production
  This app is meant to be run in a Docker container using the image built from the included Dockerfile. Running the app using a local Python  environment is only suggested for development as the app uses the project directory to search for logs, data storage, and output.
