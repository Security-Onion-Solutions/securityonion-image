# Security Onion ML Log Scanning

### This repo contains code for using previously saved models to predict on kratos log files

---
## Getting Started

1. Create venv and activate it:
```sh
# For example
python3 -m venv ./venv
source ./venv/bin/activate
```

2. Install required packages:
```sh
pip install -r requirements.txt
```

3. Copy `logscan.conf.example` to `logscan.conf` and edit as necessary
```sh
cp logscan.conf.example logscan.conf
```

4. Run the project one of two ways:
```sh
pip3 install . # from within this directory (so-logscan)
so-logscan '<model_module>'
# or
python3 logscan/run.py '<model_module>'
```
