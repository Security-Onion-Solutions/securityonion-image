# Security Onion ML Log Scanning

### This repo contains code for using previously saved models to predict on kratos log files

---
## Getting Started

1. Create venv and activate it:
```sh
python3 -m venv ./venv
source ./venv/bin/activate
```
2. Install required packages:
```sh
pip install -r requirements.txt
```
3.  Run the project one of two ways:
```sh
pip3 install so-logscan # or pip3 install . if inside repo
so-logscan '<model_module>'
# or
python3 logscan/run.py '<model_module>'
```
