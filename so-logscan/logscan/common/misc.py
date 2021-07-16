import datetime as dt
import pathlib

import json

from logscan import CONFIG

def format_datetime(date_time: dt.datetime) -> str:
    ts_format = CONFIG.get('global', 'ts_format')

    if ts_format == 'unix':
        return str(int(f'{date_time.timestamp():0.0f}'))
    else:
        return date_time.isoformat()


def check_file(filepath: str):
    if not pathlib.Path(filepath).is_file():
        raise FileNotFoundError(f'Log file {filepath} does not exist')


def filter_file(filtered_log: str, kratos_log: str):
    with open(filtered_log, 'a+') as f:
        f.seek(0)
        check_file(kratos_log)
        with open(kratos_log, 'r') as k:
            log_lines = [json.loads(line) for line in k.readlines() if "self-service/login" in line]
            new_filtered_list = list(filter(lambda x: x.get("audience") == "audit", log_lines))

        if len(new_filtered_list) >= len(f.readlines()):
            f.truncate(0)

        for line in new_filtered_list:
            f.write(f'{json.dumps(line)}\n')