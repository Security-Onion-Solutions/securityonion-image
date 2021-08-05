import datetime as dt
import pathlib

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
