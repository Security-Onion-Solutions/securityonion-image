import pathlib
import importlib
from typing import List


def get_log_lines(filename: str):
    with open((pathlib.Path(__file__).parent.parent).joinpath(f'logs/{filename}')) as log:
        return log.readlines()


def build_dataset(model_name: str, log_lines: List) -> List:
    transform = importlib.import_module(f'logscan.{model_name}.transform')
    return transform.build_dataset(log_lines)


def check_dataset(expected: List, actual: List):
    match = True
    expected.sort(key=lambda x: x[1].get('start_time'))
    actual.sort(key=lambda x: x[1].get('start_time'))

    for index, (data, metadata) in enumerate(actual):
        if data != expected[index][0]:
            match = False
        if not all(item in metadata.items() for item in expected[index][1].items()):
            match = False

    return match
