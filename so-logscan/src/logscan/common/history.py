import json
from typing import Dict

from .. import HISTORY_LOG


def get_history_line_count() -> int:
    with open(HISTORY_LOG, 'a+') as history_log:
        return len(history_log.readlines())


def drop_old_history(start_line: int):
    with open(HISTORY_LOG, 'a+') as history_log:
        history = history_log.readlines()
        history_log.truncate(0)
        history_log.writelines(f'{line}\n' for line in history[start_line:])


def check_write_history(metadata: Dict) -> bool:
    with open(HISTORY_LOG, 'a+') as history_log:
        history_log.seek(0)
        if any([json.loads(line) == metadata for line in history_log.readlines()]):
            return True
        history_log.write(f'{json.dumps(metadata)}\n')
    return False
        
