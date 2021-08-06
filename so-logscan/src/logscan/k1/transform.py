import numpy as np
import datetime as dt

from typing import Dict, List, Tuple

from logscan.common import kratos_helper, format_datetime
from logscan.k1 import LOGGER, TIME_SPLIT_SEC


def build_dataset(log: List) -> List:
    LOGGER.debug(f'Filtering kratos log')
    filtered_log = kratos_helper.filter_kratos_log(log)
    if len(filtered_log) == 0:
        return []

    LOGGER.debug(f'Transforming filtered log to attempts/ip/{TIME_SPLIT_SEC}s')
    sparse_data = kratos_helper.sparse_data(filtered_log)
    grouped_attempts = kratos_helper.group_attempts_by_ip(sparse_data)
    time_split_attempts = [kratos_helper.split_attempts_seconds(attempt_list, TIME_SPLIT_SEC) for attempt_list in grouped_attempts]

    LOGGER.debug(f'Building dataset from attempts/ip/{TIME_SPLIT_SEC}s')
    dataset = []
    for ip_group in time_split_attempts:
        dataset += [__timesplit_to_d_md(time_group) for time_group in ip_group]

    return dataset


def __timesplit_to_d_md(time_group: list) -> Tuple[List, Dict]:
    arr = np.asarray(time_group)[:, 1].astype(int)
    return [
        float(f'{sum(arr) / len(arr):0.3f}'),  # percent success
        len(arr)  # num attemps
    ], \
    {
        'model': 'k1',
        'source_ip': time_group[0][2],
        'start_time': format_datetime(dt.datetime.fromtimestamp(time_group[0][0])),
        'end_time': format_datetime(dt.datetime.fromtimestamp(time_group[-1][0])),
        'num_attempts': int(len(arr)),
        'num_failed': int(len(arr) - sum(arr))
    }
