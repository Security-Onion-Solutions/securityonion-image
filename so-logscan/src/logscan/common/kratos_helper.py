import datetime as dt
import numpy as np
import json
import time
from itertools import groupby

from typing import Dict, List

from logscan import KRATOS_SUCCESS_STR


def filter_kratos_log(all_log_lines: List) -> List:
    log_lines = [json.loads(line) for line in all_log_lines if "self-service/login" in line]

    return list(filter(lambda x: x.get("audience") == "audit", log_lines))


def __create_sparse_entry(log_line: Dict):
    return [
        dt.datetime.strptime(log_line["time"], "%Y-%m-%dT%H:%M:%SZ").timestamp(),
        1 if KRATOS_SUCCESS_STR in log_line['msg'] else 0,
        log_line["http_request"]["headers"]["x-forwarded-for"].split(',')[-1]
    ]


def sparse_data(filtered_log: List, ip_sort: bool=True) -> List:
    sparse_data = list(map(lambda x: __create_sparse_entry(x), filtered_log))
    sparse_data.sort()
    if ip_sort:
        sparse_data.sort(key=lambda x: x[2])
    return sparse_data


def group_attempts_by_ip(sparse_data: List) -> List[List]:
    return [list(ip_group) for _, ip_group in groupby(sparse_data, lambda x: x[2])]


def split_attempts_seconds(attempt_list: List, seconds: int) -> List[List]:
    attempt_list.sort()
    split_data = []
    sd_counter = 0
    time_split_group = []
    group_start_time = int(attempt_list[0][0])
    for attempt in attempt_list:
        if dt.datetime.fromtimestamp(int(attempt[0])) < (dt.datetime.fromtimestamp(group_start_time) + dt.timedelta(seconds=seconds)):
            time_split_group.append(attempt)
        else:
            split_data.append(time_split_group)
            sd_counter += 1
            time_split_group = [attempt]
            group_start_time = int(attempt[0])
    split_data.append(time_split_group)

    return split_data
