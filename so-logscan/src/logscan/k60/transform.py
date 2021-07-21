from typing import Dict, List, Tuple
import numpy as np
import datetime as dt

from logscan.common import kratos_helper,format_datetime

from logscan.k60 import LOGGER, TIME_SPLIT_SEC


def build_dataset(log: List) -> List:
    LOGGER.debug(f'Filtering kratos log')
    filtered_log = kratos_helper.filter_kratos_log(log)

    LOGGER.debug(f'Transforming filtered log to attempts/{TIME_SPLIT_SEC}s')
    sparse_data = kratos_helper.sparse_data(filtered_log)
    time_split_attempts = kratos_helper.split_attempts_seconds(sparse_data, TIME_SPLIT_SEC)
    checked_data = __check_split_attempts(time_split_attempts)

    LOGGER.debug(f'Building dataset from attempts/{TIME_SPLIT_SEC}s')
    dataset = [__timesplit_to_d_md(time_group) for time_group in checked_data]

    return dataset


def __check_split_attempts(split_data: List) -> List[List]:
    checked_data = []
    for time_split_group in split_data:
        arr = np.asarray(time_split_group)[:, 1].astype(int)
        if len(arr) - sum(arr) >= 3:
            checked_data += [time_split_group]

    return checked_data


def __get_ip_list(time_group: list) -> List:
    all_ips = np.asarray(time_group)[:, 2].tolist()
    ip_dict = {}
    for ip in all_ips:
        if ip not in ip_dict:
            ip_dict[ip] = 1
        else:
            ip_dict[ip] += 1
    sorted_ip_dict = {k: v for k, v in sorted(ip_dict.items(), key = lambda item: item[1])}
    ip_list = list(sorted_ip_dict)
    
    return ip_list[:5]


def __timesplit_to_d_md(time_group: list) -> Tuple[List, Dict]:
    arr = np.asarray(time_group)[:, 1].astype(int)
    time_arr = np.asarray(time_group)
    time_arr = (time_arr[time_arr[:,1].astype(int) == 0])[:, 0].astype(float).astype(int)
    interval_arr = np.absolute(time_arr[1:]-time_arr[:-1])

    return [
        float(f'{sum(arr) / len(arr):0.3f}'),  # percent success
        len(arr) - sum(arr),  # num fails
        float(f'{np.mean(interval_arr):0.3f}'),  # average interval
        float(f'{np.std(interval_arr):0.3f}')  # standard deviation of average interval
    ], \
    {
        'model': 'k60',
        'top_source_ips': __get_ip_list(time_group),
        'start_time': format_datetime(dt.datetime.fromtimestamp(time_group[0][0])),
        'end_time': format_datetime(dt.datetime.fromtimestamp(time_group[-1][0])),
        'num_attempts': int(len(arr)),
        'num_failed': int(len(arr) - sum(arr)),
        'avg_failure_interval': f'{np.mean(interval_arr):0.0f}s'
    }
