from typing import Dict, List, Tuple
import numpy as np
import datetime as dt

from ..common import format_datetime

def timesplit_to_d_md(time_group: list) -> Tuple[List, Dict]:
    arr = np.asarray(time_group)[:, 1].astype(int)
    time_arr = np.asarray(time_group)
    time_arr = (time_arr[time_arr[:,1].astype(int) == 0])[:, 0].astype(float).astype(int)
    interval_arr = np.absolute(time_arr[1:]-time_arr[:-1])

    return [
        float(f'{sum(arr) / len(arr):0.3f}'),  # ratio
        len(arr) - sum(arr),  # num fails
        float(f'{np.mean(interval_arr):0.3f}'), # average interval
        float(f'{np.std(interval_arr):0.3f}') # standard deviation of average interval
    ], \
    {
        'model': 'kl',
        'source_ip': time_group[0][2],
        'start_time': format_datetime(dt.datetime.fromtimestamp(time_group[0][0])),
        'end_time': format_datetime(dt.datetime.fromtimestamp(time_group[-1][0])),
        'num_attempts': int(len(arr)),
        'num_failed': int(len(arr) - sum(arr)),
        'avg_failure_interval': float(f'{np.mean(interval_arr):0.3f}')
    }