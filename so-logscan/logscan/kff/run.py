import json
import pathlib
import os
from typing import Dict, List

import numpy as np

from . import transform
from . import predict
from ..common import kratos_helper, check_file
from ..settings import OUTPUT_FILE, CONFIG, LOG_BASE_DIR
from .settings import MODEL_FILENAME, TIME_SPLIT_SEC, MODEL_FILENAME

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
from tensorflow import keras


def __write_alert(py_dict, outfile):
    with open(outfile, 'a') as outfile:
        outfile.write(f'{json.dumps(py_dict)}\n')

def run():
    kratos_log = f'{LOG_BASE_DIR}/{CONFIG.get("kratos", "log_path")}'
    check_file(kratos_log)
    filtered_log = kratos_helper.filter_kratos_log(kratos_log)
    sparse_data = kratos_helper.sparse_data(filtered_log)
    grouped_attempts = kratos_helper.group_attempts_by_ip(sparse_data)
    time_split_attempts = [kratos_helper.split_attempts_seconds(attempt_list, TIME_SPLIT_SEC) for attempt_list in grouped_attempts]

    dataset = []
    for ip_group in time_split_attempts:
        dataset += [transform.timesplit_to_d_md(time_group) for time_group in ip_group]
    
    print('Begining ML predictions')
    alert_list = list(filter(lambda x: x is not None, [predict.alert_on_anomaly(data, metadata) for data, metadata in dataset]))
    alert_list.sort(key=lambda x: x.get('timestamp'))
    print('Finished ML predictions')

    print('Writing to log')
    for alert in alert_list:
        __write_alert(alert, OUTPUT_FILE)
    print('Done writing')

if __name__ == '__main__':
    run()
