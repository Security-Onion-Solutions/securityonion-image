import json
import pathlib
import os
import sys
import threading
from typing import Dict, List

import numpy as np

from . import transform
from . import predict
from ..common import kratos_helper, check_file
from .. import ALERT_LOG, HISTORY_LOG, CONFIG, LOG_BASE_DIR
from . import TIME_SPLIT_SEC, LOGGER


def __write_alert(py_dict, outfile):
    with open(outfile, 'a') as outfile:
        outfile.write(f'{json.dumps(py_dict)}\n')

def run(event: threading.Event):
    kratos_log = f'{LOG_BASE_DIR}/{CONFIG.get("kratos", "log_path")}'
    try:
        check_file(kratos_log)
    except FileNotFoundError as e:
        LOGGER.error(e)
        sys.exit(1)

    LOGGER.debug(f'Reading and filtering kratos log')
    filtered_log = kratos_helper.filter_kratos_log(kratos_log)

    LOGGER.debug(f'Transforming filtered log to attempts/{TIME_SPLIT_SEC}s')
    sparse_data = kratos_helper.sparse_data(filtered_log)
    time_split_attempts = kratos_helper.split_attempts_seconds(sparse_data, TIME_SPLIT_SEC)

    LOGGER.debug(f'Building dataset from attempts/{TIME_SPLIT_SEC}s')
    dataset = []
    dataset += [transform.timesplit_to_d_md(time_group) for time_group in time_split_attempts]
    
    alert_list = []

    LOGGER.debug('Generating alerts')
    for data, metadata in dataset:
        if not event.is_set():
            with open(HISTORY_LOG, 'a+') as f:
                f.seek(0)
                if any([json.loads(line) == metadata for line in f.readlines()]):
                    continue
                f.write(f'{json.dumps(metadata)}\n')
            alert = predict.alert_on_anomaly(data, metadata)
            if alert is not None:
                LOGGER.debug(alert)
                alert_list.append(alert)
        else:
            LOGGER.debug(f'[THREAD_ID:{threading.get_native_id()}] Quit generating alerts early')
            break
    alert_list.sort(key=lambda x: x.get('timestamp'))
    LOGGER.info(f'Generated {len(alert_list)} new alerts from kl model')

    if len(alert_list) > 0:
        LOGGER.debug(f'Writing to {ALERT_LOG}')
        for alert in alert_list:
            __write_alert(alert, ALERT_LOG)
        LOGGER.debug(f'Finished writing {len(alert_list)} lines')

if __name__ == '__main__':
    run()
