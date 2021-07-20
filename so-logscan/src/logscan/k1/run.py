import json
import pathlib
import os
import sys
import threading
from typing import Dict, List
import time

import numpy as np
from tensorflow import keras

from . import MODEL_FILENAME, transform
from . import predict
from ..common import kratos_helper, check_file
from .. import ALERT_LOG, HISTORY_LOG, CONFIG
from . import TIME_SPLIT_SEC, LOGGER

def __write_alert(py_dict, outfile):
    with open(outfile, 'a') as outfile:
        outfile.write(f'{json.dumps(py_dict)}\n')


def run(event: threading.Event, log: List, clear_history: bool):
    tic = time.perf_counter()

    here = pathlib.Path(__file__).parent
    model = keras.models.load_model(f'{here}/{MODEL_FILENAME}')
    
    LOGGER.debug(f'Filtering kratos log')
    filtered_log = kratos_helper.filter_kratos_log(log)

    LOGGER.debug(f'Transforming filtered log to attempts/ip/{TIME_SPLIT_SEC}s')
    sparse_data = kratos_helper.sparse_data(filtered_log)
    grouped_attempts = kratos_helper.group_attempts_by_ip(sparse_data)
    time_split_attempts = [kratos_helper.split_attempts_seconds(attempt_list, TIME_SPLIT_SEC) for attempt_list in grouped_attempts]

    LOGGER.debug(f'Building dataset from attempts/ip/{TIME_SPLIT_SEC}s')
    dataset = []
    for ip_group in time_split_attempts:
        dataset += [transform.timesplit_to_d_md(time_group) for time_group in ip_group]
    
    alert_list = []

    with open(HISTORY_LOG, 'a+') as history_file:
        history_file.seek(0)
        num_initial_history_lines = len(history_file.readlines())

    LOGGER.debug('Generating alerts')
    for data, metadata in dataset:
        if not event.is_set(): # rename variable for clarity
            # TODO: move this to another package (history, common, whatever)
            with open(HISTORY_LOG, 'a+') as history_file:
                history_file.seek(0)
                if any([json.loads(line) == metadata for line in history_file.readlines()]):
                    continue
                history_file.write(f'{json.dumps(metadata)}\n')
            alert = predict.alert_on_anomaly(data, metadata, model)
            if alert is not None:
                alert_list.append(alert)
        else:
            LOGGER.debug(f'[THREAD_ID:{threading.get_native_id()}] Quit generating alerts early')
            break

    if clear_history:
        with open(HISTORY_LOG, 'a+') as history_file:
            history_lines = history_file.readlines()
            history_file.truncate(0)
            history_file.writelines("%s\n" % line for line in history_lines[num_initial_history_lines:])

    # TODO: prune_history() rolling queue, remove first x lines after line no. limit

    alert_list.sort(key=lambda x: x.get('timestamp'))
    LOGGER.info(f'Generated {len(alert_list)} new alerts from k1 model')

    if len(alert_list) > 0:
        LOGGER.debug(f'Writing to {ALERT_LOG}')
        for alert in alert_list:
            __write_alert(alert, ALERT_LOG)
        LOGGER.debug(f'Finished writing {len(alert_list)} lines')

    toc = time.perf_counter()
    LOGGER.debug(f'[PERFORMANCE] Module completed in {round(toc - tic, 2)} seconds')


if __name__ == '__main__':
    run()
