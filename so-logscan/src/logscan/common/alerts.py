import datetime as dt
import numpy as np
import json
import threading

from tensorflow import keras

from typing import Dict, List

from logscan.common.history import check_write_history
from . import format_datetime


def __predict(model: keras.Model, dataset_entry: List):
    x = np.vstack(dataset_entry)
    y = model.predict(x)

    return y


def __gen_alert(data: List, metadata: Dict, model: keras.Model, prediction_threshold: float) -> Dict:
    y = __predict(model, [data])
    if y >= prediction_threshold:
        alert = metadata
        alert['timestamp'] = format_datetime(dt.datetime.utcnow())
        alert['confidence'] = f'{y[0][0] * 100:0.3f}%'
        return alert


def gen_alert_list(dataset: List, model: keras.Model, prediction_threshold: float, exit_event: threading.Event):
    '''
    Generate a list of alerts from a dataset, given a model and prediction threshold

    dataset (List): dataset to predict on
    model (keras.Model): model used for prediction
    prediction_threshold (float): confidence threshold to call prediction an alert
    exit_event (threading.Event): event to watch to stop generating alerts early
    '''
    alert_list = []
    exit_early = False

    for data, metadata in dataset:
        if not exit_event.is_set():
            if check_write_history(metadata): 
                continue
            alert = __gen_alert(data, metadata, model, prediction_threshold)
            if alert is not None:
                alert_list.append(alert)
        else:
            exit_early = True
            break
    
    alert_list.sort(key=lambda x: x.get('timestamp'))

    return alert_list, exit_early


def write_alerts(alert_list, alert_log):
    for alert in alert_list:
        with open(alert_log, 'a') as outfile:
            outfile.write(f'{json.dumps(alert)}\n')
