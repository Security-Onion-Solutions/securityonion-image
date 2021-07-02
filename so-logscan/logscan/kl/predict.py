import os
import json
import pathlib
from typing import Dict, List
from . import LOGGER
import numpy as np
import datetime as dt

from tensorflow import keras

from . import PREDICTION_THRESHOLD
from ..common import format_datetime


def __predict(model, dataset_entry):
    X = np.vstack(dataset_entry)
    Y = model(X)

    return Y


def alert_on_anomaly(data: List, metadata: Dict, model) -> Dict:
    y = __predict(model, [data])
    if y >= PREDICTION_THRESHOLD:
        return {
            'timestamp': format_datetime(dt.datetime.utcnow()),
            'model': metadata.get('model'),
            'source_ip': metadata.get('source_ip'),
            'start_time': metadata.get('start_time'),
            'end_time': metadata.get('end_time'),
            'num_attempts': metadata.get('num_attempts'),
            'num_failed': metadata.get('num_failed'),
            'avg_failure_interval': metadata.get('avg_failure_interval')
        }
