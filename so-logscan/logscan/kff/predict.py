import os
import json
import pathlib
from typing import Dict, List
import numpy as np
import datetime as dt

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
from tensorflow import keras

from .settings import PREDICTION_THRESHOLD, MODEL_FILENAME
from ..common import format_datetime


def __predict(model, dataset_entry):
    X = np.vstack(dataset_entry)
    Y = model(X)

    return Y


def alert_on_anomaly(data: List, metadata: Dict) -> Dict:
    here = pathlib.Path(__file__).parent
    model = keras.models.load_model(f'{here}/{MODEL_FILENAME}')
    y = __predict(model, [data])
    if y >= PREDICTION_THRESHOLD:
        return {
            'timestamp': format_datetime(dt.datetime.utcnow()),
            'source_ip': metadata.get('ip'),
            'start_time': metadata.get('start_time'),
            'end_time': metadata.get('end_time'),
            'num_attempts': metadata.get('num_attempts'),
            'num_failed': int(data[1])
        }
