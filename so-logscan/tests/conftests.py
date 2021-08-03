import os
from unittest import mock
import numpy as np

from tensorflow import keras as _

class MockKerasModel(object):
    def __init__(self, confidence):
        self.predict = mock.Mock(return_value=np.array([np.array([confidence])]))


class MockThread(object):
    def __init__(self, is_alive=False):
        self.native_id = 1000
        self.is_alive = mock.Mock(return_value=is_alive)
        self.join = mock.Mock()
        self.start = mock.Mock()


class MockThreadingEvent(object):
    def __init__(self, is_set=False):
        self.set = mock.Mock()
        self.is_set = mock.Mock(return_value=is_set)
