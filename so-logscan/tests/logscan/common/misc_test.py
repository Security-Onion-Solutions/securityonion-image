import pathlib
import pytest

import datetime as dt

from unittest.mock import patch

from logscan.common.misc import check_file, format_datetime
from logscan import CONFIG


def test_format_datetime_unix():
    with patch.object(CONFIG, 'get', return_value='unix') as _:
        date_obj = dt.datetime(2000, 1, 1, 0, 0, 0, 0, dt.timezone.utc)
        expected_time_str = '946684800'
        
        time_str = format_datetime(date_obj)

        assert time_str == expected_time_str


def test_check_file():
    with pytest.raises(FileNotFoundError):
        check_file((pathlib.Path(__file__).parent).joinpath('not_exist.none'))

