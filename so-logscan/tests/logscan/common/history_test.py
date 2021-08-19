import os

from unittest.mock import patch

from logscan import HISTORY_LOG
from logscan.common import history


def test_get_history_line_count():
    expected_num_lines = 10
    
    with open(HISTORY_LOG, 'w+') as history_log:
        [ history_log.write(f'{index}\n') for index in range(expected_num_lines) ]
        
        # history_log.truncate(0)
    
    num_lines = history.get_history_line_count()
        
    assert num_lines == expected_num_lines

    if os.path.exists(HISTORY_LOG):
        os.remove(HISTORY_LOG)


def test_drop_old_history():
    write_line_num = 20
    delete_line_num = 10

    with open(HISTORY_LOG, 'w+') as history_log:
        [ history_log.write(f'{index}\n') for index in range(write_line_num) ]

    history.drop_old_history(10)

    num_lines = history.get_history_line_count()

    assert num_lines == ( write_line_num - delete_line_num )

    if os.path.exists(HISTORY_LOG):
        os.remove(HISTORY_LOG)
