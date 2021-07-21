import os
from unittest.mock import patch
from tests.logscan.helper import build_dataset, check_dataset, get_log_lines

def test_build_dataset():
    log_lines = get_log_lines('dataset_testing.log')

    expected_dataset = [
        ([0.25, 3, 13.0, 8.0], {'model': 'k60', 'top_source_ips': ['192.168.12.224', '192.168.11.196', '192.168.12.223'], 'start_time': '2011-07-05T09:05:52', 'end_time': '2011-07-05T09:06:33', 'num_attempts': 4, 'num_failed': 3, 'avg_failure_interval': '13s'}),
    ]
    
    dataset = build_dataset('k60', log_lines)
    
    assert check_dataset(expected_dataset, dataset) == True
