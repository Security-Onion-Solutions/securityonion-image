from src.logscan.k1 import transform
from tests.logscan.helper import build_dataset, check_dataset, get_log_lines


def test_build_dataset():
    log_lines = get_log_lines('k1_k5_dataset_testing.log')

    expected_dataset = [
        ([0.0, 1], {'model': 'k1', 'source_ip': '192.168.11.196', 'start_time': '2011-07-05T09:06:33', 'end_time': '2011-07-05T09:06:33', 'num_attempts': 1, 'num_failed': 1}),
        ([0.5, 2], {'model': 'k1', 'source_ip': '192.168.12.223', 'start_time': '2011-07-05T09:05:52', 'end_time': '2011-07-05T09:06:07', 'num_attempts': 2, 'num_failed': 1}),
        ([0.0, 1], {'model': 'k1', 'source_ip': '192.168.12.224', 'start_time': '2011-07-05T09:06:28', 'end_time': '2011-07-05T09:06:28', 'num_attempts': 1, 'num_failed': 1}),
    ]
    
    dataset = build_dataset('k1', log_lines)
    
    assert check_dataset(expected_dataset, dataset) == True


def test_timesplit_to_d_md():
    time_group = [ [1309871152.0, 1, '192.168.12.223'], [1309871167.0, 0, '192.168.12.223'] ]

    expected_d_md = ([0.5, 2], {'model': 'k1', 'source_ip': '192.168.12.223', 'start_time': '2011-07-05T09:05:52', 'end_time': '2011-07-05T09:06:07', 'num_attempts': 2, 'num_failed': 1})

    d_md = transform.__timesplit_to_d_md(time_group)

    assert d_md == expected_d_md
