import os
import tempfile
import json
from tests.conftests import MockKerasModel, MockThreadingEvent

from logscan import HISTORY_LOG
from logscan.common import alerts

prediction_threshold = 0.8


def get_dataset():
    return [
        [ 
            [0.471, 9, 40.25, 30.687],
            {
                "model": "kl",
                "top_source_ips": [
                    "192.168.12.09",
                    "192.168.12.02",
                    "192.168.12.06",
                    "192.168.12.07",
                    "192.168.12.05"
                ],
                "start_time": "2012-01-26T13:19:47",
                "end_time": "2012-01-26T14:14:04",
                "num_attempts": 17,
                "num_failed": 9,
                "avg_failure_interval": "40s"
            }
        ],
        [
            [0.727, 3, 437.5, 424.5],
            {
                "model": "kl",
                "top_source_ips": [
                    "192.168.12.10",
                    "192.168.12.07",
                    "192.168.12.01",
                    "192.168.12.03",
                    "192.168.12.05"
                ],
                "start_time": "2012-01-29T13:08:42",
                "end_time": "2012-01-29T13:45:11",
                "num_attempts": 11,
                "num_failed": 3,
                "avg_failure_interval": "438s"
            }
        ]
    ]


def test_predict():
    dataset = get_dataset()

    confidence_level = 0.85

    test_y = alerts.__predict(MockKerasModel(confidence_level), [dataset[0][0]])

    assert test_y[0][0] == confidence_level


def test_gen_alert():
    dataset = get_dataset()
    data = dataset[0][0]
    metadata = dataset[0][1]
    
    confidence_level = 0.85

    test_alert = alerts.__gen_alert(data, metadata, MockKerasModel(confidence_level), prediction_threshold)

    assert all(item in test_alert.items() for item in metadata.items())

    assert float(test_alert.get('confidence').replace('%', '')) / 100 >= prediction_threshold
        
def test_gen_alert_none():
    dataset = get_dataset()
    data = dataset[1][0]
    metadata = dataset[1][1]

    confidence_level = 0.75

    test_alert = alerts.__gen_alert(data, metadata, MockKerasModel(confidence_level), prediction_threshold)

    assert test_alert == None


def gen_test_alerts(exit_event: MockThreadingEvent):
    dataset = get_dataset()
    confidence_level = 0.85

    test_alert_list, exit_early = alerts.gen_alert_list(dataset, MockKerasModel(confidence_level), prediction_threshold, exit_event)

    return test_alert_list, exit_early


def gen_test_alerts_wrapper(exit_event: MockThreadingEvent, no_new = False):
    dataset = get_dataset()
    alert_list = [ dataset[0][1], dataset[1][1] ]

    test_alert_list, exit_early = gen_test_alerts(exit_event)

    alert_list.sort(key=lambda x: x.get('start_time'))
    test_alert_list.sort(key=lambda x: x.get('start_time'))

    if exit_event.is_set() == True:
        assert exit_early == True
    elif no_new == False:
        assert len(test_alert_list) == len(alert_list)
        for index, alert in enumerate(test_alert_list):
            assert all(item in alert.items() for item in alert_list[index].items())
    else:
        assert len(test_alert_list) == 0

    
def test_gen_alert_list():
    exit_event = MockThreadingEvent()
    gen_test_alerts_wrapper(exit_event)

    if os.path.exists(HISTORY_LOG):
        os.remove(HISTORY_LOG)


def test_gen_alert_history():
    exit_event = MockThreadingEvent()
    gen_test_alerts_wrapper(exit_event)

    # Run function again, should not regenerate alerts
    gen_test_alerts_wrapper(exit_event, True)

    if os.path.exists(HISTORY_LOG):
        os.remove(HISTORY_LOG)


def test_gen_alert_list_exit():
    exit_event = MockThreadingEvent(is_set=True)
    gen_test_alerts_wrapper(exit_event)

    if os.path.exists(HISTORY_LOG):
        os.remove(HISTORY_LOG)


def test_write_alerts():
    dataset = get_dataset()
    alert_list = [ dataset[0][1], dataset[1][1] ]

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_alert_log = f'{temp_dir}/alerts.log'
        alerts.write_alerts(alert_list, temp_alert_log)

        with open(temp_alert_log, 'r') as temp_alert_log_file:
            alert_lines = [json.loads(line) for line in temp_alert_log_file.readlines()]
            assert sum(1 for line in alert_lines) == len(alert_list)
            alert_list.sort(key=lambda x: x.get('model'))
            alert_lines.sort(key=lambda x: x.get('model'))
            for index, line in enumerate(alert_lines):
                assert all(item in line.items() for item in alert_list[index].items())
