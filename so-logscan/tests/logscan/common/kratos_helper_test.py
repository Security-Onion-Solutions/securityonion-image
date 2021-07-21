
import pathlib
from logscan.common import kratos_helper

from tests.logscan.helper import get_log_lines


def test_filter_kratos_log():
    mock_log_lines = get_log_lines('mock.log')
    
    audit_lines = kratos_helper.filter_kratos_log(mock_log_lines)

    expected_arr = [
        {'audience': 'audit', 'error': {'message': 'I[#/] S[] the provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number'}, 'http_request': {'headers': {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9', 'cache-control': 'max-age=0', 'cookie': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'origin': 'https://rwwiv-standalone', 'referer': 'https://rwwiv-standalone/login/?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36', 'x-forwarded-for': '192.168.88.6', 'x-forwarded-proto': 'https'}, 'host': 'rwwiv-standalone', 'method': 'POST', 'path': '/self-service/login', 'query': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'remote': '172.17.0.1:37714', 'scheme': 'http'}, 'level': 'info', 'login_flow': {'id': 'c73af96f-3217-47e8-9af9-6d11f1ec456c', 'type': 'browser', 'expires_at': '2021-07-21T00:16:31.882864531Z', 'issued_at': '2021-07-20T23:16:31.882864531Z', 'request_url': 'http://rwwiv-standalone/self-service/login/browser', 'ui': {'action': 'https://rwwiv-standalone/auth/self-service/login?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'method': 'POST', 'nodes': [{'type': 'input', 'group': 'default', 'attributes': {'name': 'csrf_token', 'type': 'hidden', 'value': 'p97vGbbgvi+a/eCR47f7CfGN+ZtL8BsqjzW2Vr8IKCm4okhPqTGunm2rAMYmI8+eqKCxZcEuWrRhQxaLCvO/BQ==', 'required': True, 'disabled': False}, 'messages': None, 'meta': {}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'password_identifier', 'type': 'text', 'value': 'onionuser@somewhere.invalid', 'required': True, 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1070004, 'text': 'ID', 'type': 'info'}}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'password', 'type': 'password', 'required': True, 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1070001, 'text': 'Password', 'type': 'info'}}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'method', 'type': 'submit', 'value': 'password', 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1010001, 'text': 'Sign in', 'type': 'info', 'context': {}}}}]}, 'created_at': '2021-07-20T23:16:31.888865Z', 'updated_at': '2021-07-20T23:16:31.888865Z', 'forced': False}, 'msg': 'Encountered self-service login error.', 'service_name': 'Ory Kratos', 'service_version': 'master', 'time': '2021-07-20T23:16:39Z'},
        {'audience': 'audit', 'error': {'message': 'I[#/] S[] the provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number'}, 'http_request': {'headers': {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9', 'cache-control': 'max-age=0', 'cookie': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'origin': 'https://rwwiv-standalone', 'referer': 'https://rwwiv-standalone/login/?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36', 'x-forwarded-for': '192.168.88.6', 'x-forwarded-proto': 'https'}, 'host': 'rwwiv-standalone', 'method': 'POST', 'path': '/self-service/login', 'query': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'remote': '172.17.0.1:37770', 'scheme': 'http'}, 'level': 'info', 'login_flow': {'id': 'c73af96f-3217-47e8-9af9-6d11f1ec456c', 'type': 'browser', 'expires_at': '2021-07-21T00:16:31.882864531Z', 'issued_at': '2021-07-20T23:16:31.882864531Z', 'request_url': 'http://rwwiv-standalone/self-service/login/browser', 'ui': {'action': 'https://rwwiv-standalone/auth/self-service/login?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'method': 'POST', 'nodes': [{'type': 'input', 'group': 'default', 'attributes': {'name': 'csrf_token', 'type': 'hidden', 'value': 'vbMC2EEMxjQtrll1stJ2+YVjpzWKQwanIdjHFGD/Jnqiz6WOXt3Whdr4uSJ3RkJu3E7vywCdRznPrmfJ1QSxVg==', 'required': True, 'disabled': False}, 'messages': None, 'meta': {}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'password_identifier', 'type': 'text', 'value': 'onionuser@somewhere.invalid', 'required': True, 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1070004, 'text': 'ID', 'type': 'info'}}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'password', 'type': 'password', 'required': True, 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1070001, 'text': 'Password', 'type': 'info'}}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'method', 'type': 'submit', 'value': 'password', 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1010001, 'text': 'Sign in', 'type': 'info', 'context': {}}}}], 'messages': [{'id': 4000006, 'text': 'The provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number.', 'type': 'error', 'context': {}}]}, 'created_at': '2021-07-20T23:16:31.888865Z', 'updated_at': '2021-07-20T23:16:31.888865Z', 'forced': False}, 'msg': 'Encountered self-service login error.', 'service_name': 'Ory Kratos', 'service_version': 'master', 'time': '2021-07-20T23:16:47Z'},
        {'audience': 'audit', 'http_request': {'headers': {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9', 'cache-control': 'max-age=0', 'cookie': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'origin': 'https://rwwiv-standalone', 'referer': 'https://rwwiv-standalone/login/?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36', 'x-forwarded-for': '192.168.88.6', 'x-forwarded-proto': 'https'}, 'host': 'rwwiv-standalone', 'method': 'POST', 'path': '/self-service/login', 'query': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'remote': '172.17.0.1:37818', 'scheme': 'http'}, 'identity_id': 'e93a0cdd-2275-42b0-9fc6-5c664865f6f8', 'level': 'info', 'msg': 'Identity authenticated successfully and was issued an Ory Kratos Session Cookie.', 'service_name': 'Ory Kratos', 'service_version': 'master', 'session_id': '9c5932ad-db89-46f6-84a3-170a87822607', 'time': '2021-07-20T23:16:55Z'},
    ]

    audit_lines.sort(key=lambda x: x.get('time'))
    expected_arr.sort(key=lambda x: x.get('time'))

    assert len(audit_lines) == len(expected_arr)

    for index, line in enumerate(audit_lines):
        assert all(item in line.items() for item in expected_arr[index].items() )


def test_create_sparse_entry_good():
    log_line = {'audience': 'audit', 'http_request': {'headers': {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9', 'cache-control': 'max-age=0', 'cookie': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'origin': 'https://rwwiv-standalone', 'referer': 'https://rwwiv-standalone/login/?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36', 'x-forwarded-for': '192.168.88.6', 'x-forwarded-proto': 'https'}, 'host': 'rwwiv-standalone', 'method': 'POST', 'path': '/self-service/login', 'query': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'remote': '172.17.0.1:37818', 'scheme': 'http'}, 'identity_id': 'e93a0cdd-2275-42b0-9fc6-5c664865f6f8', 'level': 'info', 'msg': 'Identity authenticated successfully and was issued an Ory Kratos Session Cookie.', 'service_name': 'Ory Kratos', 'service_version': 'master', 'session_id': '9c5932ad-db89-46f6-84a3-170a87822607', 'time': '2021-07-20T23:16:55Z'}
    expected_entry = [1626837415.0, 1, '192.168.88.6']

    sparse_entry = kratos_helper.__create_sparse_entry(log_line)
    assert sparse_entry == expected_entry


def test_create_sparse_entry_bad():
    log_line = {'audience': 'audit', 'error': {'message': 'I[#/] S[] the provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number'}, 'http_request': {'headers': {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9', 'cache-control': 'max-age=0', 'cookie': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'origin': 'https://rwwiv-standalone', 'referer': 'https://rwwiv-standalone/login/?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36', 'x-forwarded-for': '192.168.88.6', 'x-forwarded-proto': 'https'}, 'host': 'rwwiv-standalone', 'method': 'POST', 'path': '/self-service/login', 'query': 'Value is sensitive and has been redacted. To see the value set config key "log.leak_sensitive_values = true" or environment variable "LOG_LEAK_SENSITIVE_VALUES=true".', 'remote': '172.17.0.1:37714', 'scheme': 'http'}, 'level': 'info', 'login_flow': {'id': 'c73af96f-3217-47e8-9af9-6d11f1ec456c', 'type': 'browser', 'expires_at': '2021-07-21T00:16:31.882864531Z', 'issued_at': '2021-07-20T23:16:31.882864531Z', 'request_url': 'http://rwwiv-standalone/self-service/login/browser', 'ui': {'action': 'https://rwwiv-standalone/auth/self-service/login?flow=c73af96f-3217-47e8-9af9-6d11f1ec456c', 'method': 'POST', 'nodes': [{'type': 'input', 'group': 'default', 'attributes': {'name': 'csrf_token', 'type': 'hidden', 'value': 'p97vGbbgvi+a/eCR47f7CfGN+ZtL8BsqjzW2Vr8IKCm4okhPqTGunm2rAMYmI8+eqKCxZcEuWrRhQxaLCvO/BQ==', 'required': True, 'disabled': False}, 'messages': None, 'meta': {}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'password_identifier', 'type': 'text', 'value': 'onionuser@somewhere.invalid', 'required': True, 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1070004, 'text': 'ID', 'type': 'info'}}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'password', 'type': 'password', 'required': True, 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1070001, 'text': 'Password', 'type': 'info'}}}, {'type': 'input', 'group': 'password', 'attributes': {'name': 'method', 'type': 'submit', 'value': 'password', 'disabled': False}, 'messages': None, 'meta': {'label': {'id': 1010001, 'text': 'Sign in', 'type': 'info', 'context': {}}}}]}, 'created_at': '2021-07-20T23:16:31.888865Z', 'updated_at': '2021-07-20T23:16:31.888865Z', 'forced': False}, 'msg': 'Encountered self-service login error.', 'service_name': 'Ory Kratos', 'service_version': 'master', 'time': '2021-07-20T23:16:39Z'}
    expected_entry = [1626837399.0, 0, '192.168.88.6']

    sparse_entry = kratos_helper.__create_sparse_entry(log_line)
    assert sparse_entry == expected_entry


def test_sparse_data():
    mock_log_lines = get_log_lines('mock.log')
    
    audit_lines = kratos_helper.filter_kratos_log(mock_log_lines)

    expected_data_list = [
        [1626837399.0, 0, '192.168.88.6'],
        [1626837407.0, 0, '192.168.88.6'],
        [1626837415.0, 1, '192.168.88.6'],
    ]

    sparse_data_list = kratos_helper.sparse_data(audit_lines)

    expected_data_list.sort(key=lambda x: x[0])
    sparse_data_list.sort(key=lambda x: x[0])

    assert sparse_data_list == expected_data_list


def test_group_attempts_by_ip():
    sparse_data = [
        [1626837399.0, 0, '192.168.88.6'],
        [1626837407.0, 0, '192.168.88.6'],
        [1626837415.0, 1, '192.168.88.6'],
        [1626837499.0, 1, '192.168.88.8'],
        [1626837507.0, 1, '192.168.88.8'],
        [1626837515.0, 0, '192.168.88.8'],
    ]

    expected_grouped_data = [
        [
            [1626837399.0, 0, '192.168.88.6'],
            [1626837407.0, 0, '192.168.88.6'],
            [1626837415.0, 1, '192.168.88.6'],
        ],
        [
            [1626837499.0, 1, '192.168.88.8'],
            [1626837507.0, 1, '192.168.88.8'],
            [1626837515.0, 0, '192.168.88.8'],
        ]
    ]

    grouped_data = kratos_helper.group_attempts_by_ip(sparse_data)

    assert grouped_data == expected_grouped_data


def test_split_attempts_seconds():
    attempt_list = [
        [1626837399.0, 0, '192.168.88.6'],
        [1626837407.0, 0, '192.168.88.6'],
        [1626837415.0, 1, '192.168.88.6'],
        [1626837499.0, 1, '192.168.88.6'],
        [1626837507.0, 0, '192.168.88.6'],
        [1626837515.0, 1, '192.168.88.6'],
    ]

    expected_split_list = [
        [
            [1626837399.0, 0, '192.168.88.6'],
            [1626837407.0, 0, '192.168.88.6'],
            [1626837415.0, 1, '192.168.88.6'],
        ],
        [
            [1626837499.0, 1, '192.168.88.6'],
            [1626837507.0, 0, '192.168.88.6'],
            [1626837515.0, 1, '192.168.88.6'],
        ]
    ]

    split_list = kratos_helper.split_attempts_seconds(attempt_list, seconds=60)

    assert split_list == expected_split_list
