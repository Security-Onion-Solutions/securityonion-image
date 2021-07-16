import logging
import logscan
import configparser
from configparser import ConfigParser
from pytimeparse.timeparse import timeparse
import pathlib, os


def __read_config(file) -> ConfigParser:
    config = configparser.ConfigParser()
    config.read(file)
    return config


def __is_docker():
    path = '/proc/self/cgroup'
    return (
        os.path.exists('/.dockerenv') or
        os.path.isfile(path) and any('docker' in line for line in open(path))
    )


BASE_DIR = '/logscan' if __is_docker() else pathlib.Path(logscan.__file__).parent.parent

__OUTPUT_DIR = '/output' if __is_docker() and pathlib.Path('/output').is_dir else f'{BASE_DIR}/output'
__DATA_DIR = '/data' if __is_docker() and pathlib.Path('/data').is_dir else f'{BASE_DIR}/data'
ALERT_LOG = f'{__OUTPUT_DIR}/alerts.log'
APP_LOG = f'{__OUTPUT_DIR}/app.log'
HISTORY_LOG = f'{__DATA_DIR}/history.log'
FILTERED_LOG = f'{__DATA_DIR}/filtered.log'

LOG_BASE_DIR = '/logs' if __is_docker() and pathlib.Path('/logs').is_dir else f'{BASE_DIR}/logs'

KRATOS_SUCCESS_STR = 'Identity authenticated successfully'

__CONFIG_FILE = f'{BASE_DIR}/logscan.conf'
CONFIG = __read_config(__CONFIG_FILE)

LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timeparse(CONFIG.get('global', 'scan_interval'))

KRATOS_LOG = f'{LOG_BASE_DIR}/{CONFIG.get("kratos", "log_path")}'

    