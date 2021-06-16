import logscan
import configparser
from configparser import ConfigParser
import pathlib, os
from pytimeparse.timeparse import timeparse

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
OUTPUT_FILE = f'{__OUTPUT_DIR}/logscan.log'

LOG_BASE_DIR = '/logs' if __is_docker() and pathlib.Path('/logs').is_dir else f'{BASE_DIR}/logs' 

KRATOS_SUCCESS_STR = 'Identity authenticated successfully'

__CONFIG_FILE = f'{BASE_DIR}/logscan.conf'
CONFIG = __read_config(__CONFIG_FILE)
