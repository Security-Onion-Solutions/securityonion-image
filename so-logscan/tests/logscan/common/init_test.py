import os
import importlib

import logscan
from logscan import DATA_DIR, OUTPUT_DIR

def test_dir_creation():
    assert os.getenv('ENV') == 'testing'
    assert OUTPUT_DIR == '/Users/rwwiv/repos/securityonion-image/so-logscan/tests/output'

    if os.path.exists(DATA_DIR):
        os.rmdir(DATA_DIR)
    if os.path.exists(OUTPUT_DIR):
        os.rmdir(OUTPUT_DIR)

    importlib.reload(logscan)

    assert os.path.exists(DATA_DIR) == True
    assert os.path.exists(OUTPUT_DIR) == True
