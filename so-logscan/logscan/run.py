import importlib
import timeloop
import logging
import threading
import sys
import datetime as dt
from pytimeparse.timeparse import timeparse

from logscan.settings import __CONFIG_FILE, CONFIG
from logscan.common import check_file


def __run_model(model):
    try:
        module = importlib.import_module(f'logscan.{model}.run')
    except ImportError as e:
        print(f'Error importing {model}:', file=sys.stderr, end=' ')
        print(e, file=sys.stderr)
        exit(1)
    if hasattr(module, 'run'):
        module.run()
    else:
        raise NotImplementedError('Module does not contain necessary run function.')


tl = timeloop.Timeloop()
@tl.job(interval=dt.timedelta(seconds=timeparse(CONFIG.get('global', 'scan_interval'))))
def loop():
    threads = []
    for model in ['kff']:
        thread = threading.Thread(target=__run_model, args=(model,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()


def main():
    logging.getLogger("timeloop").setLevel(logging.CRITICAL)
    check_file(__CONFIG_FILE)
    tl.start(block=True)

if __name__ == '__main__':
    main()
