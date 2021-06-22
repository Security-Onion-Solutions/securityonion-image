from functools import partial
import importlib
import os
import logging
import pathlib
import threading
import sys
import schedule
import signal
from schedule import every, repeat
import time

from logscan import APP_LOG, LOGGER, SCAN_INTERVAL, __CONFIG_FILE, __OUTPUT_DIR, __DATA_DIR
from logscan.common import check_file

global threads
threads = []  # module-level thread list for signal handlers


def __exit_handler(signal_int, *_):
    LOGGER.info(f'Received {signal.Signals(signal_int).name}, starting shutdown...')
    print('')
    print('Trying to exit, wait a moment...', end='\r')
    sys.stdout.write("\033[K")
    for thread, event in threads:
        LOGGER.debug(f'[THREAD_ID:{thread.native_id}] Waiting 5s to join')
        thread.join(5)
        if thread.is_alive():
            LOGGER.debug(f'[THREAD_ID:{thread.native_id}] Thread still alive, setting close event')
            event.set()
        thread.join(5)
        if thread.is_alive():
            LOGGER.debug(f'[THREAD_ID:{thread.native_id}] Thread still alive, continuing')
    if len(threads) > 0:
        LOGGER.debug('Finished trying to join threads')
    LOGGER.info('Exiting logscan...')
    print('Exiting logscan...')
    os._exit(1)


def __run_model(model, event):        
    try:
        module = importlib.import_module(f'logscan.{model}.run')
    except ImportError as e:
        print(f'Error importing {model}:', file=sys.stderr, end=' ')
        print(e, file=sys.stderr)
        exit(1)

    if hasattr(module, 'run'):
        try:
            module.run(event)
        except Exception as e:
            LOGGER.error(e)
            LOGGER.error('Unexpected error occurred, quitting thread...')
            exit(1)
    else:
        raise NotImplementedError('Module does not contain necessary run function.')


@repeat(every(SCAN_INTERVAL).seconds)  # Increase time later
def __loop():
    for model in ['kff']:
        event = threading.Event()
        thread = threading.Thread(target=__run_model, args=(model, event,))
        threads.append([thread, event])
        thread.start()
    for thread, _ in threads:
        thread.join()
        threads.remove([thread, _])


def main():
    logging.basicConfig(
        filename=f'{APP_LOG}', 
        format='[ %(asctime)s : %(levelname).1s : %(name)s ] %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S',
        encoding='utf-8', 
        level=logging.DEBUG  # This will change to INFO later
        )

    if os.name == 'nt':
        LOGGER.debug('Registering signal handler for (SIGBREAK, SIGINT)')
        signal.signal(signal.SIGBREAK, __exit_handler)
    elif os.name == 'posix':
        LOGGER.debug('Registering signal handler for (SIGTERM, SIGINT)')
        signal.signal(signal.SIGTERM, __exit_handler)
    signal.signal(signal.SIGINT, __exit_handler)
    
    # Configure 3rd party log levels
    logging.getLogger('tensorflow').setLevel(logging.INFO)
    logging.getLogger('h5py._conv').setLevel(logging.WARNING)
    
    try:
        check_file(__CONFIG_FILE)
    except Exception as e:
        LOGGER.error(f'Config file {__CONFIG_FILE} does not exist, exiting...')
        print(e, file=sys.stderr)
        print('Exiting...')
        exit(1)

    if not pathlib.Path(__OUTPUT_DIR).is_dir():
        os.mkdir(__OUTPUT_DIR)

    if not pathlib.Path(__DATA_DIR).is_dir():
        os.mkdir(__DATA_DIR)

    LOGGER.info('Starting logscan...')
    print('Running logscan...')

    LOGGER.debug('Importing keras, will take a moment...')
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Disable tensorflow stdout
    from tensorflow import keras

    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            LOGGER.error(e)
            print('Unexpected error occurred, exiting...', file=sys.stderr)
            exit(1)
        time.sleep(1)


if __name__ == '__main__':
    main()
