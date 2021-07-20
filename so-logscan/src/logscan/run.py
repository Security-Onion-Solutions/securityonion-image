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
import tempfile
import json
import traceback

from src.logscan import APP_LOG, LOGGER, SCAN_INTERVAL, THREAD_EXPIRE_TIME, __CONFIG_FILE, __OUTPUT_DIR, __DATA_DIR, KRATOS_LOG, HISTORY_LOG
from src.logscan.common import check_file

global threads
threads = []  # module-level thread list for signal handlers


def __fatal(e: Exception, message: str, stdout = True, exit_parent = False):
    if stdout: print(message, file=sys.stderr)
    LOGGER.exception(message)
    if stdout: traceback.print_exc(file=sys.stderr)
    if exit_parent:
        os._exit(1)
    else:
        exit(1)


def __exit_handler(signal_int, *_):
    LOGGER.info(f'Received {signal.Signals(signal_int).name}, starting shutdown...')
    print('')
    print('Trying to exit, wait a moment...', end='\r')
    sys.stdout.write("\033[K")
    for thread, event in threads:
        LOGGER.debug(f'[THREAD_ID:{thread.native_id}] Waiting 1s to join')
        thread.join(THREAD_EXPIRE_TIME)
        if thread.is_alive():
            LOGGER.debug(f'[THREAD_ID:{thread.native_id}] Thread still alive, setting close event')
            event.set()
        thread.join(THREAD_EXPIRE_TIME)
        if thread.is_alive():
            LOGGER.debug(f'[THREAD_ID:{thread.native_id}] Thread still alive, continuing')
    if len(threads) > 0:
        LOGGER.debug('Finished trying to join threads')
    LOGGER.debug('Closing log cache...')
    log_cache.close()
    LOGGER.info('Exiting logscan...')
    print('Exiting logscan...')
    os._exit(2)


def __run_model(model, event, log, clear_history):        
    try:
        module = importlib.import_module(f'src.logscan.{model}.run')
    except ImportError as e:
        __fatal(e, f'Error importing {model}', exit_parent=True)

    if hasattr(module, 'run'):
        try:
            module.run(event, log, clear_history)
        except Exception as e:
            __fatal(e, 'Unexpected error occurred, quitting thread...', stdout=False)
    else:
        raise NotImplementedError('Module does not contain necessary run function.')


@repeat(every(SCAN_INTERVAL).seconds)
def __loop():
    tic = time.perf_counter()
    LOGGER.debug('Copying kratos log to cache...')
    try:
        check_file(KRATOS_LOG)
        with open(KRATOS_LOG, 'r') as kratos_log:
            log_lines = kratos_log.readlines()
    except FileNotFoundError as e:
        LOGGER.error(e)
        sys.exit(1)

    # TODO: convert to rolling queue (delete old lines as cache fills up)

    clear_history = True
    log_cache.seek(0)
    log_cache_lines = log_cache.readlines()
    if len(log_cache_lines) == 0 or log_lines[0] == log_cache_lines[0]:
        log_cache.truncate(0)
        clear_history = False
    for line in log_lines:
        log_cache.write(line + '\n')

    log_cache.seek(0)
    log = log_cache.readlines()
    for model in ['k1', 'k5', 'k60']:
        event = threading.Event()
        thread = threading.Thread(target=__run_model, args=(model, event, log, clear_history, ))
        threads.append([thread, event])
        thread.start()
    for thread, _ in threads:
        thread.join()
        threads.remove([thread, _])

    toc = time.perf_counter()
    LOGGER.debug(f'[PERFORMANCE] Full scan completed in {round(toc - tic, 2)} seconds')
    LOGGER.info('Full scan complete')
    LOGGER.debug('Waiting for next job...')


def main():
    logging.basicConfig(
        filename=f'{APP_LOG}', 
        format='[ %(asctime)s : %(levelname).1s : %(name)s ] %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S',
        encoding='utf-8', 
        level=logging.DEBUG  # FIXME: change to INFO
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
        __fatal(e, f'Config file {__CONFIG_FILE} does not exist, exiting...')
    
    global log_cache
    log_cache = tempfile.SpooledTemporaryFile(max_size=8000000, dir=__DATA_DIR, mode='a+')

    if not pathlib.Path(__OUTPUT_DIR).is_dir():
        os.mkdir(__OUTPUT_DIR)

    if not pathlib.Path(__DATA_DIR).is_dir():
        os.mkdir(__DATA_DIR)

    LOGGER.info('Starting logscan...')
    print('Running logscan...')

    LOGGER.debug('Importing keras...')
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Disable tensorflow stdout
    from tensorflow import keras

    try:
        schedule.run_all()
        while True:
            schedule.run_pending()
            time.sleep(1)
    except Exception as e:
        __fatal(e, 'Unexpected error occurred, exiting...')



if __name__ == '__main__':
    main()
