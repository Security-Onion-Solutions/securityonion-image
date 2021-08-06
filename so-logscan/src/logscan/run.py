import os
import sys
import pathlib
import importlib
import logging
import time
import schedule
from schedule import every, repeat
from pytimeparse.timeparse import timeparse
import signal
import tempfile
import threading
import traceback

from logscan import ALERT_LOG, APP_LOG, CONFIG, LOGGER, LOG_BASE_DIR, THREAD_EXPIRE_TIME, __CONFIG_FILE, DATA_DIR
from logscan.common import check_file
from logscan.common.alerts import gen_alert_list, write_alerts
from logscan.common.history import drop_old_history, get_history_line_count

threads = []  # module-level thread list for signal handlers
log_cache = tempfile.SpooledTemporaryFile(max_size=8000000, dir=DATA_DIR, mode='a+') # temp file to cache previous log read


def __fatal(e: Exception, message: str, stdout = True, exit_parent = False):
    if stdout: print(message, file=sys.stderr)
    LOGGER.exception(message)
    if stdout: traceback.print_exc(file=sys.stderr)
    if exit_parent:
        os._exit(1)
    else:
        sys.exit(1)


# Get config options
try:    
    check_file(__CONFIG_FILE)
except Exception as e:
    __fatal(e, f'Config file {__CONFIG_FILE} does not exist, exiting...')
SCAN_INTERVAL = timeparse(CONFIG.get('global', 'scan_interval'))
KRATOS_LOG = f'{LOG_BASE_DIR}/{CONFIG.get("kratos", "log_path")}'


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


def __run_model(model, exit_event, log):  
    tic = time.perf_counter()
    try:
        module = importlib.import_module(f'logscan.{model}')
    except ImportError as e:
        __fatal(e, f'Error importing {model}', exit_parent=True)

    try:
        transform = importlib.import_module(f'logscan.{model}.transform')
    except ImportError as e:
        __fatal(e, f'Error importing {model}.transform', exit_parent=True)

    if not hasattr(module, 'LOGGER'): raise NotImplementedError('Module does not contain required logger')
    if not hasattr(module, 'PREDICTION_THRESHOLD'): raise NotImplementedError('Module does not contain required prediction threshold')
       
    module_logger = logging.getLogger(module.__name__)

    try:
        from tensorflow import keras # lazy load keras
        model = keras.models.load_model(f'{pathlib.Path(module.__file__).parent}/{module.MODEL_FILENAME}')
        
        dataset = transform.build_dataset(log)
        if len(dataset) > 0:
            module_logger.debug('Generating alerts')
            alert_list, exit_early = gen_alert_list(dataset, model, module.PREDICTION_THRESHOLD, exit_event)
            if exit_early: module_logger.debug(f'[THREAD_ID:{threading.get_native_id()}] Quit generating alerts early')
            
            if len(alert_list) > 0:
                module_logger.debug(f'Writing to {ALERT_LOG}')
                write_alerts(alert_list, ALERT_LOG)
                module_logger.debug(f'Finished writing {len(alert_list)} lines')

    except Exception as e:
        __fatal(e, 'Unexpected error occurred, quitting thread...', stdout=False)

    toc = time.perf_counter()
    module_logger.debug(f'[ PERFORMANCE ] Module completed in {round(toc - tic, 2)} seconds')


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

    clear_history = True
    log_cache.seek(0)
    log_cache_lines = log_cache.readlines()

    if len(log_cache_lines) == 0 or log_lines[0] == log_cache_lines[0]:
        log_cache.seek(0)
        log_cache.truncate(0)
        clear_history = False
    for line in log_lines:
        log_cache.write(f'{line}\n')

    log_cache.seek(0)
    log = log_cache.readlines()

    history_line_init = get_history_line_count()

    if len(log) == 0:
        LOGGER.info('No log lines to scan')
        return

    for model in ['k1', 'k5', 'k60']:
        exit_event = threading.Event()
        thread = threading.Thread(target=__run_model, args=(model, exit_event, log, ))
        threads.append((thread, exit_event))
        thread.start()
    for thread, _ in threads:
        thread.join()
        threads.remove((thread, _))

    if clear_history: drop_old_history(start_line=history_line_init)

    toc = time.perf_counter()
    LOGGER.debug(f'[ PERFORMANCE ] Full scan completed in {round(toc - tic, 2)} seconds')
    LOGGER.info('Full scan complete')
    LOGGER.debug('Waiting for next job...')


def main():
    log_level = CONFIG.get('global', 'log_level').upper()
    if log_level not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG' ]:
        log_level = 'INFO'

    logging.basicConfig(
        filename=f'{APP_LOG}', 
        format='[ %(asctime)s : %(levelname).1s : %(name)s ] %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S',
        encoding='utf-8', 
        level=log_level
        )

    # Only log critical errors to console
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.CRITICAL)
    root_logger = logging.getLogger('')
    root_logger.addHandler(console)

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
    

    
    LOGGER.info('Starting logscan...')
    print('Running logscan...')

    LOGGER.debug('Importing keras...')
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Disable tensorflow stdout
    from tensorflow import keras as _

    try:
        schedule.run_all()
        while True:
            schedule.run_pending()
            time.sleep(1)
    except Exception as e:
        __fatal(e, 'Unexpected error occurred, exiting...')


if __name__ == '__main__':
    main()
