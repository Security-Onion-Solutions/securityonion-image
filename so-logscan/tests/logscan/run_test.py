import os
import sys
from tests.conftests import MockThread, MockThreadingEvent
import pytest
import traceback
import signal
import logging

from unittest.mock import ANY, MagicMock, patch

import logscan
from logscan import LOG_BASE_DIR, run

exit_thread = False


def test_fatal(capsys, caplog):
    message = 'Test error message'
    with pytest.raises(SystemExit):
        try:
            raise Exception(message)
        except Exception as e:
            _, _, tb = sys.exc_info()
            run.__fatal(e, message, stdout=True)

        out, err = capsys.readouterr()

        assert message in err
        assert message in caplog.text
        for line in traceback.extract_tb(tb).format():
            assert line in caplog.text
            assert line in err


@patch('os._exit')
def test_fatal_os_exit(mock_exit, capsys, caplog):
    message = 'Test error message'
    try:
        raise Exception(message)
    except Exception as e:
        _, _, tb = sys.exc_info()
        run.__fatal(e, message, stdout=True, exit_parent=True)

    out, err = capsys.readouterr()

    assert mock_exit.called


def test_fatal_quiet(capsys, caplog):
    message = 'Test error message'
    with pytest.raises(SystemExit):
        try:
            raise Exception(message)
        except Exception as e:
            _, _, tb = sys.exc_info()
            run.__fatal(e, message, stdout=False)

        out, err = capsys.readouterr()

        assert message not in err
        assert message in caplog.text
        for line in traceback.extract_tb(tb).format():
                assert line in caplog.text
                assert line not in err


@patch('os._exit')
def test_exit_handler_no_threads(mock_exit, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    run.__exit_handler(signal.SIGTERM)

    out, err = capsys.readouterr()

    assert mock_exit.called
    assert f'Received SIGTERM, starting shutdown' in caplog.text
    assert 'Finished trying to join threads' not in caplog.text
    assert 'Closing log cache' in caplog.text
    assert 'Exiting logscan' in caplog.text
    assert 'Exiting logscan' in out
        

@patch('os._exit')
def test_exit_handler_thread(mock_exit, caplog):
    caplog.set_level(logging.DEBUG)
    exit_event = MockThreadingEvent()
    thread = MockThread()
    test_threads = [ 
        ( thread, exit_event ) 
    ]
    with patch.object(run, 'threads', test_threads):
        run.__exit_handler(signal.SIGTERM)

        thread.join.assert_called_once()

        log_prefix = '[THREAD_ID:1000]'

        assert f'{log_prefix} Waiting 1s to join' in caplog.text
        assert f'Finished trying to join threads' in caplog.text


@patch('os._exit')
def test_exit_handler_thread_stillalive(mock_exit, caplog):
    caplog.set_level(logging.DEBUG)
    exit_event = MockThreadingEvent()
    thread = MockThread(is_alive=True)
    test_threads = [ 
        ( thread, exit_event ) 
    ]
        
    with patch.object(run, 'threads', test_threads):
        run.__exit_handler(signal.SIGTERM)

        assert thread.join.call_count == 2
        exit_event.set.assert_called_once()

        log_prefix = '[THREAD_ID:1000]'
        assert f'{log_prefix} Waiting 1s to join' in caplog.text
        assert f'{log_prefix} Thread still alive, setting close event' in caplog.text
        assert f'{log_prefix} Thread still alive, continuing' in caplog.text

@pytest.mark.skip('WIP test')
@patch('logscan.run.__run_model')
@patch('logscan.run.log_cache')
def test_loop(mock_run, mock_log):
    mock_run = MagicMock()
    mock_log = MagicMock()

    run.__loop()

    assert mock_run.call_count == 3
    mock_run.assert_called_with('k1', ANY, ANY)
    mock_run.assert_called_with('k5', ANY, ANY)
    mock_run.assert_called_with('k60', ANY, ANY)

