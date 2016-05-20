# coding=utf-8

# Copyright 2014 International Business Machines Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Ironic console utilities.
"""

import errno
import os
import psutil
import signal
import subprocess
import time

from ironic_lib import utils as ironic_utils
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import netutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LW
from ironic.common import utils


opts = [
    cfg.StrOpt('terminal',
               default='shellinaboxd',
               help=_('Path to serial console terminal program')),
    cfg.StrOpt('terminal_cert_dir',
               help=_('Directory containing the terminal SSL cert(PEM) for '
                      'serial console access')),
    cfg.StrOpt('terminal_pid_dir',
               help=_('Directory for holding terminal pid files. '
                      'If not specified, the temporary directory '
                      'will be used.')),
    cfg.StrOpt('terminal_log_dir',
               help=_('Directory for holding terminal log files. '
                      'If not specified, the temporary directory '
                      'will be used.')),
    cfg.IntOpt('subprocess_checking_interval',
               default=1,
               help=_('Time interval (in seconds) for checking the status of '
                      'console subprocess.')),
    cfg.IntOpt('subprocess_timeout',
               default=10,
               help=_('Time (in seconds) to wait for the console subprocess '
                      'to start.')),
]

CONF = cfg.CONF
CONF.register_opts(opts, group='console')

LOG = logging.getLogger(__name__)


def _get_console_pid_dir():
    """Return the directory for the pid file."""

    return CONF.console.terminal_pid_dir or CONF.tempdir


def _get_console_log_dir():
    """Return the directory for the pid file."""

    return CONF.console.terminal_log_dir or CONF.tempdir


def _ensure_console_pid_dir_exists():
    """Ensure that the console PID directory exists

    Checks that the directory for the console PID file exists
    and if not, creates it.

    :raises: ConsoleError if the directory doesn't exist and cannot be created
    """

    dir = _get_console_pid_dir()
    if not os.path.exists(dir):
        try:
            os.makedirs(dir)
        except OSError as exc:
            msg = (_("Cannot create directory '%(path)s' for console PID file."
                     " Reason: %(reason)s.") % {'path': dir, 'reason': exc})
            LOG.error(msg)
            raise exception.ConsoleError(message=msg)


def _ensure_console_log_dir_exists():
    """Ensure that the console log directory exists

    Checks that the directory for the console log file exists
    and if not, creates it.

    :raises: ConsoleError if the directory doesn't exist and cannot be created
    """

    dir = _get_console_log_dir()
    if not os.path.exists(dir):
        try:
            os.makedirs(dir)
        except OSError as exc:
            msg = (_("Cannot create directory '%(path)s' for console log file."
                     " Reason: %(reason)s.") % {'path': dir, 'reason': exc})
            LOG.error(msg)
            raise exception.ConsoleError(message=msg)


def _get_console_pid_file(node_uuid):
    """Generate the pid file name to hold the terminal process id."""

    pid_dir = _get_console_pid_dir()
    name = "%s.pid" % node_uuid
    path = os.path.join(pid_dir, name)
    return path


def _get_console_log_file(node_uuid):
    """Generate the pid file name to hold the terminal process id."""

    pid_dir = _get_console_log_dir()
    name = "%s.console.log" % node_uuid
    path = os.path.join(pid_dir, name)
    return path


def _get_console_pid(node_uuid):
    """Get the terminal process id from pid file."""

    pid_path = _get_console_pid_file(node_uuid)
    try:
        with open(pid_path, 'r') as f:
            pid_str = f.readline()
            return int(pid_str)
    except (IOError, ValueError):
        raise exception.NoConsolePid(pid_path=pid_path)


def _stop_console(node_uuid):
    """Close the serial console for a node

    Kills the console process and deletes the PID file.

    :param node_uuid: the UUID of the node
    :raises: NoConsolePid if no console PID was found
    :raises: ConsoleError if unable to stop the console process
    """

    try:
        console_pid = _get_console_pid(node_uuid)

        os.kill(console_pid, signal.SIGTERM)
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            msg = (_("Could not stop the console for node '%(node)s'. "
                     "Reason: %(err)s.") % {'node': node_uuid, 'err': exc})
            raise exception.ConsoleError(message=msg)
        else:
            LOG.warning(_LW("Console process for node %s is not running "
                            "but pid file exists while trying to stop "
                            "shellinabox console."), node_uuid)
    finally:
        ironic_utils.unlink_without_raise(_get_console_pid_file(node_uuid))


def _send_signal(node_uuid, signum):
    """send a signal to the console server.

    Kills the console process and deletes the PID file.

    :param node_uuid: the UUID of the node
    :param signum: signal number to send
    :raises: NoConsolePid if no console PID was found
    :raises: processutils.ProcessExecutionError if unable to stop the process
    """

    try:
        console_pid = _get_console_pid(node_uuid)

        # Allow exitcode 99 (RC_UNAUTHORIZED)
        utils.execute('kill', '-%s' % signum, str(console_pid),
                      check_exit_code=[0, 99])
    finally:
        pass


def make_persistent_password_file(path, password):
    """Writes a file containing a password until deleted."""

    try:
        utils.delete_if_exists(path)
        with open(path, 'wb') as file:
            os.chmod(path, 0o600)
            file.write(password.encode())
        return path
    except Exception as e:
        utils.delete_if_exists(path)
        raise exception.PasswordFileFailedToCreate(error=e)


def get_shellinabox_console_url(port):
    """Get a url to access the console via shellinaboxd.

    :param port: the terminal port for the node.
    """

    console_host = CONF.my_ip
    if netutils.is_valid_ipv6(console_host):
        console_host = '[%s]' % console_host
    scheme = 'https' if CONF.console.terminal_cert_dir else 'http'
    return '%(scheme)s://%(host)s:%(port)s' % {'scheme': scheme,
                                               'host': console_host,
                                               'port': port}


def start_shellinabox_console(node_uuid, port, console_cmd):
    """Open the serial console for a node.

    :param node_uuid: the uuid for the node.
    :param port: the terminal port for the node.
    :param console_cmd: the shell command that gets the console.
    :raises: ConsoleError if the directory for the PID file cannot be created.
    :raises: ConsoleSubprocessFailed when invoking the subprocess failed.
    """

    # make sure that the old console for this node is stopped
    # and the files are cleared
    try:
        _stop_console(node_uuid)
    except exception.NoConsolePid:
        pass
    except processutils.ProcessExecutionError as exc:
        LOG.warning(_LW("Failed to kill the old console process "
                        "before starting a new shellinabox console "
                        "for node %(node)s. Reason: %(err)s"),
                    {'node': node_uuid, 'err': exc})

    _ensure_console_pid_dir_exists()
    pid_file = _get_console_pid_file(node_uuid)

    # put together the command and arguments for invoking the console
    args = []
    args.append(CONF.console.terminal)
    if CONF.console.terminal_cert_dir:
        args.append("-c")
        args.append(CONF.console.terminal_cert_dir)
    else:
        args.append("-t")
    args.append("-p")
    args.append(str(port))
    args.append("--background=%s" % pid_file)
    args.append("-s")
    args.append(console_cmd)

    # run the command as a subprocess
    try:
        LOG.debug('Running subprocess: %s', ' '.join(args))
        # use pipe here to catch the error in case shellinaboxd
        # failed to start.
        obj = subprocess.Popen(args,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    except (OSError, ValueError) as e:
        error = _("%(exec_error)s\n"
                  "Command: %(command)s") % {'exec_error': str(e),
                                             'command': ' '.join(args)}
        LOG.warning(error)
        raise exception.ConsoleSubprocessFailed(error=error)

    def _wait(node_uuid, popen_obj):
        locals['returncode'] = popen_obj.poll()

        # check if the console pid is created and the process is running.
        # if it is, then the shellinaboxd is invoked successfully as a daemon.
        # otherwise check the error.
        if locals['returncode'] is not None:
            if (locals['returncode'] == 0 and os.path.exists(pid_file) and
                psutil.pid_exists(_get_console_pid(node_uuid))):
                raise loopingcall.LoopingCallDone()
            else:
                (stdout, stderr) = popen_obj.communicate()
                locals['errstr'] = _(
                    "Command: %(command)s.\n"
                    "Exit code: %(return_code)s.\n"
                    "Stdout: %(stdout)r\n"
                    "Stderr: %(stderr)r") % {
                        'command': ' '.join(args),
                        'return_code': locals['returncode'],
                        'stdout': stdout,
                        'stderr': stderr}
                LOG.warning(locals['errstr'])
                raise loopingcall.LoopingCallDone()

        if (time.time() > expiration):
            locals['errstr'] = _("Timeout while waiting for console subprocess"
                                 "to start for node %s.") % node_uuid
            LOG.warning(locals['errstr'])
            raise loopingcall.LoopingCallDone()

    locals = {'returncode': None, 'errstr': ''}
    expiration = time.time() + CONF.console.subprocess_timeout
    timer = loopingcall.FixedIntervalLoopingCall(_wait, node_uuid, obj)
    timer.start(interval=CONF.console.subprocess_checking_interval).wait()

    if locals['errstr']:
        raise exception.ConsoleSubprocessFailed(error=locals['errstr'])


def stop_shellinabox_console(node_uuid):
    """Close the serial console for a node.

    :param node_uuid: the UUID of the node
    :raises: ConsoleError if unable to stop the console process
    """

    try:
        _stop_console(node_uuid)
    except exception.NoConsolePid:
        LOG.warning(_LW("No console pid found for node %s while trying to "
                        "stop shellinabox console."), node_uuid)


def start_ics_console_log(node_uuid, port, console_cmd, enable_console):
    """Start console logging of a node with ironic console server.

    :param node_uuid: the uuid for the node.
    :param port: the terminal port for the node.
    :param console_cmd: the shell command that gets the console.
    :param enable_console: enable serial console service (default: False)
    :raises: ConsoleError if the directory for the PID file cannot be created.
    :raises: ConsoleSubprocessFailed when invoking the subprocess failed.
    """

    # make sure that the old console for this node is stopped
    # and the files are cleared
    try:
        _stop_console(node_uuid)
    except exception.NoConsolePid:
        pass
    except processutils.ProcessExecutionError as exc:
        LOG.warning(_LW("Failed to kill the old console process "
                        "before starting a new console server"
                        "for node %(node)s. Reason: %(err)s"),
                    {'node': node_uuid, 'err': exc})

    _ensure_console_pid_dir_exists()
    _ensure_console_log_dir_exists()
    pid_file = _get_console_pid_file(node_uuid)
    log_file = _get_console_log_file(node_uuid)

    # put together the command and arguments for invoking the console
    args = []
    args.append(CONF.console.terminal)
    if not enable_console:
        args.append("-d")
    args.append("-p")
    args.append(str(port))
    args.append("-f")
    args.append(log_file)
    args.append("-c")
    args.append(console_cmd)

    # run the command as a subprocess
    try:
        LOG.debug('Running subprocess: %s', ' '.join(args))
        obj = subprocess.Popen(args)
    except (OSError, ValueError) as e:
        error = _("%(exec_error)s\n"
                  "Command: %(command)s") % {'exec_error': str(e),
                                             'command': ' '.join(args)}
        LOG.warning(error)
        raise exception.ConsoleSubprocessFailed(error=error)

    with open(pid_file, "w") as f:
        f.write("%s" % obj.pid)


def stop_ics_console_log(node_uuid):
    """Stop console logging of a node with ironic console server.

    :param node_uuid: the UUID of the node
    :raises: ConsoleError if unable to stop the console process
    """

    try:
        _stop_console(node_uuid)
    except exception.NoConsolePid:
        LOG.warning(_LW("No console pid found for node %s while trying to "
                        "stop the console server."), node_uuid)
    except processutils.ProcessExecutionError as exc:
            msg = (_("Could not stop the console for node '%(node)s'. "
                     "Reason: %(err)s.") % {'node': node_uuid, 'err': exc})
            raise exception.ConsoleError(message=msg)


def get_ics_console_log(node_uuid):
    """Get the content of a console log of a node (ironic console server).

    :param node_uuid: the UUID of the node
    :raises: ConsoleError if unable to stop the console process
    """
    log_file = _get_console_log_file(node_uuid)

    args = ["tail", "-n", "100", log_file]
    try:
        LOG.debug('Running subprocess: %s', ' '.join(args))
        stdout, stderr = utils.execute(*args)
    except (OSError, ValueError) as e:
        error = _("%(exec_error)s\n"
                  "Command: %(command)s") % {'exec_error': str(e),
                                             'command': ' '.join(args)}
        LOG.warning(error)
        raise exception.ConsoleSubprocessFailed(error=error)
    return stdout


def clear_ics_console_log(node_uuid):
    """Clear the content of a console log (ironic console server).

    :param node_uuid: the uuid for the node.
    :raises: ConsoleError if unable to clear the console log
    """

    try:
        ironic_utils.unlink_without_raise(_get_console_log_file(node_uuid))
        _send_signal(node_uuid, 'HUP')
    except exception.NoConsolePid:
        LOG.warning(_LW("No console pid found for node %s while trying to "
                        "enable the console service."), node_uuid)
    except processutils.ProcessExecutionError as exc:
            msg = (_("Could not enable the console service for node "
                     "'%(node)s'. Reason: %(err)s.") % {
                   'node': node_uuid, 'err': exc})
            raise exception.ConsoleError(message=msg)


def get_ics_console_url(port):
    """Get a url to access the console (ironic console server).

    :param port: the terminal port for the node.
    """

    console_host = CONF.my_ip
    schema = 'tcp'
    if netutils.is_valid_ipv6(console_host):
        console_host = '[%s]' % console_host
        schema = 'tcp6'
    return '%(schema)s://%(host)s:%(port)s' % {'schema': schema,
                                               'host': console_host,
                                               'port': port}


def start_ics_console(node_uuid):
    """Open the serial console for a node (ironic console server).

    :param node_uuid: the uuid for the node.
    :raises: ConsoleError if unable to enable the console service
    """

    try:
        _send_signal(node_uuid, 'USR1')
    except exception.NoConsolePid:
        LOG.warning(_LW("No console pid found for node %s while trying to "
                        "enable the console service."), node_uuid)
    except processutils.ProcessExecutionError as exc:
            msg = (_("Could not enable the console service for node "
                     "'%(node)s'. Reason: %(err)s.") % {
                   'node': node_uuid, 'err': exc})
            raise exception.ConsoleError(message=msg)


def stop_ics_console(node_uuid):
    """Close the serial console for a node (ironic console server).

    :param node_uuid: the UUID of the node
    :raises: ConsoleError if unable to disable the console service
    """

    try:
        _send_signal(node_uuid, 'USR2')
    except exception.NoConsolePid:
        LOG.warning(_LW("No console pid found for node %s while trying to "
                        "disable the console service."), node_uuid)
    except processutils.ProcessExecutionError as exc:
            msg = (_("Could not disable the console service for node "
                     "'%(node)s'. Reason: %(err)s.") % {
                   'node': node_uuid, 'err': exc})
            raise exception.ConsoleError(message=msg)
