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

"""Test class for console_utils driver module."""

import errno
import os
import psutil
import random
import signal
import string
import subprocess
import tempfile

from ironic_lib import utils as ironic_utils
import mock
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import netutils

from ironic.common import exception
from ironic.common import utils
from ironic.drivers.modules import console_utils
from ironic.drivers.modules import ipmitool as ipmi
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as obj_utils

CONF = cfg.CONF

INFO_DICT = db_utils.get_test_ipmi_info()


class ConsoleUtilsTestCase(db_base.DbTestCase):

    def setUp(self):
        super(ConsoleUtilsTestCase, self).setUp()
        self.node = obj_utils.get_test_node(
            self.context,
            driver='fake_ipmitool',
            driver_info=INFO_DICT)
        self.info = ipmi._parse_driver_info(self.node)

    def test__get_console_pid_dir(self):
        pid_dir = '/tmp/pid_dir'
        self.config(terminal_pid_dir=pid_dir, group='console')
        dir = console_utils._get_console_pid_dir()
        self.assertEqual(pid_dir, dir)

    def test__get_console_pid_dir_tempdir(self):
        self.config(tempdir='/tmp/fake_dir')
        dir = console_utils._get_console_pid_dir()
        self.assertEqual(CONF.tempdir, dir)

    @mock.patch.object(os, 'makedirs', autospec=True)
    @mock.patch.object(os.path, 'exists', autospec=True)
    def test__ensure_console_pid_dir_exists(self, mock_path_exists,
                                            mock_makedirs):
        mock_path_exists.return_value = True
        mock_makedirs.side_effect = OSError
        pid_dir = console_utils._get_console_pid_dir()

        console_utils._ensure_console_pid_dir_exists()

        mock_path_exists.assert_called_once_with(pid_dir)
        self.assertFalse(mock_makedirs.called)

    @mock.patch.object(os, 'makedirs', autospec=True)
    @mock.patch.object(os.path, 'exists', autospec=True)
    def test__ensure_console_pid_dir_exists_fail(self, mock_path_exists,
                                                 mock_makedirs):
        mock_path_exists.return_value = False
        mock_makedirs.side_effect = OSError
        pid_dir = console_utils._get_console_pid_dir()

        self.assertRaises(exception.ConsoleError,
                          console_utils._ensure_console_pid_dir_exists)

        mock_path_exists.assert_called_once_with(pid_dir)
        mock_makedirs.assert_called_once_with(pid_dir)

    @mock.patch.object(console_utils, '_get_console_pid_dir', autospec=True)
    def test__get_console_pid_file(self, mock_dir):
        mock_dir.return_value = tempfile.gettempdir()
        expected_path = '%(tempdir)s/%(uuid)s.pid' % {
            'tempdir': mock_dir.return_value,
            'uuid': self.info.get('uuid')}
        path = console_utils._get_console_pid_file(self.info['uuid'])
        self.assertEqual(expected_path, path)
        mock_dir.assert_called_once_with()

    @mock.patch.object(console_utils, '_get_console_pid_file', autospec=True)
    def test__get_console_pid(self, mock_exec):
        tmp_file_handle = tempfile.NamedTemporaryFile()
        tmp_file = tmp_file_handle.name
        self.addCleanup(ironic_utils.unlink_without_raise, tmp_file)
        with open(tmp_file, "w") as f:
            f.write("12345\n")

        mock_exec.return_value = tmp_file

        pid = console_utils._get_console_pid(self.info['uuid'])

        mock_exec.assert_called_once_with(self.info['uuid'])
        self.assertEqual(pid, 12345)

    @mock.patch.object(console_utils, '_get_console_pid_file', autospec=True)
    def test__get_console_pid_not_a_num(self, mock_exec):
        tmp_file_handle = tempfile.NamedTemporaryFile()
        tmp_file = tmp_file_handle.name
        self.addCleanup(ironic_utils.unlink_without_raise, tmp_file)
        with open(tmp_file, "w") as f:
            f.write("Hello World\n")

        mock_exec.return_value = tmp_file

        self.assertRaises(exception.NoConsolePid,
                          console_utils._get_console_pid,
                          self.info['uuid'])
        mock_exec.assert_called_once_with(self.info['uuid'])

    def test__get_console_pid_file_not_found(self):
        self.assertRaises(exception.NoConsolePid,
                          console_utils._get_console_pid,
                          self.info['uuid'])

    @mock.patch.object(ironic_utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(os, 'kill', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console(self, mock_pid, mock_kill, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.return_value = 12345

        console_utils._stop_console(self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_kill.assert_called_once_with(mock_pid.return_value,
                                          signal.SIGTERM)
        mock_unlink.assert_called_once_with(pid_file)

    @mock.patch.object(ironic_utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(os, 'kill', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console_nopid(self, mock_pid, mock_kill, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.side_effect = iter(
            [exception.NoConsolePid(pid_path="/tmp/blah")])

        self.assertRaises(exception.NoConsolePid,
                          console_utils._stop_console,
                          self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        self.assertFalse(mock_kill.called)
        mock_unlink.assert_called_once_with(pid_file)

    @mock.patch.object(ironic_utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(os, 'kill', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console_shellinabox_not_running(self, mock_pid,
                                                   mock_kill, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.return_value = 12345
        mock_kill.side_effect = OSError(errno.ESRCH, 'message')

        console_utils._stop_console(self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_kill.assert_called_once_with(mock_pid.return_value,
                                          signal.SIGTERM)
        mock_unlink.assert_called_once_with(pid_file)

    @mock.patch.object(ironic_utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(os, 'kill', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console_exception(self, mock_pid, mock_kill, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.return_value = 12345
        mock_kill.side_effect = OSError(2, 'message')

        self.assertRaises(exception.ConsoleError,
                          console_utils._stop_console,
                          self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_kill.assert_called_once_with(mock_pid.return_value,
                                          signal.SIGTERM)
        mock_unlink.assert_called_once_with(pid_file)

    def _get_shellinabox_console(self, scheme):
        generated_url = (
            console_utils.get_shellinabox_console_url(self.info['port']))
        console_host = CONF.my_ip
        if netutils.is_valid_ipv6(console_host):
            console_host = '[%s]' % console_host
        http_url = "%s://%s:%s" % (scheme, console_host, self.info['port'])
        self.assertEqual(http_url, generated_url)

    def test_get_shellinabox_console_url(self):
        self._get_shellinabox_console('http')

    def test_get_shellinabox_console_https_url(self):
        # specify terminal_cert_dir in /etc/ironic/ironic.conf
        self.config(terminal_cert_dir='/tmp', group='console')
        # use https
        self._get_shellinabox_console('https')

    def test_make_persistent_password_file(self):
        filepath = '%(tempdir)s/%(node_uuid)s' % {
            'tempdir': tempfile.gettempdir(),
            'node_uuid': self.info['uuid']}
        password = ''.join([random.choice(string.ascii_letters)
                            for n in range(16)])
        console_utils.make_persistent_password_file(filepath, password)
        # make sure file exists
        self.assertTrue(os.path.exists(filepath))
        # make sure the content is correct
        with open(filepath) as file:
            content = file.read()
        self.assertEqual(password, content)
        # delete the file
        os.unlink(filepath)

    @mock.patch.object(os, 'chmod', autospec=True)
    def test_make_persistent_password_file_fail(self, mock_chmod):
        mock_chmod.side_effect = IOError()
        filepath = '%(tempdir)s/%(node_uuid)s' % {
            'tempdir': tempfile.gettempdir(),
            'node_uuid': self.info['uuid']}
        self.assertRaises(exception.PasswordFileFailedToCreate,
                          console_utils.make_persistent_password_file,
                          filepath,
                          'password')

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    @mock.patch.object(psutil, 'pid_exists', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console(self, mock_stop,
                                       mock_dir_exists,
                                       mock_pid_exists,
                                       mock_pid,
                                       mock_popen):
        mock_popen.return_value.poll.return_value = 0
        mock_pid.return_value = 12345
        mock_pid_exists.return_value = True

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_shellinabox_console(self.info['uuid'],
                                                self.info['port'],
                                                'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_pid_exists.assert_called_once_with(12345)
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    @mock.patch.object(psutil, 'pid_exists', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_nopid(self, mock_stop,
                                             mock_dir_exists,
                                             mock_pid_exists,
                                             mock_pid,
                                             mock_popen):
        # no existing PID file before starting
        mock_stop.side_effect = iter([exception.NoConsolePid('/tmp/blah')])
        mock_popen.return_value.poll.return_value = 0
        mock_pid.return_value = 12345
        mock_pid_exists.return_value = True

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_shellinabox_console(self.info['uuid'],
                                                self.info['port'],
                                                'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_pid_exists.assert_called_once_with(12345)
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_fail(self, mock_stop, mock_dir_exists,
                                            mock_popen):
        mock_popen.return_value.poll.return_value = 1
        mock_popen.return_value.communicate.return_value = ('output', 'error')

        self.assertRaises(exception.ConsoleSubprocessFailed,
                          console_utils.start_shellinabox_console,
                          self.info['uuid'],
                          self.info['port'],
                          'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    @mock.patch.object(psutil, 'pid_exists', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_fail_no_pid(self, mock_stop,
                                                   mock_dir_exists,
                                                   mock_pid_exists,
                                                   mock_pid,
                                                   mock_popen):
        mock_popen.return_value.poll.return_value = 0
        mock_pid.return_value = 12345
        mock_pid_exists.return_value = False
        mock_popen.return_value.communicate.return_value = ('output', 'error')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        self.assertRaises(exception.ConsoleSubprocessFailed,
                          console_utils.start_shellinabox_console,
                          self.info['uuid'],
                          self.info['port'],
                          'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_pid_exists.assert_called_once_with(12345)
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_fail_nopiddir(self, mock_stop,
                                                     mock_dir_exists,
                                                     mock_popen):
        mock_dir_exists.side_effect = iter(
            [exception.ConsoleError(message='fail')])
        mock_popen.return_value.poll.return_value = 0

        self.assertRaises(exception.ConsoleError,
                          console_utils.start_shellinabox_console,
                          self.info['uuid'],
                          self.info['port'],
                          'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        self.assertFalse(mock_popen.called)

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_shellinabox_console(self, mock_stop):

        console_utils.stop_shellinabox_console(self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_shellinabox_console_fail_nopid(self, mock_stop):
        mock_stop.side_effect = iter([exception.NoConsolePid('/tmp/blah')])

        console_utils.stop_shellinabox_console(self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])

    def _get_ics_console(self, scheme):
        generated_url = (
            console_utils.get_ics_console_url(self.info['port']))
        console_host = CONF.my_ip
        if netutils.is_valid_ipv6(console_host):
            console_host = '[%s]' % console_host
        http_url = "%s://%s:%s" % (scheme, console_host, self.info['port'])
        self.assertEqual(http_url, generated_url)

    def test_get_ics_console_url(self):
        self.config(terminal='ironic-console-server', group='console')
        self._get_ics_console('tcp')

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_ics_console_log(self, mock_stop,
                                   mock_dir_exists,
                                   mock_popen):
        self.config(terminal='ironic-console-server', group='console')
        mock_popen.return_value.pid = 12345

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_ics_console_log(self.info['uuid'],
                                            self.info['port'],
                                            'ls&',
                                            True)

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_popen.assert_called_once_with(mock.ANY)

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_ics_console_log_fail(self, mock_stop, mock_dir_exists,
                                        mock_popen):
        self.config(terminal='ironic-console-server', group='console')
        mock_popen.return_value.pid = 12345
        mock_popen.side_effect = OSError()

        self.assertRaises(exception.ConsoleSubprocessFailed,
                          console_utils.start_ics_console_log,
                          self.info['uuid'],
                          self.info['port'],
                          'ls&',
                          True)

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_popen.assert_called_once_with(mock.ANY)

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_ics_console_log(self, mock_stop):
        self.config(terminal='ironic-console-server', group='console')
        console_utils.stop_ics_console_log(self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_ics_console_log_fail_nopid(self, mock_stop):
        self.config(terminal='ironic-console-server', group='console')
        mock_stop.side_effect = iter([exception.NoConsolePid('/tmp/blah')])

        console_utils.stop_ics_console_log(self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])

    @mock.patch.object(utils, 'execute', autospec=True)
    def test_get_ics_console_log(self, mock_execute):
        self.config(terminal='ironic-console-server', group='console')
        mock_execute.return_value = ('output', '')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.get_ics_console_log(self.info['uuid'])

        mock_execute.assert_called_once_with('tail', '-n', '100', mock.ANY)

    @mock.patch.object(utils, 'execute', autospec=True)
    def test_get_ics_console_log_fail(self, mock_execute):
        self.config(terminal='ironic-console-server', group='console')
        mock_execute.side_effect = OSError()

        self.assertRaises(exception.ConsoleSubprocessFailed,
                          console_utils.get_ics_console_log,
                          self.info['uuid'])

        mock_execute.assert_called_once_with('tail', '-n', '100', mock.ANY)

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_clear_ics_console_log(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.clear_ics_console_log(self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'HUP')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_clear_ics_console_log_fail_nopid(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')
        mock_send_signal.side_effect = exception.NoConsolePid(pid_path='/foo')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.clear_ics_console_log(self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'HUP')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_clear_ics_console_log_fail(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')
        mock_send_signal.side_effect = processutils.ProcessExecutionError()

        self.assertRaises(exception.ConsoleError,
                          console_utils.clear_ics_console_log,
                          self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'HUP')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_start_ics_console(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_ics_console(self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'USR1')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_start_ics_console_fail_nopid(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')
        mock_send_signal.side_effect = exception.NoConsolePid(pid_path='/foo')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_ics_console(self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'USR1')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_start_ics_console_fail(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')
        mock_send_signal.side_effect = processutils.ProcessExecutionError()

        self.assertRaises(exception.ConsoleError,
                          console_utils.start_ics_console,
                          self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'USR1')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_stop_ics_console(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.stop_ics_console(self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'USR2')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_stop_ics_console_fail_nopid(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')
        mock_send_signal.side_effect = exception.NoConsolePid(pid_path='/foo')

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.addCleanup(os.remove, pid_file)
        self.assertTrue(os.path.exists(pid_file))

        console_utils.stop_ics_console(self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'USR2')

    @mock.patch.object(console_utils, '_send_signal', autospec=True)
    def test_stop_ics_console_fail(self, mock_send_signal):
        self.config(terminal='ironic-console-server', group='console')
        mock_send_signal.side_effect = processutils.ProcessExecutionError()

        self.assertRaises(exception.ConsoleError,
                          console_utils.stop_ics_console,
                          self.info['uuid'])

        mock_send_signal.assert_called_once_with(mock.ANY, 'USR2')
