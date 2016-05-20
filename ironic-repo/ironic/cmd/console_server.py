# -*- encoding: utf-8 -*-
#
# ironic-console-server: remote console server with logging output
#
# (C) 2016 Akira Yoshiyama <akirayoshiyama@gmail.com>
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
#
# usage: ironic-console-server [-h] [-d] [-p PORT] [-f FILENAME] [-c ARGV]
#
# optional arguments:
#   -h, --help   show this help message and exit
#   -d           disable socket service on startup
#   -p PORT      port number (default: 7777)
#   -f FILENAME  log file name (default: typescript)
#   -c ARGV      command line (default: /bin/sh, use quotes for arguments)
#
# on SIGHUP: re-open the log file (for rotation/trancating)
# on SIGUSR1: enable socket service (for node-set-console-mode = ON)
# on SIGUSR2: disable socket service (for node-set-console-mode = OFF)


import argparse
import eventlet
from eventlet.green import socket
from eventlet import hubs
import os
import pty
import select
import shlex
import signal
import sys


DEFAULT_PORT = 7777
DEFAULT_FILENAME = 'typescript'
DEFAULT_COMMAND = '/bin/sh'

CLIENTS = set()
CHILD_PID = None
CHILD_FD = None
LOGFILE_FD = None
LOGFILE = None
IO_SIZE = 1024
SOCKET_ENABLED = True


hubs.use_hub("selects")
eventlet.monkey_patch()


def reopen_logfile(*args):
    """Close and re-open the log file for rotation/trancating"""
    global LOGFILE_FD

    # Close the current file descriptor if needed
    if LOGFILE_FD is not None:
        LOGFILE_FD.close()

    # Re-open the log file
    LOGFILE_FD = open(LOGFILE, "wb", 1)


def enable_socket(*args):
    """Enable socket service again"""
    global SOCKET_ENABLED
    SOCKET_ENABLED = True


def disable_socket(*args):
    """Close exist sockets and disable socket service"""
    global SOCKET_ENABLED
    SOCKET_ENABLED = False

    for fd in CLIENTS:
        fd.close()


def run_command_wrapper(argv):
    global CHILD_PID
    global CHILD_FD

    signal.signal(signal.SIGHUP, reopen_logfile)
    signal.signal(signal.SIGUSR1, enable_socket)
    signal.signal(signal.SIGUSR2, disable_socket)

    while True:
        CHILD_PID, CHILD_FD = pty.fork()
        if CHILD_PID == 0:
            # Child process
            os.execlp(argv[0], *argv)

        # Parent process
        while True:
            try:
                _r, _w, _x = select.select([CHILD_FD], [], [])
            except select.error as e:
                errno, msg = e
                if errno != 4:
                    raise
            if CHILD_FD not in _r:
                continue
            try:
                data = os.read(CHILD_FD, IO_SIZE)
            except OSError:
                # Re-execute the command
                break

            LOGFILE_FD.write(data)

            for fd in CLIENTS:
                try:
                    fd.sendall(data)
                except socket.error as e:
                    if e[0] != 32:
                        raise

        os.close(CHILD_FD)


def read_socket(sock):
    while True:
        try:
            data = sock.recv(IO_SIZE)
        except socket.error as e:
            errno, msg = e
            if errno == socket.EBADF:
                break
        if not data:
            break
        try:
            os.write(CHILD_FD, data)
        except socket.error as e:
            if e[0] != 32:
                raise
        except OSError:
            # The command looks exited.
            pass
    CLIENTS.remove(sock)


def run_services(port=DEFAULT_PORT, filename=DEFAULT_FILENAME,
                 disabled=False, argv=None):
    global CLIENTS
    global LOGFILE
    global LOGFILE_FD
    global SOCKET_ENABLED

    prog = sys.argv[0]
    argv = shlex.split(argv)

    if disabled:
        SOCKET_ENABLED = False

    LOGFILE = filename
    LOGFILE_FD = open(filename, "ab", 1)

    eventlet.spawn_n(run_command_wrapper, argv)

    try:
        print("%s starting up on port %s" % (prog, port))
        server = eventlet.listen(('0.0.0.0', port))
        while True:
            sock, address = server.accept()
            if SOCKET_ENABLED:
                print("new client:", address)
                CLIENTS.add(sock)
                eventlet.spawn_n(read_socket, sock)
            else:
                print("new client not accepted:", address)
                sock.close()
    except (KeyboardInterrupt, SystemExit):
        print("%s exiting." % prog)

    LOGFILE_FD.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='disabled', action='store_true',
                        help='disable socket service on startup')
    parser.add_argument('-p', dest='port', type=int, default=DEFAULT_PORT,
                        help='port number (default: %d)' % DEFAULT_PORT)
    parser.add_argument('-f', dest='filename', default=DEFAULT_FILENAME,
                        help='log file name (default: %s)' % DEFAULT_FILENAME)
    parser.add_argument('-c', dest='argv', default=DEFAULT_COMMAND,
                        help='command line (default: %s, use quotes for '
                        'arguments)' % DEFAULT_COMMAND)
    options = parser.parse_args()
    run_services(**options.__dict__)


if __name__ == '__main__':
    sys.exit(main())
