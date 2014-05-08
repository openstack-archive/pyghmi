#!/usr/bin/env python
# Copyright 2013 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
@author: Jarrod Johnson <jbjohnso@us.ibm.com>
"""

"""A simple little script to exemplify/test ipmi.console module
"""
import fcntl
import os
import select
import sys
import termios
import tty

from pyghmi.ipmi import console
import threading

tcattr = termios.tcgetattr(sys.stdin)
newtcattr = tcattr
#TODO(jbjohnso): add our exit handler
newtcattr[-1][termios.VINTR] = 0
newtcattr[-1][termios.VSUSP] = 0
termios.tcsetattr(sys.stdin, termios.TCSADRAIN, newtcattr)

tty.setcbreak(sys.stdin.fileno())
fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

passwd = os.environ['IPMIPASSWORD']

sol = None


def _doinput():
    while True:
        select.select((sys.stdin,), (), (), 600)
        try:
            data = sys.stdin.read()
        except OSError:
            continue
        sol.send_data(data)


def _print(data):
    sys.stdout.write(data)
    sys.stdout.flush()

try:
    sol = console.Console(bmc=sys.argv[1], userid=sys.argv[2], password=passwd,
                          iohandler=_print, force=True)
    inputthread = threading.Thread(target=_doinput)
    inputthread.start()
    sol.main_loop()
finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, tcattr)
