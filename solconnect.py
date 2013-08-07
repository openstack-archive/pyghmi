#!/usr/bin/env python
"""
@author: Jarrod Johnson <jbjohnso@us.ibm.com>

Copyright 2013 IBM Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""A simple little script to exemplify/test ipmi.console module
"""
import os
import sys
import termios
import tty

from pyghmi.ipmi import console

tcattr = termios.tcgetattr(sys.stdin)
newtcattr = tcattr
#TODO(jbjohnso): add our exit handler
newtcattr[-1][termios.VINTR] = 0
newtcattr[-1][termios.VSUSP] = 0
termios.tcsetattr(sys.stdin, termios.TCSADRAIN, newtcattr)

tty.setcbreak(sys.stdin.fileno())

passwd = os.environ['IPMIPASSWORD']

try:
    sol = console.Console(bmc=sys.argv[1], userid=sys.argv[2], password=passwd,
                          iohandler=(sys.stdin, sys.stdout), force=True)
    sol.main_loop()
finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, tcattr)
