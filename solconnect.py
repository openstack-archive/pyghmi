import os
import sys
import fcntl

import tty
import termios

from ipmi import console

tcattr = termios.tcgetattr(sys.stdin)
newtcattr = tcattr
#TODO: allow ctrl-c and crtl-z to go to remote console, add our own exit handler
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
