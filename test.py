import sys
import struct
import os
import time


cmd = "gnome-terminal --command='/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rule'"
os.system(cmd)
cmd = "gnome-terminal --command='/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rule'"
os.system(cmd)
cmd = "gnome-terminal --command='sudo python send_finefood.py'"
os.system(cmd)
