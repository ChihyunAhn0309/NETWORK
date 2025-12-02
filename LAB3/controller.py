#!/usr/bin/python3

#
# KAIST CS341 SDN Lab POX controller
# 

import json
import sys
import os

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import dns
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import task_controller # task_controller.py

log = core.getLogger()

net = None
switchcnt = 0

class Switch(object):

    task_handlePacket = task_controller.handlePacket

    def __init__(self, connection, controller):
        self.connection = connection
        self.controller = controller
        connection.addListeners(self)

    # By default, switch will send unhandled packets to the controller
    def _handle_PacketIn(self, event):
        switchname = str(event.connection.ports[65534]).split(':',2)[0]
        self.task_handlePacket(switchname, event, self.connection)

class Controller(object):
    task_init = task_controller.init
    task_addrule = task_controller.addrule
    def __init__(self):
        core.openflow.addListeners(self)
    def routeinit(self):
        global net
        net = json.load(open('/tmp/net.json'))
        self.task_init(net)
        self.switches = []
    def _handle_ConnectionUp(self, event):
        global net
        global switchcnt
        if switchcnt == 0:
            # This is the first switch
            self.routeinit()
        switchname = str(event.connection.ports[65534]).split(':',2)[0]
        self.task_addrule(switchname, event.connection)
        switchcnt += 1
        if switchcnt == len(net['switches']):
            # This was the last switch
            switchcnt = 0
        self.switches.append(Switch(event.connection, self))
def launch():
    """
    Starts the component
    """
    core.registerNew(Controller)
