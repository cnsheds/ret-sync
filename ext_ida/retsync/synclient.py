#
# Copyright (C) 2016-2021, Alexandre Gazet.
#
# Copyright (C) 2012-2014, Quarkslab.
#
# This file is part of ret-sync.
#
# ret-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import socket
import errno
import base64
import tempfile
import threading
import logging
import json
import traceback
from collections import namedtuple
from string import Template

import idc
import idaapi


# default values
HOST = "localhost"
PORT = 9100
USE_TMP_LOGGING_FILE = True
TIMER_PERIOD = 0.1
PYTHON_MAJOR = sys.version_info[0]


# encoding settings (for data going in/out the plugin)
RS_ENCODING = 'utf-8'

# log settings
LOG_LEVEL = logging.DEBUG
LOG_PREFIX = 'synclient'
LOG_COLOR_ON = ""
LOG_COLOR_OFF = ""
CMD_COLOR_ON = ""
CMD_COLOR_OFF = ""


def rs_encode(buffer_str):
    return buffer_str.encode(RS_ENCODING)


def rs_decode(buffer_bytes):
    return buffer_bytes.decode(RS_ENCODING)


def rs_log(s, lvl=logging.INFO):
    if lvl >= LOG_LEVEL:
        print("%s[%s]%s %s" % (LOG_COLOR_ON, LOG_PREFIX, LOG_COLOR_OFF, s))



class Tunnel():

    def __init__(self, host, port):
        rs_log("initializing tunnel to IDA Server using %s:%d..." % (host, port))
        self.sock = None

        try:
            self.sock = socket.create_connection((host, port), 4)
        except socket.error as msg:
            if self.sock:
                self.sock.close()
                self.sock = None
            self.sync = False
            rs_log("tunnel initialization error: %s" % msg)
            return None

        self.sync = True

    def is_up(self):
        return (self.sock is not None and self.sync is True)

    def poll(self):
        if not self.is_up():
            return None

        self.sock.setblocking(False)

        try:
            msg = rs_decode(self.sock.recv(4096))
        except socket.error as e:
            err = e.args[0]
            if (err == errno.EAGAIN or err == errno.EWOULDBLOCK):
                return '\n'
            else:
                self.close()
                return None

        self.sock.setblocking(True)
        return msg

    def send(self, msg):
        if not self.sock:
            rs_log("tunnel_send: tunnel is unavailable (did you forget to sync ?)")
            return

        try:
            self.sock.send(rs_encode(msg))
        except socket.error as msg:
            print(msg)
            self.sync = False
            self.close()

            rs_log("tunnel_send error: %s" % msg)

    def close(self):
        if self.is_up():
            self.send("[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n")

        if self.sock:
            try:
                self.sock.close()
            except socket.error as msg:
                rs_log("tunnel_close error: %s" % msg)

        self.sync = False
        self.sock = None



# periodically poll socket in a dedicated thread
class Poller(threading.Thread):

    def __init__(self, sync):
        threading.Thread.__init__(self)
        self.evt_enabled = threading.Event()
        self.evt_enabled.clear()
        self.evt_stop = threading.Event()
        self.evt_stop.clear()
        self.sync: Sync = sync

    def run(self):
        last_ping = time.time()  # 新增：记录上次心跳时间
        while True:
            if self.evt_stop.is_set():
                break

            if not self.evt_enabled.is_set():
                while True:
                    if self.evt_enabled.wait(2*TIMER_PERIOD):
                        break
                    if not self.interpreter_alive():
                        return

            if not self.interpreter_alive():
                return
            if not self.sync.tunnel:
                return

            # 新增：每1秒发送一次心跳
            now = time.time()
            if now - last_ping >= 5.0:
                try:
                    self.sync.tunnel.send("[sync]{\"type\":\"ping\"}\n")
                except Exception as e:
                    rs_log(f"Ping failed: {e}")
                last_ping = now

            if self.sync.tunnel.is_up():
                self.poll()

            time.sleep(TIMER_PERIOD)

    # "the main thread is the thread from which the Python interpreter was started"
    def interpreter_alive(self):
        return threading.main_thread().is_alive()

    def poll(self):
        msg = self.sync.tunnel.poll()
        if msg:
            if len(msg) > 1 and msg.strip() != "[pong]":
                rs_log(msg)
        else:
            self.stop()

    def enable(self):
        self.evt_enabled.set()

    def disable(self):
        self.evt_enabled.clear()

    def stop(self):
        self.evt_stop.set()



class Sync():

    def __init__(self, cfg, commands=[]):
        rs_log("init")

        self.cfg = cfg
        self.auto = True
        self.pid = None
        self.maps = None
        self.base = None
        self.offset = None
        self.tunnel = None
        self.poller = None

        for cmd in commands:
            cmd(self)

        rs_log("%d commands added" % len(commands))

    def identity(self):
        id = "ida_client"
        return id.strip()

    def locate(self):
        self.offset = idaapi.get_screen_ea()
        self.base = idaapi.get_imagebase()
        self.tunnel.send("[sync]{\"type\":\"loc\",\"base\":%d,\"offset\":%d}\n" % (self.base, self.offset))
        self.makefunc(self.offset)

    def makefunc(self, ea):
        self.offset = ea
        self.base = idaapi.get_imagebase()
        cur_func = idaapi.get_func(self.offset)
        if cur_func is not None:
            func_name = idaapi.get_func_name(cur_func.start_ea)
            self.tunnel.send("[sync]{\"type\":\"addfunc\",\"base\":%d,\"offset\":%d,\"fnstart\":%d,\"fnname\":\"%s\"}\n"
                             % (self.base, self.offset, cur_func.start_ea, func_name))

    def create_poll_timer(self):
        if not self.poller:
            self.poller = Poller(self)
            self.poller.start()

    def suspend_poll_timer(self):
        if self.poller:
            self.poller.disable()

    def rearm_poll_timer(self):
        if self.poller:
            self.poller.enable()

    def release_poll_timer(self):
        if self.poller:
            self.poller.stop()
            self.poller = None

    def newobj_handler(self, event):
        # force a new capture
        self.maps = None

    def cont_handler(self, event):
        if self.tunnel:
            if self.poller is not None:
                self.poller.disable()
        return ''

    def stop_handler(self, event):
        if self.tunnel:
            self.locate()
            if self.poller is not None:
                self.poller.enable()
        return ''

    def exit_handler(self, event):
        self.reset_state()
        rs_log("exit, sync finished")

    def reset_state(self):
        try:
            self.release_poll_timer()

            if self.tunnel:
                self.tunnel.close()
                self.tunnel = None

            self.pid = None
            self.maps = None
            self.base = None
            self.offset = None
        except Exception as e:
            print(e)

    def startSync(self, arg):
        if self.tunnel and not self.tunnel.is_up():
            self.tunnel = None

        if not self.tunnel:
            if arg == "":
                arg = self.cfg.host

            self.tunnel = Tunnel(arg, self.cfg.port)
            if not self.tunnel.is_up():
                rs_log("sync failed")
                return

            id = self.identity()
            self.tunnel.send("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"ida\"}\n" % id)
            rs_log("sync is now enabled with host %s" % str(arg))
            self.create_poll_timer()
        else:
            print('(update)')

        if self.poller:
            self.poller.enable()



class GoAddr:
    def __init__(self, sync):
        self.sync = sync

    def invoke(self, raddr):
        self.sync.locate(raddr)

        if (raddr is None) or (self.sync.offset is None):
            return "-"

        self.sync.tunnel.send("[sync]{\"type\":\"loc\",\"base\":%d,\"offset\":%d" % (0,raddr))

        # Let time for the IDB client to reply if it exists
        # Need to give it more time than usual to avoid "Resource temporarily unavailable"
        time.sleep(0.5)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        if msg:
            return msg[:-1]  # strip newline
        else:
            return "-"


def load_configuration():
    user_conf = namedtuple('user_conf', 'host port ctx use_tmp_logging_file')
    host, port, ctx, use_tmp_logging_file = HOST, PORT, None, USE_TMP_LOGGING_FILE

    return user_conf(host, port, ctx, use_tmp_logging_file)



class Synclient:
    def __init__(self, modname=None):
        self.SYNC_PLUGIN = None
        self.Start(modname)

    def Start(self, modname):
        if self.SYNC_PLUGIN:
            rs_log('plugin already loaded')
        else:
            rs_cfg = load_configuration()
            rs_commands = []

            self.SYNC_PLUGIN = Sync(rs_cfg, rs_commands)
            self.SYNC_PLUGIN.startSync("")
            idbname = idaapi.get_root_filename()
            if modname:
                idbname = modname
            self.SYNC_PLUGIN.tunnel.send("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n" % idbname)

    def Stop(self):
        self.SYNC_PLUGIN.reset_state()
        self.SYNC_PLUGIN = None

    def bp_sync_loc(self):
        self.SYNC_PLUGIN.locate()

    def SyncAllFuncs(self):
        func_num = idaapi.get_func_qty()
        idaapi.show_wait_box("Sync All Functions")
        for i in range(0, func_num):
            if idaapi.user_cancelled():
                break

            func_start = idaapi.getn_func(i).start_ea
            self.SYNC_PLUGIN.makefunc(idaapi.getn_func(i).start_ea)
            time.sleep(0.01)
            idaapi.replace_wait_box("sync sub_%08X  (%d/%d)" % (func_start, i, func_num))

        idaapi.hide_wait_box();
        rs_log("Sync of all function definitions is completed.\n")


if __name__ == "__main__":
    pass

