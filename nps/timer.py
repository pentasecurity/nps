# -*- coding: UTF-8 -*-

import threading
from nps.file_log import *


class PeriodicThread(object):
    """
    Python periodic Thread using Timer with instant cancellation
    """
    def __init__(self, callback=None, period=1, name=None, *args, **kwargs):
        self.name = name
        self.args = args
        self.kwargs = kwargs
        self.callback = callback
        self.period = period
        self.stop = False
        self.current_timer = None
        self.schedule_lock = threading.Lock()

    def set_period_sec(self, period):
        self.period = period

    def set_period_msec(self, period):
        self.period = period / 1000.0

    def set_interface(self, iface):
        self.iface = iface

    def set_tc_list(self, tcList):
        self.tcList = tcList

    def set_tc_list_loc(self, tcLock):
        self.tcLock = tcLock

    #Mimics Thread standard start method
    def start(self):
        self.stop = False
        self.schedule_timer()

    #By default run callback. Override it if you want to use inheritance
    def run(self):
        if self.callback is not None:
            self.callback(self.iface, self.tcList, self.tcLock)

    #Run desired callback and then reschedule Timer (if thread is not stopped)
    def _run(self):
        try:
            self.run()
        finally:
            with self.schedule_lock:
                if not self.stop:
                    self.schedule_timer()

    #Schedules next Timer run
    def schedule_timer(self):
        self.current_timer = threading.Timer(self.period, self._run, *self.args, **self.kwargs)
        if self.name:
            self.current_timer.name = self.name
        self.current_timer.start()

    #Mimics Timer standard cancel method
    def cancel(self):
        with self.schedule_lock:
            self.stop = True
            if self.current_timer is not None:
                self.current_timer.cancel()

    def restart(self):
        self.cancel()
        self.start()
        msg = '[' + self.iface + '] timer restart'
        write_log_file(msg)

    #Mimics Thread standard join method
    def join(self):
        self.current_timer.join()


''' how to use timer
def do_work():
    print 'timer is worked'

timer = PeriodicThread(do_work, 0.1, 'periodic timer',)
timer.start()
time.sleep(5)
timer.cancel()
timer.setPeriodMsec(1000)
timer.start()
time.sleep(5)
timer.cancel()
timer.join()
'''
