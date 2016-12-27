# -*- coding: UTF-8 -*-
import threading
import time


class PeriodicThread(object):
    """
    periodic thread using Timer with instant cancellation
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

    # Mimics Thread standard start method
    def start(self):
        self.stop = False
        self.schedule_timer()

    # By default run callback. Override it if you want to use inheritance
    def run(self):
        if self.callback is not None:
            # only execute once callback
            self.callback(self.args, self.kwargs)

            # if you want it to run callback every timeout,
            # do nextline comment!
            self.stop = True

    # Run desired callback and then reschedule Timer (if thread is not stopped)
    def _run(self):
        try:
            self.run()
        finally:
            with self.schedule_lock:
                if not self.stop:
                    self.schedule_timer()

    # Schedules next Timer run
    def schedule_timer(self):
        self.current_timer = threading.Timer(self.period, self._run, *self.args, **self.kwargs)
        if self.name:
            self.current_timer.name = self.name
        self.current_timer.start()

    # Mimics Timer standard cancel method
    def cancel(self):
        with self.schedule_lock:
            self.stop = True
            if self.current_timer is not None:
                self.current_timer.cancel()

    def restart(self):
        self.cancel()
        self.start()

    # Mimics Thread standard join method
    def join(self):
        self.current_timer.join()


# Sample testing
#if __name__ == "__main__":
#    def do_work(*args, **kwargs):
#        print('timer is worked')
#
#    timer = PeriodicThread(do_work, 2, 'periodic timer',)
#    print('This is prediocThread test...')
#    print('Start timeout(2000ms) and sleep(5000ms)')
#    timer.start()
#    time.sleep(5)
#    timer.cancel()
#    print('end')
#
#    print('Start timeout(100ms) and sleep(5000ms)')
#    timer.set_period_msec(100)
#    timer.start()
#    time.sleep(5)
#    timer.cancel()
#    timer.join()
#    print('end')
