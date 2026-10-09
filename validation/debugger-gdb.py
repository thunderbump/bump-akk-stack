"""Explicit GDB command file. Print locations only, never argument/local values."""
import gdb

gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set startup-with-shell off')
gdb.execute('set disable-randomization off')
gdb.execute('set detach-on-fork off')
gdb.execute('handle SIGSEGV SIGABRT SIGBUS SIGILL SIGFPE stop nopass')
gdb.execute('handle SIGTERM SIGHUP nostop noprint pass')


def crash(event):
    if not isinstance(event, gdb.SignalEvent):
        return
    gdb.write('EQEMU_CRASH_TRACE signal '+event.stop_signal+'\n')
    threads = gdb.selected_inferior().threads()
    for thread in threads[:16]:
        thread.switch()
        gdb.write('thread '+str(thread.num)+'\n')
        frame = gdb.newest_frame()
        count = 0
        while frame is not None and count < 24:
            location = frame.find_sal()
            filename = location.symtab.filename if location.symtab else '<unknown>'
            gdb.write('#'+str(count)+' '+str(frame.name() or '<unknown>')
                      +' at '+filename+':'+str(location.line)+'\n')
            frame = frame.older()
            count += 1
        if frame is not None:
            gdb.write('frames truncated at 24\n')
    if len(threads) > 16:
        gdb.write('threads truncated at 16\n')
    # Never resume into EQEmu's unbounded crash-handler debugger.
    gdb.execute('quit 2')


gdb.events.stop.connect(crash)
try:
    gdb.execute('run')
except gdb.error:
    gdb.write('EQEMU_CRASH_TRACE capture failed\n')
    gdb.execute('quit 2')
