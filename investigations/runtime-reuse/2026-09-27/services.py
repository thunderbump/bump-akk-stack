"""Owned process capture. Text never decides whether to kill a service."""
import os
from pathlib import Path
import signal
import subprocess
import threading
import time


class Service:
    def __init__(self, name, args, cwd, log, env, secrets=(), observe=lambda *_: None,
                 event=lambda *_: None, cap=64*1024**2):
        self.name=name; self.path=Path(log); self.error=None; self.flags=set()
        self.tail=DiagnosticTail(secrets); self.tail.capacity=self.tail.limit+1024; self.observe=observe; self.event=event; self.cap=cap
        self.proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,cwd=cwd,env=env,start_new_session=True)
        self.pid=self.proc.pid; self.started=time.monotonic(); self.stop_reason=None; self.stop_complete=False; self.forced=False
        self.thread=threading.Thread(target=self.drain,daemon=True); self.thread.start()

    def drain(self):
        pending=''; total=0
        try:
            with self.path.open('xb') as stream:
                while chunk:=self.proc.stdout.read1(65536):
                    total+=len(chunk)
                    if total>self.cap: raise RuntimeError(self.name+': output limit')
                    stream.write(chunk); self.tail.feed(chunk)
                    pending+=chunk.decode(errors='replace')
                    while '\n' in pending:
                        line,pending=pending.split('\n',1)
                        if len(line)>65536: raise RuntimeError(self.name+': line limit')
                        self.observe(self,line)
                    if len(pending)>65536: raise RuntimeError(self.name+': line limit')
                if pending:self.observe(self,pending)
        except Exception as error:
            self.error=str(error)[:2000]
        finally:self.proc.stdout.close()

    def live(self):
        if self.error: raise RuntimeError(self.error)
        code=self.proc.poll()
        if code is not None: raise RuntimeError(self.name+': unexpected exit '+str(code))

    def stop(self, reason='requested shutdown', timeout=30):
        self.stop_reason=reason; before=self.proc.poll()
        if before is None:
            try:os.killpg(self.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.forced=True
                try:os.killpg(self.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                self.proc.wait(timeout=5)
        # Allow buffered output to drain before checking for descendants holding the pipe.
        self.thread.join(.25)
        if self.thread.is_alive():
            try:
                os.killpg(self.pid,signal.SIGKILL)
                self.forced=True
            except ProcessLookupError:pass
        self.thread.join(5)
        self.stop_complete=self.proc.poll() is not None and not self.thread.is_alive()
        value={'service':self.name,'return_code':self.proc.returncode,'early_exit':before is not None,
               'forced':self.forced,'reason':reason,'capture_error':self.error,
               'capture_complete':not self.thread.is_alive()}
        self.event('service-stop',value)
        return value
