"""Fixed, finite task-limit positive probe. No user inputs or host data access."""
import errno,json,os,signal,time
children=[];hit=False
try:
    for _ in range(64):
        try:pid=os.fork()
        except OSError as exc:
            if exc.errno!=errno.EAGAIN:raise
            hit=True;break
        if pid==0:
            time.sleep(20);os._exit(0)
        children.append(pid)
    print(json.dumps({'eagain':hit,'children':len(children),'cgroup':open('/proc/self/cgroup').read().strip()}),flush=True)
finally:
    for pid in children:
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
    for pid in children:os.waitpid(pid,0)
raise SystemExit(0 if hit and children else 1)
