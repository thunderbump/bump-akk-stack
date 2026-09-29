"""Synthetic client and command launcher; never selects the installed runner."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import time

RUN_ID = '0123456789'


def client(root, op):
    case = (root / 'case').read_text()
    with (root / 'calls').open('a') as stream:
        stream.write(op + '\n')
    if case == 'refused' and op == 'run':
        print('Synthetic admission refusal: disk reserve', file=sys.stderr)
        return 1
    if op == 'run':
        print(json.dumps(dict(started=True, run_id=RUN_ID, accepted=False)))
        return 0
    if case.startswith('interrupt') and op == 'status':
        (root / 'in-request').touch()
        time.sleep(0.5)
    if case == 'request-error' and op == 'status':
        print('Synthetic status unavailable', file=sys.stderr)
        return 1
    if case == 'cancel-error' and op in ('status', 'cancel'):
        print('Synthetic ' + op + ' unavailable', file=sys.stderr)
        return 1
    if case in ('deadline-cancel-error', 'interrupt-cancel-error') and op == 'cancel':
        print('Synthetic cancel unavailable', file=sys.stderr)
        return 1
    report = dict(version=1, run_id=RUN_ID, accepted=False, diagnostic_only=True,
                  terminal=op == 'cancel' or not case.startswith(('interrupt', 'deadline')),
                  diagnostic_complete=case != 'interrupt', cleanup_complete=True,
                  error='Synthetic database warning', report_directory=str(root / RUN_ID))
    if not report['terminal'] or case == 'cleanup-incomplete':
        report['cleanup_complete'] = False
    if case == 'invalid' and op == 'status':
        report['run_id'] = 'wrong'
    if case == 'false-acceptance' and op == 'status':
        report['accepted'] = True
    print(json.dumps(report))
    return 0


def launch(root):
    script = Path(__file__).resolve().parents[2] / 'scripts/validate'
    loader = importlib.machinery.SourceFileLoader('validation_command', str(script))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module.CLIENT = (sys.executable, '-B', str(Path(__file__).resolve()), 'client', str(root))
    module.REPORTS = root
    module.POLL_SECONDS = 0.02
    module.WORK_SECONDS = 0.15 if (root / 'case').read_text().startswith('deadline') else 10
    module.REQUEST_SECONDS = 3
    return module.main(['--diagnostic'])


if __name__ == '__main__':
    root = Path(sys.argv[2])
    raise SystemExit(client(root, sys.argv[3]) if sys.argv[1] == 'client' else launch(root))
