"""Bounded LLVM pilot using the producer's exact compilation database.

The fixed target set is a compatibility pilot, not changed-code coverage.
Run this module through the guest's bounded command adapter so cancellation
and VM teardown own the entire analyzer process group.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import resource
import re
import subprocess
import time

PROFILE = 'build-static-unit-v1'
TARGETS = ('common/crash.cpp', 'zone/worldserver.cpp')
CHECKS = ('clang-analyzer-core.NullDereference', 'clang-analyzer-core.CallAndMessage',
          'clang-analyzer-cplusplus.NewDelete', 'bugprone-use-after-move')
TIDY = '/usr/bin/clang-tidy-18'
SECONDS = 600
LIMIT = 1024 * 1024


def validate_summary(value):
    """Validate finite completed pilot evidence before host acceptance."""
    keys={'version','profile','complete','compile_database_sha256','checks','targets','findings',
          'wall_seconds','child_peak_rss_kib'}
    if (not isinstance(value,dict) or set(value)!=keys or type(value['version']) is not int
            or value['version']!=1 or value['profile']!=PROFILE or value['complete'] is not True
            or value['checks']!=list(CHECKS) or value['findings']!=[]
            or not isinstance(value['compile_database_sha256'],str)
            or not re.fullmatch('[a-f0-9]{64}',value['compile_database_sha256'])
            or not isinstance(value['targets'],list) or len(value['targets'])!=len(TARGETS)):
        raise ValueError('Incomplete native static pilot identity')
    times=[value['wall_seconds']]
    for name,row in zip(TARGETS,value['targets']):
        if (not isinstance(row,dict) or set(row)!={'target','exit_code','findings','wall_seconds'}
                or row['target']!=name or type(row['exit_code']) is not int or row['exit_code']!=0
                or type(row['findings']) is not int or row['findings']!=0):
            raise ValueError('Incomplete native static pilot target')
        times.append(row['wall_seconds'])
    if (any(type(t) not in (int,float) or not math.isfinite(t) or not 0<=t<=SECONDS for t in times)
            or type(value['child_peak_rss_kib']) is not int or not 0<=value['child_peak_rss_kib']<=64*1024**2
            or len(json.dumps(value,allow_nan=False).encode())>8192):
        raise ValueError('Native static pilot measurement bounds')
    return value


def compile_targets(source, build, targets=TARGETS):
    """Require one exact producer command per selected project translation unit."""
    source = Path(source).resolve(strict=True); build = Path(build).resolve(strict=True)
    database = build/'compile_commands.json'
    if database.is_symlink() or not database.is_file() or database.stat().st_size > 16*1024**2:
        raise ValueError('Missing or oversized compilation database')
    raw = database.read_bytes(); rows = json.loads(raw)
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20000 or not targets:
        raise ValueError('Empty or invalid translation-unit selection')
    selected = []
    for name in targets:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name:
            raise ValueError('Invalid project target')
        path = source/relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source):
            raise ValueError('Missing or escaped project target: '+name)
        matches = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('directory'), str) or not isinstance(row.get('file'), str):
                raise ValueError('Malformed compilation command')
            if not (isinstance(row.get('command'), str) and row['command'] or
                    isinstance(row.get('arguments'), list) and row['arguments'] and
                    all(isinstance(a, str) for a in row['arguments'])):
                raise ValueError('Missing compilation arguments')
            directory = Path(row['directory'])
            if not directory.is_absolute(): raise ValueError('Relative compilation directory')
            if (directory/row['file']).resolve() == path.resolve(): matches.append(row)
        if len(matches) != 1 or not Path(matches[0]['directory']).is_dir():
            raise ValueError('Missing or ambiguous compilation command: '+name)
        selected.append((name, path))
    return selected, hashlib.sha256(raw).hexdigest()


def diagnostic_result(raw, exit_code):
    """Compiler errors and unexpected exits are incomplete analysis, never clean."""
    import yaml
    if len(raw) > LIMIT: raise ValueError('Diagnostic report exceeds budget')
    report = yaml.safe_load(raw) if raw else {}
    if not isinstance(report, dict) or not isinstance(report.get('Diagnostics', []), list):
        raise ValueError('Malformed analyzer report')
    findings = []
    for item in report.get('Diagnostics', []):
        if not isinstance(item, dict) or not isinstance(item.get('DiagnosticName'), str):
            raise ValueError('Malformed analyzer diagnostic')
        name = item['DiagnosticName']
        if name.startswith('clang-diagnostic-'):
            # Even warning-only compiler incompatibilities need review in this pilot.
            raise ValueError('Compiler/context diagnostic: '+name)
        if name not in CHECKS: raise ValueError('Unexpected diagnostic: '+name)
        message = item.get('DiagnosticMessage', {})
        if not isinstance(message, dict) or not isinstance(message.get('Message'), str):
            raise ValueError('Malformed diagnostic message')
        findings.append(dict(check=name, message=message['Message'][:2000],
                             file=str(message.get('FilePath', ''))[:1024],
                             offset=message.get('FileOffset')))
    if exit_code != (1 if findings else 0):
        raise ValueError('Analyzer exit/report mismatch: '+str(exit_code))
    return findings


def analyze(source, build, output, targets=TARGETS):
    selected, digest = compile_targets(source, build, targets)
    output = Path(output)
    if output.exists(): raise ValueError('Diagnostic output already exists')
    output.mkdir(mode=0o700)
    started = time.monotonic(); records = []; findings = []
    try:
        for index, (name, path) in enumerate(selected):
            remaining = SECONDS-(time.monotonic()-started)
            if remaining <= 0: raise ValueError('Analysis deadline exceeded')
            fixes = output/(str(index)+'.yaml'); log = output/(str(index)+'.log')
            args = [TIDY, '--quiet', '--config={}', '--checks=-*,'+','.join(CHECKS),
                    '--warnings-as-errors='+','.join(CHECKS), '--export-fixes='+str(fixes),
                    '-p='+str(build), str(path)]
            begin = time.monotonic()
            # Temporary files avoid an unbounded in-memory stdout capture.
            with log.open('xb') as stream:
                process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT)))
                try:
                    while process.poll() is None:
                        if time.monotonic()-begin > min(120, remaining):
                            raise ValueError('Analyzer deadline: '+name)
                        if log.stat().st_size > LIMIT or fixes.exists() and fixes.stat().st_size > LIMIT:
                            raise ValueError('Analyzer output budget: '+name)
                        time.sleep(.05)
                    if log.stat().st_size > LIMIT: raise ValueError('Analyzer output budget')
                finally:
                    if process.poll() is None: process.kill()
                    process.wait(timeout=10)
            # clang-tidy omits its YAML file when there are no diagnostics.
            found = diagnostic_result(fixes.read_bytes() if fixes.exists() else b'', process.returncode)
            findings += found
            records.append(dict(target=name, exit_code=process.returncode, findings=len(found),
                                wall_seconds=round(time.monotonic()-begin, 3)))
        result = dict(version=1, profile=PROFILE, complete=True, compile_database_sha256=digest,
                      checks=list(CHECKS), targets=records, findings=findings,
                      wall_seconds=round(time.monotonic()-started, 3),
                      child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        (output/'report.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    except Exception as error:
        (output/'report.json').write_text(json.dumps(dict(version=1, profile=PROFILE, complete=False,
            compile_database_sha256=digest, targets=records, error=str(error)), indent=2)+'\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.source, args.build, args.output)
        print(json.dumps(result))
        return 1 if result['findings'] else 0
    except Exception as error:
        print(json.dumps(dict(complete=False, error=str(error))))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
