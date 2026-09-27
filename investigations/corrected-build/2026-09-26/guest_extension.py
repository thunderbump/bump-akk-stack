# Inserted into the fixed guest recipe. This code runs only inside the offline VM.

def apply_candidate(src):
    overlay = json.loads(P('/opt/eqemu-proof/candidate.json').read_text())
    for item in overlay['files']:
        path = src / item['path']
        if (sha(path) if path.exists() else None) != item['before_sha256']:
            raise RuntimeError('Baseline source mismatch: ' + item['path'])
        content = bytes.fromhex(item['hex'])
        if hashlib.sha256(content).hexdigest() != item['sha256']:
            raise RuntimeError('Candidate source mismatch')
        path.write_bytes(content)
    emit({'kind': 'observation', 'name': 'candidate', 'value': {
        'baseline': overlay['baseline'], 'candidate': overlay['candidate'],
        'overlay_sha256': sha(P('/opt/eqemu-proof/candidate.json'))}})


def completed_output(path, parser, *args):
    output = path.read_text()
    try:
        return parser(output, *args)
    except (ValueError, TypeError, KeyError) as error:
        tail = DiagnosticTail(limit=3000); tail.feed(output.encode())
        raise RuntimeError(path.stem + ': ' + str(error)[:500] + '\n' + tail.export()['text']) from error


def runner_controls():
    command('runner-control-build', ['cmake', '--build', str(WORK/'build'),
            '--target', 'tests_runner_controls', '--parallel', '1'], timeout=600)
    for mode in ['pass', 'fail', 'empty', 'setup-exception', 'body-exception']:
        expected_exit = 0 if mode == 'pass' else 1
        path = command('runner-' + mode, [str(WORK/'build/bin/tests_runner_controls'), mode],
                       timeout=30, cwd=WORK/'build', cap=1024**2, expected_exit=expected_exit)
        record = completed_output(path, control_result, expected_exit, mode)
        emit({'kind': 'observation', 'name': 'runner-' + mode, 'value': record})


def real_utility_suite():
    path = command('upstream-tests', [str(WORK/'build/bin/tests')], timeout=600,
                   cwd=WORK/'build', cap=1024**2)
    record = completed_output(path, utility_result, 0)
    emit({'kind': 'observation', 'name': 'utility', 'value': record})


def measure_outputs():
    """Measure direct ELF metadata and loader-resolved transitive libraries, guest only.

    This does not prove dlopen, Perl/Lua modules, maps, or a reusable runtime image.
    Unstripped binaries retain their embedded debug sections. No export is promoted.
    """
    paths = {str(WORK/'build/bin'/name) for name in ['world', 'zone', 'shared_memory', 'tests']}
    executables = sorted(paths)
    for index, executable in enumerate(executables):
        output = command('loader-' + str(index), ['ldd', executable], timeout=30, cap=1024**2).read_text()
        if 'not found' in output:
            tail = DiagnosticTail(limit=3000); tail.feed(output.encode())
            raise RuntimeError('Unresolved loader dependency: ' + executable + '\n' + tail.export()['text'])
        resolved = []
        for line in output.splitlines():
            match = re.search(r'(?:=>\s+)?(/\S+)\s+\(0x[0-9a-f]+\)', line)
            if match:
                resolved.append(match[1]); paths.add(str(P(match[1]).resolve(strict=True)))
            elif line.strip() and not line.strip().startswith('linux-vdso.so.'):
                raise RuntimeError('Unrecognized loader output: ' + line[:500])
        if not resolved:
            raise RuntimeError('Missing loader dependency evidence')
        emit({'kind': 'observation', 'name': 'loader-' + str(index),
              'value': {'executable': executable, 'resolved_paths': resolved}})
    if len(paths) > 128:
        raise RuntimeError('ELF measurement inventory exceeds 128 files')
    files = []; build_bytes = 0; system_bytes = 0
    for index, name in enumerate(sorted(paths)):
        path = P(name)
        if not path.is_file(): raise RuntimeError('Missing ELF file')
        out = command('elf-' + str(index), ['readelf', '-W', '-l', '-d', '-n', '-S', name],
                      timeout=30, cap=1024**2).read_text()
        build_file = path.is_relative_to(WORK)
        debug_info = bool(re.search(r'\] \.debug_info\s', out))
        if name in executables and not debug_info:
            raise RuntimeError('Expected embedded debug information: ' + name)
        build_id = re.findall(r'Build ID: ([a-f0-9]+)', out)
        if len(build_id) != 1: raise RuntimeError('Missing or ambiguous ELF build ID')
        record = {'path': name, 'bytes': path.stat().st_size, 'sha256': sha(path),
                  'build_file': build_file, 'debug_info': debug_info, 'build_id': build_id[0],
                  'needed': re.findall(r'\(NEEDED\).*?\[(.*?)\]', out),
                  'rpath': re.findall(r'\((?:RPATH|RUNPATH)\).*?\[(.*?)\]', out),
                  'interpreter': re.findall(r'Requesting program interpreter: ([^\]]+)', out)}
        files.append(record)
        if build_file: build_bytes += record['bytes']
        else: system_bytes += record['bytes']
        emit({'kind': 'observation', 'name': 'elf-' + str(index), 'value': record})
    emit({'kind': 'observation', 'name': 'measurement', 'value': {
        'files': len(files), 'build_bytes': build_bytes, 'system_bytes': system_bytes,
        'total_bytes': build_bytes + system_bytes,
        'within_payload_budget': build_bytes + system_bytes <= 3*1024**3,
        'artifact_eligible': False, 'runtime_closure_proven': False}})
