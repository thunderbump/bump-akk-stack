# Guest observations are bounded data. They never select host paths or commands.
class BuildProtocol(BaseBuildProtocol):
    def __init__(self, nonce):
        super().__init__(nonce)
        self.observations = {}

    def accept(self, value):
        if value.get('kind') == 'ready':
            copy = dict(value)
            if copy.pop('experiment_sha256', None) != EXPERIMENT_SHA:
                raise RuntimeError('Wrong corrected build recipe')
            return super().accept(copy)
        if value.get('kind') == 'observation':
            self.frames += 1
            if self.frames > 1500 or self.result is not None or not self.ready or value.get('nonce') != self.nonce:
                raise RuntimeError('Observation identity/order')
            if set(value) != {'kind', 'nonce', 'name', 'value'}:
                raise RuntimeError('Observation shape')
            name = value['name']; item = value['value']
            if (not isinstance(name, str) or not re.fullmatch('[a-z0-9-]{1,80}', name)
                    or name in self.observations or len(self.observations) >= 150
                    or not isinstance(item, dict)):
                raise RuntimeError('Observation name/count/type')
            if name == 'candidate':
                if item != CANDIDATE: raise RuntimeError('Candidate identity mismatch')
            elif name.startswith('runner-'):
                mode = name.removeprefix('runner-')
                if mode not in EXPECTED: raise RuntimeError('Unknown runner control')
                record = dict(item); rc = record.pop('exit_code', None)
                control_result('EQEMU_TEST_RESULT ' + json.dumps(record), rc, mode)
            elif name == 'utility':
                utility_result('EQEMU_TEST_RESULT ' + json.dumps(item), 0)
            elif name != 'measurement' and not re.fullmatch(r'(elf|loader)-\d{1,3}', name):
                raise RuntimeError('Unknown observation')
            self.observations[name] = item
            return 'observation'
        if value.get('kind') == 'result' and value.get('ok') is True:
            required = {'candidate', 'utility', 'measurement', *('runner-' + mode for mode in EXPECTED),
                        *('loader-' + str(i) for i in range(4))}
            if not required <= self.observations.keys(): raise RuntimeError('Incomplete corrected build evidence')
            files = [item for name, item in self.observations.items() if name.startswith('elf-')]
            if not 4 <= len(files) <= 128: raise RuntimeError('Incomplete ELF inventory')
            for item in files:
                if (type(item.get('bytes')) is not int or not 0 < item['bytes'] <= 32*GIB
                        or type(item.get('build_file')) is not bool
                        or not isinstance(item.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', item['sha256'])):
                    raise RuntimeError('Invalid ELF observation')
            build_bytes = sum(item['bytes'] for item in files if item['build_file'])
            system_bytes = sum(item['bytes'] for item in files if not item['build_file'])
            expected = {'files': len(files), 'build_bytes': build_bytes, 'system_bytes': system_bytes,
                        'total_bytes': build_bytes + system_bytes,
                        'within_payload_budget': build_bytes + system_bytes <= 3*GIB,
                        'artifact_eligible': False, 'runtime_closure_proven': False}
            if self.observations['measurement'] != expected: raise RuntimeError('Inconsistent measurement summary')
        return super().accept(value)
