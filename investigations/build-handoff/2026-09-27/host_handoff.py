# Included after the corrected-build protocol and custody helper, before main.
BUILD_ID = '@BUILD_ID@'


def producer_result():
    path = ROOT.parent/'producer/evidence/report.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 1024**2:
        raise RuntimeError('Unsafe producer evidence')
    return json.loads(path.read_text())


def expected_manifest():
    value = producer_result().get('guest_report_untrusted', {}).get('artifact', {})
    if value.get('identity') != BUILD_ID or not re.fullmatch('[a-f0-9]{64}', value.get('manifest_sha256', '')):
        raise RuntimeError('Missing producer manifest identity')
    return value['manifest_sha256']


ProducerBuildProtocol = BuildProtocol


class BuildProtocol(ProducerBuildProtocol):
    def accept(self, value):
        if CASE == 'producer':
            if value.get('kind') == 'result' and value.get('ok') is True:
                artifact = value.get('artifact', {})
                if (set(artifact) != {'identity', 'manifest_sha256', 'files', 'payload_bytes', 'unmounted'}
                        or artifact['identity'] != BUILD_ID or artifact['files'] != 4
                        or type(artifact['payload_bytes']) is not int or not 0 < artifact['payload_bytes'] <= 3*GIB
                        or not re.fullmatch('[a-f0-9]{64}', artifact.get('manifest_sha256', ''))
                        or artifact['unmounted'] is not True):
                    raise RuntimeError('Incomplete export evidence')
                copy = dict(value); del copy['artifact']
                return super().accept(copy)
            return super().accept(value)
        kind = value.get('kind')
        if kind == 'ready': return super().accept(value)
        if kind == 'observation':
            if value.get('name') != 'utility': raise RuntimeError('Unexpected consumer observation')
            return super().accept(value)
        if kind == 'result' and value.get('ok') is True:
            self.frames += 1
            if self.frames > 1500 or self.result is not None or not self.ready or value.get('nonce') != self.nonce:
                raise RuntimeError('Consumer completion identity/order')
            if set(value) != {'kind', 'nonce', 'ok', 'consumer'}: raise RuntimeError('Consumer completion shape')
            item = value['consumer']; prior = producer_result()
            binaries = prior['guest_report_untrusted']['binaries']
            libraries = {entry['path']:entry['sha256'] for name,entry in prior['observations_untrusted'].items()
                         if name.startswith('elf-') and not entry['build_file']}
            if (item.get('identity') != BUILD_ID or item.get('manifest_sha256') != custody()['manifest_sha256']
                    or item.get('readonly') is not True or item.get('unmounted') is not True
                    or item.get('compiled') is not False
                    or item.get('binaries') != {name:binaries[name] for name in ['world','zone','shared_memory','tests']}
                    or item.get('libraries') != libraries
                    or item.get('after_status') != prior['preflight_untrusted']['after_status']
                    or item.get('utility') != self.observations.get('utility')
                    or 'utility' not in self.observations):
                raise RuntimeError('Consumer output or environment differs from producer')
            self.result = value
            return kind
        return BaseBuildProtocol.accept(self, value)
