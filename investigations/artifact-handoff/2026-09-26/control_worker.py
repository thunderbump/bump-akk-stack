# Fixed test-only adapter, appended to the worker; no runtime failure switch.
CONTROL = '@CONTROL@'
normal_write_custody = write_custody


def write_custody(value):
    if CONTROL == 'publish' and value.get('eligible') is True:
        write_json(EVIDENCE / 'publication-fault.json', {'injected': True, 'operation': 'finalize-custody'})
        raise OSError('Intentional custody finalization failure')
    return normal_write_custody(value)
