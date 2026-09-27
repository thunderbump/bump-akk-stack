"""Exact outcomes for the five fixed C++ runner controls; no process execution."""
import json

EXPECTED = {
    'pass': (0, 1, 1, 1, 0, True, True),
    'fail': (1, 1, 1, 1, 1, True, False),
    'empty': (1, 0, 0, 0, 0, True, False),
    'setup-exception': (1, 1, 1, 0, 0, False, False),
    'body-exception': (1, 1, 1, 1, 1, True, False),
}


def control_result(output, exit_code, mode):
    if len(output) > 1024**2: raise ValueError('Control output budget')
    lines = [line.removeprefix('EQEMU_TEST_RESULT ') for line in output.splitlines()
             if line.startswith('EQEMU_TEST_RESULT ')]
    if len(lines) != 1 or len(lines[0]) > 2048: raise ValueError('Control completion missing/duplicated')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('Duplicate control field')
            value[key] = item
        return value
    result = json.loads(lines[0], object_pairs_hook=unique)
    keys = ['version', 'selected', 'started', 'completed', 'failed', 'finalized', 'passed']
    if not isinstance(result, dict) or set(result) != set(keys): raise ValueError('Control completion shape')
    if any(type(result[k]) is not int for k in keys[:5]) or any(type(result[k]) is not bool for k in keys[5:]):
        raise ValueError('Control completion types')
    if result['version'] != 1 or (exit_code, *(result[k] for k in keys[1:])) != EXPECTED[mode]:
        raise ValueError('Unexpected control outcome: ' + mode)
    return dict(result, exit_code=exit_code)
