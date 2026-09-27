"""Bounded diagnostic data and utility completion acceptance, with no process-kill policy."""
import json


class DiagnosticTail:
    def __init__(self, secrets=(), limit=32768):
        if not 0 < limit <= 32768 or len(secrets) > 16 or any(len(s) > 1024 for s in secrets):
            raise ValueError('Diagnostic bounds')
        self.secrets = [s.encode() for s in secrets if s]
        self.limit = limit
        self.capacity = limit + max(map(len, self.secrets), default=0)
        self.data = b''
        self.total = 0

    def feed(self, chunk):
        self.total += len(chunk)
        self.data = (self.data + chunk[-self.capacity:])[-self.capacity:]

    def export(self):
        data = self.data
        for secret in sorted(self.secrets, key=len, reverse=True):
            data = data.replace(secret, b'[redacted]')
        # Truncate decoded text by encoded bytes, including replacement characters.
        text = ''.join(c if c in '\n\t' or ord(c) >= 32 and not 127 <= ord(c) <= 159 else '?'
                       for c in data.decode('utf-8', 'replace'))
        encoded = text.encode()
        text = encoded[-self.limit:].decode('utf-8', 'ignore')
        return {'text': text, 'input_bytes': self.total,
                'retained_bytes': len(text.encode()), 'truncated': self.total > self.limit}



def utility_result(output, exit_code):
    if len(output) > 1024 * 1024:
        raise ValueError('Utility output budget')
    lines = [line[len('EQEMU_TEST_RESULT '):] for line in output.splitlines()
             if line.startswith('EQEMU_TEST_RESULT ')]
    if len(lines) != 1 or len(lines[0]) > 2048:
        raise ValueError('Missing or duplicate utility completion')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate completion key')
            result[key] = value
        return result
    result = json.loads(lines[0], object_pairs_hook=unique)
    if not isinstance(result, dict) or type(result.get('version')) is not int or result.get('version') != 1:
        raise ValueError('Completion version')
    for key in ['selected', 'started', 'completed', 'failed']:
        if type(result.get(key)) is not int or not 0 <= result[key] <= 1000000:
            raise ValueError('Completion count')
    passed = (exit_code == 0 and result.get('passed') is True and result.get('finalized') is True
              and result['selected'] > 0 and result['selected'] == result['started'] == result['completed']
              and result['failed'] == 0)
    if not passed:
        raise ValueError('Utility suite failed or incomplete')
    return result
