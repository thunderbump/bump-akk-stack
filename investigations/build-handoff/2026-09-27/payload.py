"""Fixed four-executable payload policy. Guest paths never become host actions."""
import hashlib
import json
import re

NAMES = {'world', 'zone', 'shared_memory', 'tests'}


def manifest_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_payload(value, identity):
    # validate_inventory is the existing bounded flat-file policy, included by preparation.
    entries = validate_inventory(value, identity)
    if {entry['path'] for entry in entries} != NAMES or len(entries) != 4:
        raise ValueError('Expected four executable files')
    libraries = value.get('libraries')
    if not isinstance(libraries, list) or not 1 <= len(libraries) <= 128:
        raise ValueError('Library inventory size')
    seen = set()
    for entry in libraries:
        if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                or not re.fullmatch(r'/usr/lib/x86_64-linux-gnu/[A-Za-z0-9_.+-]+', entry['path'])
                or entry['path'] in seen or type(entry.get('bytes')) is not int or not 0 < entry['bytes'] <= 1024**3
                or not isinstance(entry.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256'])):
            raise ValueError('Invalid system library identity')
        seen.add(entry['path'])
    if not isinstance(value.get('build'), dict) or not isinstance(value.get('preflight'), dict):
        raise ValueError('Build provenance missing')
    if value['preflight'].get('after_status') is None:
        raise ValueError('Package identity missing')
    return entries


def parse_manifest(data, identity, expected_sha):
    if len(data) > 262144 or hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError('Artifact manifest identity/size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate manifest field')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    validate_payload(value, identity)
    return value
