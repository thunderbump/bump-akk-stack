"""Pure readelf-text/data regressions; no ELF or toolchain program executes."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'validation/worker'))
import staging_container as container

HEADER = 'Class: ELF64\nMachine: Advanced Micro Devices X86-64\n'


def text(needed=(), defined=(), undefined=(), versions=()):
    raw = HEADER + ''.join(' (NEEDED) Shared library: [' + name + ']\n' for name in needed)
    for index, name in enumerate(defined): raw += f' {index}: 0000 1 FUNC GLOBAL DEFAULT 12 {name}\n'
    for index, name in enumerate(undefined): raw += f' {index}: 0000 0 FUNC GLOBAL DEFAULT UND {name}\n'
    raw += "Version definition section '.gnu.version_d':\n"
    for name in versions: raw += ' Index: 2 Cnt: 1 Name: ' + name + '\n'
    return raw


def consumer(needed, undefined, version_needs=None):
    facts = container.readelf_facts(text(needed=needed, undefined=undefined))
    facts['interpreter'] = ['/lib64/ld-linux-x86-64.so.2']
    facts['version_needs'] = version_needs or {}
    return facts


def fixture_inventory():
    libraries = {
        'lib/root.so': {'sha256': '1' * 64, 'elf': dict(needed=['leaf.so'], soname=['root.so'], defined_dynamic_symbols=['root'], version_definitions=['V1'])},
        'lib/leaf.so': {'sha256': '2' * 64, 'elf': dict(needed=[], soname=['leaf.so'], defined_dynamic_symbols=['known'], version_definitions=['V1', 'V2'])},
    }
    facts = {
        'lib/root.so': container.readelf_facts(text(needed=['leaf.so'], defined=['root@@V1'], versions=['V1'])),
        'lib/leaf.so': container.readelf_facts(text(defined=['known@@V1'], versions=['V1', 'V2'])),
    }
    for path, value in facts.items(): value['sha256'] = libraries[path]['sha256']
    return dict(runtime_libraries=libraries, provider_facts=facts)


class AbiResolution(unittest.TestCase):
    def test_actual_inventory_unrelated_uuid_provider_cannot_resolve_libc_consumer(self):
        path = Path('/home/bump/.local/state/eqemu-cdau-staging-deploy/20261106-build-export-inputs-v1/RUNTIME-ABI-AND-LIBRARY-INVENTORY.json')
        if not path.exists(): self.skipTest('sealed external runtime data unavailable')
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '7fca16dfa0b22a568d6b01b5d25cb1ecdc64f2171fbf43f79546a0c708118615')
        inventory = json.loads(raw)
        self.assertIn('uuid_generate', inventory['runtime_libraries']['usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0']['elf']['defined_dynamic_symbols'])
        self.assertEqual(inventory['runtime_libraries']['usr/lib/x86_64-linux-gnu/libc.so.6']['elf']['needed'], ['ld-linux-x86-64.so.2'])
        # Actual pinned dependency edges; synthetic text supplies only the relevant symbol facts.
        inventory['provider_facts'] = {}
        for name, entry in inventory['runtime_libraries'].items():
            defined = ['uuid_generate@@UUID_1.0'] if 'libuuid' in name else []
            facts = container.readelf_facts(text(needed=entry['elf']['needed'], defined=defined,
                                                 versions=entry['elf']['version_definitions']))
            facts['sha256'] = entry['sha256']; inventory['provider_facts'][name] = facts
        with self.assertRaisesRegex(ValueError, 'release-unresolved-symbol'):
            container.check_abi(consumer(['libc.so.6'], ['uuid_generate']), inventory)

    def test_name_and_version_nodes_do_not_prove_symbol_export_at_required_version(self):
        inventory = fixture_inventory()
        with self.assertRaisesRegex(ValueError, 'release-unresolved-symbol'):
            container.check_abi(consumer(['root.so'], ['known@V2'], {'leaf.so': ['V2']}), inventory)

    def test_valid_transitive_versioned_and_default_resolution(self):
        inventory = fixture_inventory()
        container.check_abi(consumer(['root.so'], ['known@V1'], {'leaf.so': ['V1']}), inventory)
        container.check_abi(consumer(['root.so'], ['known']), inventory)

    def test_nondefault_version_resolves_only_matching_version(self):
        inventory = fixture_inventory()
        inventory['provider_facts']['lib/leaf.so']['defined'] = ['known@V2']
        container.check_abi(consumer(['root.so'], ['known@V2'], {'leaf.so': ['V2']}), inventory)
        with self.assertRaises(ValueError): container.check_abi(consumer(['root.so'], ['known']), inventory)

    def test_guest_derivation_uses_verified_bytes_not_inventory_symbol_names(self):
        inventory = dict(runtime_libraries={'lib/leaf.so': dict(sha256='a' * 64,
            elf=dict(needed=[], soname=['leaf.so'], defined_dynamic_symbols=['invented'], version_definitions=['V1', 'V2']))})
        output = text(defined=['known@@V1', 'known@V2'], versions=['V1', 'V2']).encode()
        with patch.object(container, 'sha', side_effect=['a' * 64, 'a' * 64]) as digest, patch.object(container, 'run', return_value=output) as readelf:
            result = container.derive_provider_facts(inventory)
            self.assertEqual(result['lib/leaf.so']['defined'], ['known@@V1', 'known@V2'])
            self.assertEqual(digest.call_count, 2)
            readelf.assert_called_once_with(['readelf', '-W', '-h', '-l', '-d', '-V', '--dyn-syms', '/lib/leaf.so'])
        with patch.object(container, 'sha', side_effect=['a' * 64, 'b' * 64]), patch.object(container, 'run', return_value=output):
            with self.assertRaisesRegex(ValueError, 'library-bytes'): container.derive_provider_facts(inventory)

    def test_missing_associations_unknown_edges_and_hashes_fail_closed(self):
        inventory = fixture_inventory()
        facts = consumer(['root.so'], ['known'])
        for change in ('missing', 'hash', 'edge'):
            altered = copy.deepcopy(inventory)
            if change == 'missing': altered.pop('provider_facts')
            elif change == 'hash': altered['provider_facts']['lib/leaf.so']['sha256'] = '0' * 64
            else: altered['provider_facts']['lib/root.so']['needed'] = ['unseen.so']
            with self.assertRaises(ValueError): container.check_abi(facts, altered)


if __name__ == '__main__': unittest.main()
