#!/usr/bin/python3 -I
"""Prepare a verified installer from maintained recipes and explicit public inputs."""
import argparse
import json
import hashlib
import stat
import os
from pathlib import Path
import shutil
import sys
import tempfile
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, load, sha

RUNTIME = ('common.py', 'render.py', 'host.py', 'candidate.py', 'install.py',
           'disable.py', 'host_support.py', 'installer_support.py', 'inputs.py', 'profile.json')
RECIPES = ('producer-user.json', 'consumer-user.json', 'producer-guest.py', 'consumer-guest.py', 'producer-worker.py.in',
           'consumer-worker.py.in', 'suite.py.in', 'recipe-binding.json')


def file_digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256*1024:
            raise ValueError('Not a bounded recipe file: '+str(path))
        data = stream.read(256*1024+1)
        if len(data) != info.st_size:
            raise ValueError('Recipe changed while reading')
    return data, hashlib.sha256(data).hexdigest()


def verified_sources(package=HERE):
    """Require the fixed recipe file set and checked-in seals before copying code."""
    raw, _ = file_digest(package/'recipe-manifest.json')
    manifest = json.loads(raw)
    names = set(RUNTIME) | {'recipes/'+name for name in RECIPES}
    if type(manifest.get('version')) is not int or manifest.get('version') != 1 or set(manifest.get('files', {})) != names:
        raise ValueError('Unexpected recipe manifest')
    for name, digest in manifest['files'].items():
        _, actual = file_digest(package/name)
        if actual != digest:
            raise ValueError('Recipe identity mismatch: '+name)
    return manifest


def prepare(output, input_store, websocketpp, package=HERE):
    if os.geteuid() == 0:
        raise ValueError('Prepare as the normal user')
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists')
    store = Path(input_store).resolve(strict=True)
    websocketpp = Path(websocketpp).resolve(strict=True)
    if any(output.is_relative_to(path) for path in (store, websocketpp, package.resolve())):
        raise ValueError('Output must be outside dependency and package directories')
    manifest = verified_sources(package)
    inputs = load('preparation_inputs', package/'inputs.py')
    profile = json.loads((package/'profile.json').read_text())
    inputs.check_dependencies(profile, store)
    with tempfile.TemporaryDirectory(prefix='eqemu-package-') as scratch:
        view = inputs.GitTree(websocketpp, Path(scratch))
        wanted = profile['sources']['websocketpp']
        entries, links = view.inventory(wanted['commit'], wanted['tree'])
        if links != wanted['gitlinks']:
            raise ValueError('Websocketpp submodule identity mismatch')
        view.clean(wanted['commit'], entries, links)
    output.mkdir(mode=0o700)
    try:
        for name in RUNTIME:
            shutil.copyfile(package/name, output/name)
        for name in RECIPES:
            shutil.copyfile(package/'recipes'/name, output/name)
        host_inputs = {name: dict(source=str(store/profile['dependencies'][key]['path']),
                                  **{k: profile['dependencies'][key][k] for k in ('bytes', 'sha256')})
                       for name, key in [('base.qcow2', 'base'), ('fixture.iso', 'media')]}
        (output/'host-inputs.json').write_text(json.dumps(host_inputs, indent=2)+'\n')
        (output/'client-config.json').write_text(json.dumps(dict(input_store=str(store),
                                                               websocketpp=str(websocketpp)), indent=2)+'\n')
        # Verify copied bytes against the original seals, including a racing change.
        for name, digest in manifest['files'].items():
            if sha(output/Path(name).name) != digest:
                raise ValueError('Recipe changed during copy: '+name)
        installed = {'version': 1, 'files': {p.name: sha(p) for p in sorted(output.iterdir())}}
        (output/'manifest.json').write_text(json.dumps(installed, indent=2, sort_keys=True)+'\n')
    except BaseException:
        shutil.rmtree(output)
        raise
    return {'prepared': str(output), 'manifest_sha256': sha(output/'manifest.json'), 'vm_started': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--input-store', type=Path, required=True)
    parser.add_argument('--websocketpp', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.input_store, args.websocketpp)))
