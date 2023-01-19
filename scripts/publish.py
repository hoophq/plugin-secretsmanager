#!/usr/bin/env python3
import os
import subprocess
import hashlib
from urllib.request import urlopen
import json
import datetime

PLUGIN_NAME = 'secretsmanager'
S3_BUCKET = 'pluginregistry'
PLUGIN_REGISTRY_URL = 'https://{}.s3.amazonaws.com'.format(S3_BUCKET)
PKG_NAME = 'hoop/{}'.format(PLUGIN_NAME)


def compute_digest(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_packages_manifest(url):
    with urlopen(url) as resp:
        return json.loads(resp.read())

def main():
    version = os.environ.get('PLUGIN_VERSION')
    if not version:
        print('missing environment variables: PLUGIN_VERSION')
        exit(1)

    plugin_arch = os.environ.get('GOARCH') or 'amd64'
    plugin_os = os.environ.get('GOOS') or 'Linux'
        

    binary_file = './builds/{}'.format(PLUGIN_NAME)
    tarfile = '{}-{}-{}-{}.tar.gz'.format(
            PLUGIN_NAME,
            version,
            plugin_os,
            plugin_arch)
    tarfile_path = './builds/'+tarfile
    finfo = os.stat(binary_file)

    pkg_digest = compute_digest(tarfile_path)
    binary_digest = compute_digest(binary_file)
    packages_manifest_path = '{}/packages.json'.format(PLUGIN_REGISTRY_URL)
    pkgpath = '{}/{}/{}'.format(PKG_NAME, version, tarfile)
    now = datetime.datetime.utcnow()
    print('--> downloading packages.json manifest')
    # Download the file from `url` and save it locally under `file_name`:

    packages = get_packages_manifest(packages_manifest_path)
    pkgsection = packages.get(PKG_NAME)
    plugin_manifest = {
        'name': PLUGIN_NAME,
        'version': version,
        'size': finfo.st_size,
        'digest': 'sha256:{}'.format(binary_digest),
        'url': '{}/{}'.format(PLUGIN_REGISTRY_URL, pkgpath),
        'created_at': now.isoformat('T')+'Z',
        'platform': {
            'architecture': plugin_arch,
            'os': plugin_os,
        }
    }
    if pkgsection:
        pkgsection['versions'].insert(0, plugin_manifest)
    else:
        packages[PKG_NAME] = {'versions': [plugin_manifest]}
    with open('/tmp/packages.json', 'w+') as w:
        w.write(json.dumps(packages))

    print('--> uploading package {}'.format(tarfile_path))
    envs = os.environ.copy()
    out = subprocess.run(['aws', 's3', 'cp',
        tarfile_path,
        's3://{}/{}'.format(S3_BUCKET, pkgpath)], env=envs)
    if out.returncode > 0:
        exit(out.returncode)
    
    print('--> uploading packages.json manifest')
    
    out = subprocess.run(['aws', 's3', 'cp',
        '/tmp/packages.json',
        's3://{}/packages.json'.format(S3_BUCKET)], env=envs)
    if out.returncode > 0:
        exit(out.returncode)
    print('--> published')
    print(json.dumps(plugin_manifest, indent=2))

if __name__ == '__main__':
    main()
