#!/usr/bin/env python3
import os
import subprocess

PLUGIN_NAME = 'secretsmanager'

def main():
    version = os.environ.get('PLUGIN_VERSION')
    if not version:
        print('missing environment variables: PLUGIN_VERSION')
        exit(1)
    
    build_dir_path = 'builds'
    os.mkdir(build_dir_path)

    plugin_os = os.environ.get('GOOS') or 'linux'
    plugin_arch = os.environ.get('GOARCH') or 'amd64'
    envs = os.environ.copy()
    envs['GOOS'] = plugin_os.lower()
    envs['GOARCH'] = plugin_arch
    build_file = '{}/{}'.format(build_dir_path, PLUGIN_NAME)
    out = subprocess.run(['go', 'build', '-o', build_file, '.'],
        env=envs)

    if out.returncode > 0:
        exit(out.returncode)
    
    tarfile = '{}-{}-{}-{}.tar.gz'.format(
        PLUGIN_NAME,
        version,
        plugin_os,
        plugin_arch)
    out = subprocess.run(['tar', '-czf', tarfile, '-C', build_dir_path, PLUGIN_NAME])
    tarfile_path = '{}/{}'.format(build_dir_path, tarfile)
    os.rename(tarfile, tarfile_path)
    
    exit(out.returncode)

if __name__ == '__main__':
    main()
