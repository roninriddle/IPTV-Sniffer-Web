"""Reject version/tag drift before any registry credentials or publish step."""
import argparse
import ast
import os
from pathlib import Path
import re
import subprocess


def check(root, tag=None):
    tree = ast.parse((root / 'config.py').read_text())
    version = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'APP_VERSION' for t in n.targets))
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-test)?', version):
        raise ValueError('Unsupported project version')
    for filename in ('docker-compose.yml', 'docker-bake.hcl'):
        tags = re.findall(r'roninriddle/iptv-sniffer-web:([\w.-]+)', (root/filename).read_text())
        if tags != [version]:
            raise ValueError(f'{filename} version differs from config.py')
    if tag and tag.removeprefix('v') != version:
        raise ValueError('Release tag does not match APP_VERSION')
    if os.environ.get('GITHUB_SHA'):
        actual = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
        expected = subprocess.check_output(['git','rev-parse',os.environ['GITHUB_SHA']+'^{commit}'],cwd=root,text=True).strip()
        if actual != expected:
            raise ValueError('Checkout differs from the tested event SHA')
    return version


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag')
    args = parser.parse_args()
    print(check(Path(__file__).resolve().parents[1], args.tag))
