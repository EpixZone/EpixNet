#!/usr/bin/env python3
"""Replay only the runtime fixture against hash-verified prior QA binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert re.fullmatch(r'[1-9][0-9]{0,15}', args.run)
    assert re.fullmatch(r'[0-9a-f]{40}', args.revision)
    repository = os.environ['GITHUB_REPOSITORY']
    run = json.loads(subprocess.check_output([
        'gh', 'api', f'repos/{repository}/actions/runs/{args.run}'], text=True))
    assert run['status'] == 'completed', 'prior run has not finished'
    assert run['head_branch'] == 'test/windows-data-directory', 'not the owned QA branch'
    artifacts = json.loads(subprocess.check_output([
        'gh', 'api', f'repos/{repository}/actions/runs/{args.run}/artifacts'], text=True))
    name = f'issue-649-windows-candidate-{args.run}-{run["run_attempt"]}'
    matching = [item for item in artifacts['artifacts'] if item['name'] == name]
    assert len(matching) == 1 and not matching[0]['expired'], 'exact artifact unavailable'
    artifact = matching[0]
    assert artifact['size_in_bytes'] < 2 * 1024**3, 'artifact exceeds replay bound'
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', ''))
    output = args.output.resolve()
    prior = output / 'reused-artifact'
    subprocess.run(['gh', 'run', 'download', args.run, '--repo', repository,
                    '--name', name, '--dir', str(prior)], check=True, timeout=240)
    build_path = prior / 'candidate-build.json'
    build = json.loads(build_path.read_text(encoding='utf-8-sig'))
    assert build['source_revision'] == args.revision, 'candidate source differs'
    assert build['status'] == 'passed' and build['tracked_source_unchanged'] is True
    binaries = build['binaries']
    assert {'epix-browser.exe', 'epix-nmh.exe'} <= set(binaries)
    target = output / 'candidate-binaries'
    target.mkdir()
    for filename, recorded in binaries.items():
        assert re.fullmatch(r'epix-(browser|nmh)\.exe|epix_snowflake-[A-Za-z0-9_-]+\.dll', filename)
        source = prior / 'candidate-binaries' / filename
        assert source.is_file() and source.stat().st_size == recorded['bytes']
        assert digest(source) == recorded['sha256'], 'binary digest differs from original build'
        shutil.copy2(source, target / filename)
    shutil.copy2(build_path, output / 'reused-candidate-build.json')
    if (prior / 'native-pac-tests.log').is_file():
        shutil.copy2(prior / 'native-pac-tests.log', output / 'prior-native-pac-tests.log')
    record = {
        'scope': 'Runtime-only replay. Compilation and native source tests are not rerun; fresh final acceptance remains required.',
        'source_revision': args.revision,
        'prior_run': int(args.run), 'prior_run_url': run['html_url'],
        'prior_qa_revision': run['head_sha'],
        'artifact': {key: artifact[key] for key in ('id', 'name', 'size_in_bytes', 'digest')},
        'build_report_sha256': digest(build_path), 'binaries': binaries,
    }
    (output / 'reused-candidate-provenance.json').write_text(json.dumps(record, indent=2) + '\n')
    shutil.rmtree(prior)
    print(json.dumps({'verified_source': args.revision, 'binaries': list(binaries)}))


if __name__ == '__main__':
    main()
