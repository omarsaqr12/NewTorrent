"""Run checks, a local swarm and interoperability; write logs to .validation/."""
import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    python = sys.executable
    cli = str(Path(python).with_name('newtorrent.exe' if os.name == 'nt' else 'newtorrent'))
    commands = [
        [python, '-m', 'pip', 'check'],
        [python, '-m', 'ruff', 'check', '.'],
        [python, '-m', 'compileall', '-q', 'app', 'tools', 'tests', 'benchmark.py'],
        [cli, '--help'], [cli, 'decode', 'd3:foo3:bare'], [cli, 'info', 'sample.torrent'],
        [python, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
        [python, '-m', 'tools.swarm'],
        [python, '-m', 'tools.interop', '--output', '.validation/interop.json'],
        [python, '-m', 'tools.summarize', 'benchmarks/local'],
        [python, '-m', 'tools.summarize', 'benchmarks/large'],
    ]
    output = Path('.validation')
    output.mkdir(exist_ok=True)
    records = []
    env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
    with open(output / 'output.txt', 'w', encoding='utf-8') as log:
        for command in commands:
            print('Running: ' + ' '.join(command[1:]), flush=True)
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                                    errors='replace', timeout=120, env=env)
            log.write('$ ' + ' '.join(command) + '\n' + result.stdout + result.stderr +
                      f'\nexit={result.returncode}\n\n')
            log.flush()
            records.append({'command': command, 'exit_code': result.returncode})
            if result.returncode:
                print(result.stdout + result.stderr)
                raise SystemExit(result.returncode)
    (output / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    result = subprocess.run([python, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True, env=env)
    (output / 'environment.txt').write_text(result.stdout)
    print('All clean-environment checks passed.', flush=True)


if __name__ == '__main__':
    main()
