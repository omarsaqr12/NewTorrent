"""Regenerate honest summary tables and charts from retained raw JSONL."""
import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path


def summarize(root: Path):
    groups = defaultdict(list)
    for line in (root / 'raw.jsonl').read_text().splitlines():
        row = json.loads(line)
        groups[(row['experiment'], row['size_bytes'], row['config'])].append(row)
    summary, lines = [], ['# Local real-socket benchmark', '',
                         'Application response delay on loopback; whole-harness CPU/RSS. '
                         'Failed configurations remain in the table. Medians include failed durations.', '',
                         '| Experiment | MiB | Config | Success | Wall median (min–max), s | '
                         'Median requested bytes | Revalidation median, s |',
                         '|---|---:|---|---:|---:|---:|---:|']
    for (case, size, config), rows in sorted(groups.items()):
        durations = [r['wall_seconds'] for r in rows if 'wall_seconds' in r]
        measured = [r for r in rows if 'wall_seconds' in r]
        result = dict(experiment=case, size_bytes=size, config=config,
                      successes=sum(r['status'] == 'ok' for r in rows), trials=len(rows),
                      median_wall=statistics.median(durations) if durations else None,
                      min_wall=min(durations) if durations else None, max_wall=max(durations) if durations else None)
        for metric in ('requested_bytes', 'duplicate_bytes', 'resumed_bytes', 'revalidation_seconds',
                       'peak_rss_bytes', 'cpu_seconds', 'goodput_bytes_second', 'peak_pending', 'peak_active'):
            values = [r[metric] for r in measured if metric in r]
            result['median_' + metric] = statistics.median(values) if values else None
        summary.append(result)
        if durations:
            lines.append(f'| {case} | {size // 1048576} | {config} | {result["successes"]}/{len(rows)} | '
                         f'{result["median_wall"]:.3f} ({result["min_wall"]:.3f}–{result["max_wall"]:.3f}) | '
                         f'{result["median_requested_bytes"]} | {result["median_revalidation_seconds"]:.4f} |')
        else:
            lines.append(f'| {case} | {size // 1048576} | {config} | 0/{len(rows)} | unavailable | — | — |')
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    (root / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    sizes = sorted({r['size_bytes'] for r in summary})
    fig, axes = plt.subplots(len(sizes), 1, figsize=(12, 4 * len(sizes)), squeeze=False)
    for axis, size in zip(axes[:, 0], sizes):
        entries = [r for r in summary if r['size_bytes'] == size and r['median_wall'] is not None]
        labels = [f'{r["experiment"]}\n{r["config"]}\n{r["successes"]}/{r["trials"]} ok' for r in entries]
        axis.bar(labels, [r['median_wall'] for r in entries],
                 color=['#226a9e' if r['successes'] == r['trials'] else '#b55836' for r in entries])
        axis.set_title(f'{size // 1048576} MiB, loopback application delay (failures included)')
        axis.set_ylabel('Median wall seconds')
        axis.tick_params(axis='x', labelsize=8)
    fig.tight_layout()
    fig.savefig(root / 'wall-time.png', dpi=160)
    plt.close(fig)
    print('\n'.join(lines))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', default='benchmarks/local')
    summarize(Path(parser.parse_args().directory))
