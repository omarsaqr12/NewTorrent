# Local real-socket benchmark

Application response delay on loopback; whole-harness CPU/RSS. Failed configurations remain in the table. Medians include failed durations.

| Experiment | MiB | Config | Success | Wall median (min–max), s | Median requested bytes | Revalidation median, s |
|---|---:|---|---:|---:|---:|---:|
| peers | 64 | four | 5/5 | 5.400 (5.143–7.224) | 67108864 | 0.0000 |
| peers | 64 | one | 5/5 | 15.722 (15.548–18.707) | 67108864 | 0.0000 |
