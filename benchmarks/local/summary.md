# Local real-socket benchmark

Application response delay on loopback; whole-harness CPU/RSS. Failed configurations remain in the table. Medians include failed durations.

| Experiment | MiB | Config | Success | Wall median (min–max), s | Median requested bytes | Revalidation median, s |
|---|---:|---|---:|---:|---:|---:|
| endgame | 1 | off | 5/5 | 0.548 (0.544–0.560) | 1048576 | 0.0000 |
| endgame | 1 | on | 5/5 | 0.361 (0.281–0.377) | 1064960 | 0.0000 |
| peers | 1 | four | 5/5 | 0.204 (0.171–0.257) | 1048576 | 0.0000 |
| peers | 1 | one | 5/5 | 0.369 (0.310–0.384) | 1048576 | 0.0000 |
| pipeline | 1 | window1 | 5/5 | 1.151 (1.094–1.350) | 1048576 | 0.0000 |
| pipeline | 1 | window5 | 5/5 | 0.381 (0.309–2.617) | 1048576 | 0.0000 |
| resume | 1 | resume | 5/5 | 0.754 (0.639–0.834) | 655360 | 0.0310 |
| resume | 1 | scratch | 5/5 | 1.233 (1.073–1.360) | 1048576 | 0.0000 |
| scheduling | 1 | rarest | 5/5 | 0.539 (0.478–0.611) | 1114112 | 0.0000 |
| scheduling | 1 | sequential | 0/5 | 4.565 (4.526–4.663) | 1048576 | 0.0000 |
