# Process matcher benchmarks

Measured for the process path glob matcher (see [process lists](../process-lists.md)).
Before is the exact-only matcher on `main` (`30e9bc8f`), after is the glob
index. Same machine (AMD Ryzen 5 5600G, Linux, go1.27.4), same benchmark file
(`pkg/route/process_matcher_benchmark_test.go`, byte-identical in both trees;
only the small adapter that builds the matcher differs), runs interleaved
before/after, `-count=10 -benchtime=0.5s`, compared with `benchstat`.

```bash
go test ./pkg/route -run '^$' -bench 'BenchmarkProcessMatcher' -benchmem -count=10
```

**Read the glob rows carefully.** The old matcher had no glob support: it
stored `/opt/app/**` as a literal string, so its "glob hit" numbers are the
cost of an exact *miss* and it returned no match. Those rows show the price of
actually evaluating patterns, not a slowdown of equal work.

Every lookup allocates nothing, before and after (0 B/op, 0 allocs/op in all
lookup benchmarks).

## Summary

- **Exact-only lists** (no globs anywhere): an exact hit got ~27–30% faster
  (≈24 → 17 ns; plain map, no lock). An exact miss costs ≈+18 ns (≈20 → 37 ns):
  the path is checked for redundant separators, `.` and `..` before the
  canonical lookup.
- **Once any glob exists**, every lookup also probes the glob index, about
  80–150 ns for typical paths (5–8 components) and up to ≈0.3 µs for long
  Windows paths with case folding. This is per *connection* with process
  lookup enabled, next to a socket table lookup that costs microseconds.
- **Independent of pattern count**: a glob hit is ≈149 ns with 1 pattern and
  ≈149 ns with 10,000; globs are never scanned linearly (largest index bucket
  in the benchmark mix: 1 pattern, fallback scan: 0 patterns).
- Cost grows with path depth instead (one probe per component):
  `deep` (20 components) ≈0.44 µs, `many_components` (61) ≈0.61 µs,
  `long_windows` (≈250 characters, folded) ≈0.93 µs.
- **Parallel lookups** got faster (exact hit 27.9 → 13.7 ns): the installed
  index is read through an atomic pointer instead of a read-write mutex.
- **Configuration time**: building 10,000 globs takes ≈17 ms (was ≈4 ms for
  10,000 literal strings) and retains ≈4.1 MiB (≈475 B per pattern); 10,000
  exact paths retain ≈1.2 MiB (was ≈1.6 MiB).

### Lookup by pattern count (ns/op)

| Benchmark | before | after | Δ |
| --- | ---: | ---: | ---: |
| `n=1/exact/hit` | 23.68n | 16.49n | -30.36% |
| `n=1/exact/miss` | 17.64n | 37.02n | +109.78% |
| `n=1/glob/hit` | 17.66n | 148.80n | +742.58% |
| `n=1/glob/deep_hit` | 18.11n | 242.80n | +1240.33% |
| `n=1/glob/miss` | 17.62n | 107.10n | +507.83% |
| `n=1/glob/similar_miss` | 17.68n | 91.75n | +419.09% |
| `n=1/mixed/exact_hit` | 23.73n | 16.47n | -30.58% |
| `n=1/mixed/glob_hit` | 17.69n | 37.06n | +109.53% |
| `n=1/mixed/miss` | 17.68n | 47.12n | +166.56% |
| `n=10/exact/hit` | 23.75n | 17.37n | -26.88% |
| `n=10/exact/miss` | 19.75n | 36.52n | +84.89% |
| `n=10/glob/hit` | 21.71n | 149.05n | +586.71% |
| `n=10/glob/deep_hit` | 22.45n | 243.85n | +985.95% |
| `n=10/glob/miss` | 22.66n | 107.60n | +374.85% |
| `n=10/glob/similar_miss` | 18.28n | 98.38n | +438.33% |
| `n=10/mixed/exact_hit` | 23.72n | 143.15n | +503.50% |
| `n=10/mixed/glob_hit` | 17.92n | 194.85n | +987.33% |
| `n=10/mixed/miss` | 18.17n | 168.80n | +829.26% |
| `n=100/exact/hit` | 24.57n | 17.32n | -29.52% |
| `n=100/exact/miss` | 22.18n | 36.55n | +64.77% |
| `n=100/glob/hit` | 18.59n | 149.00n | +701.29% |
| `n=100/glob/deep_hit` | 18.60n | 243.85n | +1211.02% |
| `n=100/glob/miss` | 18.14n | 107.50n | +492.61% |
| `n=100/glob/similar_miss` | 22.14n | 98.98n | +347.09% |
| `n=100/mixed/exact_hit` | 25.66n | 98.51n | +283.90% |
| `n=100/mixed/glob_hit` | 22.19n | 166.00n | +648.08% |
| `n=100/mixed/miss` | 18.40n | 120.10n | +552.54% |
| `n=1000/exact/hit` | 25.82n | 18.77n | -27.31% |
| `n=1000/exact/miss` | 22.42n | 39.48n | +76.09% |
| `n=1000/glob/hit` | 22.89n | 150.10n | +555.89% |
| `n=1000/glob/deep_hit` | 23.10n | 245.10n | +961.04% |
| `n=1000/glob/miss` | 22.29n | 107.70n | +383.28% |
| `n=1000/glob/similar_miss` | 18.74n | 98.74n | +426.92% |
| `n=1000/mixed/exact_hit` | 24.84n | 98.62n | +296.96% |
| `n=1000/mixed/glob_hit` | 18.61n | 104.70n | +462.45% |
| `n=1000/mixed/miss` | 20.37n | 112.30n | +451.30% |
| `n=10000/exact/hit` | 25.64n | 18.64n | -27.28% |
| `n=10000/exact/miss` | 19.20n | 39.69n | +106.80% |
| `n=10000/glob/hit` | 19.15n | 149.40n | +680.16% |
| `n=10000/glob/deep_hit` | 19.80n | 245.15n | +1138.13% |
| `n=10000/glob/miss` | 19.18n | 110.00n | +473.36% |
| `n=10000/glob/similar_miss` | 19.18n | 99.91n | +420.88% |
| `n=10000/mixed/exact_hit` | 27.47n | 103.70n | +277.43% |
| `n=10000/mixed/glob_hit` | 19.14n | 104.90n | +447.92% |
| `n=10000/mixed/miss` | 21.47n | 114.35n | +432.60% |
### Lookup shapes, 2,000 background entries (ns/op)

| Benchmark | before | after | Δ |
| --- | ---: | ---: | ---: |
| `exact/hit` | 23.26n | 89.50n | +284.78% |
| `exact/miss` | 22.75n | 84.66n | +272.13% |
| `exact/multi_list_hit` | 23.32n | 91.17n | +290.85% |
| `directory/hit` | 19.32n | 155.00n | +702.49% |
| `directory/deep_hit` | 19.23n | 216.20n | +1024.58% |
| `directory/similar_miss` | 18.61n | 100.30n | +438.81% |
| `glob/any_depth_hit` | 19.12n | 149.45n | +681.64% |
| `glob/any_depth_similar_miss` | 18.66n | 109.15n | +484.78% |
| `glob/partial_component_hit` | 18.64n | 190.55n | +922.54% |
| `glob/partial_component_miss` | 18.67n | 180.00n | +864.11% |
| `glob/middle_double_star_hit` | 22.61n | 179.85n | +695.27% |
| `glob/miss` | 18.71n | 119.65n | +539.33% |
| `windows/exact_hit` | 23.21n | 158.80n | +584.19% |
| `windows/exact_case_hit` | 18.60n | 158.75n | +753.72% |
| `windows/exact_miss` | 18.68n | 161.25n | +762.99% |
| `windows/drive_fixed_hit` | 19.75n | 320.20n | +1521.27% |
| `windows/drive_case_hit` | 19.17n | 320.95n | +1574.23% |
| `windows/drive_other_miss` | 19.23n | 271.95n | +1314.20% |
| `windows/any_drive_hit` | 19.17n | 256.50n | +1237.68% |
| `windows/unc_hit` | 19.16n | 311.50n | +1525.36% |
| `windows/extended_hit` | 19.25n | 319.10n | +1557.66% |
### Path length and depth (ns/op)

| Benchmark | before | after | Δ |
| --- | ---: | ---: | ---: |
| `short` | 23.50n | 72.46n | +208.27% |
| `application` | 19.20n | 157.85n | +722.14% |
| `deep` | 21.00n | 444.35n | +2015.45% |
| `many_components` | 20.22n | 607.25n | +2903.21% |
| `long_windows` | 21.87n | 925.05n | +4130.73% |
### Parallel lookups through Lists, 12 goroutines (ns/op)

| Benchmark | before | after | Δ |
| --- | ---: | ---: | ---: |
| `exact_hit` | 27.90n | 13.73n | -50.79% |
| `glob_hit` | 27.93n | 24.60n | -11.91% |
| `miss` | 27.91n | 15.43n | -44.71% |
### Index build (time/op; includes two forced GCs per op)

| Benchmark | before | after | Δ |
| --- | ---: | ---: | ---: |
| `exact/n=1` | 441.1µ | 452.8µ | +2.65% |
| `glob/n=1` | 440.0µ | 458.6µ | +4.23% |
| `exact/n=10` | 442.7µ | 487.4µ | +10.08% |
| `glob/n=10` | 444.1µ | 492.6µ | +10.91% |
| `exact/n=100` | 477.0µ | 539.6µ | +13.10% |
| `glob/n=100` | 474.1µ | 607.6µ | +28.17% |
| `exact/n=1000` | 806.0µ | 1009.7µ | +25.28% |
| `glob/n=1000` | 811.3µ | 1645.5µ | +102.82% |
| `exact/n=10000` | 4.235m | 5.965m | +40.85% |
| `glob/n=10000` | 4.185m | 16.917m | +304.24% |
| `one_path_many_lists` | 1.996m | 2.258m | +13.13% |
| `duplicate_patterns` | 926.4µ | 3489.6µ | +276.68% |

### Retained heap of the built index

| Benchmark | before | after |
| --- | ---: | ---: |

Index shape for the glob mix (`PROCESSPATH_STATS=1 go test -run StatsReport -v ./pkg/route/processpath`):
10,000 globs → 10,000 index keys, largest bucket 1, 0 fallback globs,
4.25 segments per glob, one prefix-key length.

Notes: `mixed` at n=1 holds one exact entry and no glob, so its `glob_hit` is a
miss. Some n=10…1,000 rows show wide confidence intervals (±50–190%) because
other work shared the machine during part of the run; the medians agree with
the quiet n=1 and n=10,000 rows.
