# bb-side fixture generators

Test-only sources dropped into the pinned `aztec-packages` tree (see `../PIN`) to produce the
fixtures under `../data/<pin>/`.

- `bbref_dump.test.cpp` → `barretenberg/cpp/src/barretenberg/dsl/acir_format/` (part of `dsl_tests`).
  Dumps the UltraHonk proving instance of an ACIR program before Oink, plus bb's proof and VK:
  `BBREF_PROGRAM=<program.json> BBREF_WITNESS=<witness.gz> BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.*'`
  writes `<dir>/{nozk,zk}/` consumed by `tests/m2_ultra_prove.rs` and `tests/m3_builder.rs`
  (the dumps are large and gitignored; regenerate them locally).
- `../regen_vk_hashes.sh` needs only the stock `bb` binary.
