# bb-side fixture generators

Test-only sources dropped into the pinned `aztec-packages` tree (see `../PIN`) to produce the
fixtures under `../data/<pin>/`.

- `bbref_dump.test.cpp` → `barretenberg/cpp/src/barretenberg/dsl/acir_format/` (part of `dsl_tests`).
  Dumps the UltraHonk proving instance of an ACIR program before Oink, plus bb's proof and VK:
  `BBREF_PROGRAM=<program.json> BBREF_WITNESS=<witness.gz> BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.*'`
  writes `<dir>/{nozk,zk}/` consumed by `tests/m2_ultra_prove.rs` and `tests/m3_builder.rs`
  (the dumps are large and gitignored; regenerate them locally).
- `../regen_vk_hashes.sh` needs only the stock `bb` binary.

The same file also provides `BbRefDump.MegaScript`, which runs a circuit script (one builder call
per line, see `../scripts/*.txt` and `tests/common/script.rs` for the grammar) on a
`MegaCircuitBuilder` and dumps the proving instance for the chosen flavor, together with its VK
and Oink proof:
`BBREF_SCRIPT=<script.txt> BBREF_FLAVOR=app|kernel|zk BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.MegaScript'`
(`tests/m4_mega.rs` reads `data/<pin>/instance/scripts/<script>/<flavor>/`). `BbRefDump.UltraInstance`
now also writes `<dir>/mega_app/` (MegaAppFlavor instance + Oink proof of the same ACIR program).
