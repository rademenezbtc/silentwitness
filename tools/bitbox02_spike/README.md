# BitBox02 silent-payment spike

Throwaway test for the BitBox02 adapter. `sp-spike.patch` adds silent-payment outputs to
[bitbox-api-rs](https://github.com/BitBoxSwiss/bitbox-api-rs) (commit pinned in
`.github/workflows/bitbox02-spike.yml`) and a test that signs the `silent-payment` vector from its
shared test vectors against the official firmware simulator. It prints the generated output script,
the DLEQ proof and the simulator's screens.

It runs only in CI (`bitbox02-spike` workflow). The simulator is third-party code; do not run it on
a machine with keys or credentials.
