# Aiken Groth16 Verifier — Integration Test

This project verifies that the snarkjs-generated Aiken Groth16 verifier compiles and passes on-chain verification using Cardano's BLS12-381 builtins.

## Prerequisites

- **Node.js** ≥ 18
- **Aiken** ≥ 1.1.19 — [installation instructions](https://aiken-lang.org/installation-instructions)

## Automated test

```bash
cd smart_contract_tests/aiken
npm install
npm test
```

This runs a mocha test that:
1. Reads the BLS12-381 test artifacts from `test/groth16_bls12381/` (zkey, proof, public signals)
2. Calls `exportAikenVerifier()` to generate `validators/groth16_verifier.ak` with embedded inline tests
3. Runs `aiken check`, which compiles the validator and executes two inline tests:
   - `verify_valid_proof` — verifies a real Groth16 proof (should pass)
   - `verify_invalid_proof` — verifies a tampered proof (should fail, marked with `fail`)

## Manual flow

1. **Generate the Aiken verifier** (from the repo root):

```bash
node cli.js zkey export aikenverifier \
  test/groth16_bls12381/circuit.zkey \
  smart_contract_tests/aiken/validators/groth16_verifier.ak \
  -t test/groth16_bls12381/proof.json \
  -p test/groth16_bls12381/public.json
```

The `-t` and `-p` flags embed a test proof and public signals as inline Aiken `test` blocks.

2. **Compile and run inline tests**:

```bash
cd smart_contract_tests/aiken
aiken check
```
