#!/bin/bash
# Script to generate BLS12-381 Groth16 test artifacts
# Run from the test/groth16_bls12381/ directory
# Requires: circom, node, snarkjs (from parent repo)

set -e

SNARKJS="node ../../cli.js"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== Step 1: Compile circuit with BLS12-381 prime ==="
circom circuit.circom --r1cs --wasm --prime bls12381 -o .

echo "=== Step 2: Generate BLS12-381 Powers of Tau ==="
$SNARKJS powersoftau new bls12-381 8 pot8_0000.ptau
$SNARKJS powersoftau contribute pot8_0000.ptau pot8_0001.ptau --name="First contribution" -e="random entropy for testing"
$SNARKJS powersoftau prepare phase2 pot8_0001.ptau powersoftau_bls12381.ptau
rm -f pot8_0000.ptau pot8_0001.ptau

echo "=== Step 3: Generate Groth16 zkey ==="
$SNARKJS groth16 setup circuit.r1cs powersoftau_bls12381.ptau circuit_0000.zkey
$SNARKJS zkey contribute circuit_0000.zkey circuit.zkey --name="First contribution" -e="random entropy for testing"
rm -f circuit_0000.zkey

echo "=== Step 4: Export verification key ==="
$SNARKJS zkey export verificationkey circuit.zkey verification_key.json

echo "=== Step 5: Generate witness ==="
$SNARKJS wtns calculate circuit_js/circuit.wasm input.json witness.wtns

echo "=== Step 6: Generate proof ==="
$SNARKJS groth16 prove circuit.zkey witness.wtns proof.json public.json

echo "=== Step 7: Verify proof ==="
$SNARKJS groth16 verify verification_key.json public.json proof.json

echo "=== All artifacts generated successfully ==="
echo "Files created:"
ls -la *.r1cs *.ptau *.zkey *.wtns *.json circuit_js/circuit.wasm 2>/dev/null
