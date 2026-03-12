import assert from "assert";
import * as path from "path";
import { fileURLToPath } from "url";
import * as snarkjs from "../main.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bls12381Dir = path.join(__dirname, "groth16_bls12381");

describe("BLS12-381 Groth16 test artifacts", () => {
    it("should verify the pre-generated BLS12-381 proof", async () => {
        const { readFileSync } = await import("fs");

        const vk = JSON.parse(readFileSync(path.join(bls12381Dir, "verification_key.json"), "utf8"));
        const proof = JSON.parse(readFileSync(path.join(bls12381Dir, "proof.json"), "utf8"));
        const publicSignals = JSON.parse(readFileSync(path.join(bls12381Dir, "public.json"), "utf8"));

        assert.strictEqual(vk.curve, "bls12381");
        assert.strictEqual(vk.protocol, "groth16");

        const isValid = await snarkjs.groth16.verify(vk, publicSignals, proof);
        assert.strictEqual(isValid, true, "BLS12-381 proof should verify successfully");
    });

    it("should reject a tampered BLS12-381 proof", async () => {
        const { readFileSync } = await import("fs");

        const vk = JSON.parse(readFileSync(path.join(bls12381Dir, "verification_key.json"), "utf8"));
        const proof = JSON.parse(readFileSync(path.join(bls12381Dir, "proof.json"), "utf8"));
        const publicSignals = JSON.parse(readFileSync(path.join(bls12381Dir, "public.json"), "utf8"));

        // Tamper with a public signal
        const tamperedSignals = [...publicSignals];
        tamperedSignals[0] = "999";

        const isValid = await snarkjs.groth16.verify(vk, tamperedSignals, proof);
        assert.strictEqual(isValid, false, "Tampered proof should not verify");
    });
});
