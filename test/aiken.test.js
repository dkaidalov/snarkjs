import assert from "assert";
import * as path from "path";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import * as snarkjs from "../main.js";
import { g1CompressedHex, g2CompressedHex } from "../src/aiken_utils.js";
import { getCurveFromName } from "../src/curves.js";
import exportAikenVerifier from "../src/zkey_export_aikenverifier.js";
import groth16ExportAikenCallData from "../src/groth16_exportaikencalldata.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bls12381Dir = path.join(__dirname, "groth16_bls12381");

const vk = JSON.parse(readFileSync(path.join(bls12381Dir, "verification_key.json"), "utf8"));
const proof = JSON.parse(readFileSync(path.join(bls12381Dir, "proof.json"), "utf8"));
const publicSignals = JSON.parse(readFileSync(path.join(bls12381Dir, "public.json"), "utf8"));

describe("BLS12-381 Groth16 test artifacts", () => {
    it("should verify the pre-generated BLS12-381 proof", async () => {
        assert.strictEqual(vk.curve, "bls12381");
        assert.strictEqual(vk.protocol, "groth16");

        const isValid = await snarkjs.groth16.verify(vk, publicSignals, proof);
        assert.strictEqual(isValid, true, "BLS12-381 proof should verify successfully");
    });

    it("should reject a tampered BLS12-381 proof", async () => {
        const tamperedSignals = [...publicSignals];
        tamperedSignals[0] = "999";

        const isValid = await snarkjs.groth16.verify(vk, tamperedSignals, proof);
        assert.strictEqual(isValid, false, "Tampered proof should not verify");
    });
});

describe("Aiken point compression utilities", () => {
    let curve;

    before(async () => {
        curve = await getCurveFromName("bls12381");
    });

    after(async () => {
        await curve.terminate();
    });

    it("should compress G1 points to 96-char hex (48 bytes)", () => {
        const hex = g1CompressedHex(curve, vk.vk_alpha_1);
        assert.strictEqual(typeof hex, "string");
        assert.strictEqual(hex.length, 96, "G1 compressed should be 48 bytes = 96 hex chars");
        assert.match(hex, /^[0-9a-f]+$/, "Should be valid hex");
    });

    it("should compress G2 points to 192-char hex (96 bytes)", () => {
        const hex = g2CompressedHex(curve, vk.vk_beta_2);
        assert.strictEqual(typeof hex, "string");
        assert.strictEqual(hex.length, 192, "G2 compressed should be 96 bytes = 192 hex chars");
        assert.match(hex, /^[0-9a-f]+$/, "Should be valid hex");
    });

    it("should compress all IC points", () => {
        for (let i = 0; i < vk.IC.length; i++) {
            const hex = g1CompressedHex(curve, vk.IC[i]);
            assert.strictEqual(hex.length, 96, `IC[${i}] should be 96 hex chars`);
        }
    });

    it("should produce consistent output for same input", () => {
        const hex1 = g1CompressedHex(curve, vk.vk_alpha_1);
        const hex2 = g1CompressedHex(curve, vk.vk_alpha_1);
        assert.strictEqual(hex1, hex2, "Same input should produce same output");
    });

    it("should produce different output for different points", () => {
        const hex1 = g2CompressedHex(curve, vk.vk_beta_2);
        const hex2 = g2CompressedHex(curve, vk.vk_gamma_2);
        assert.notStrictEqual(hex1, hex2, "Different points should produce different output");
    });

    it("should produce Zcash-format compressed G1 (compression flag set)", () => {
        const hex = g1CompressedHex(curve, vk.vk_alpha_1);
        const firstByte = parseInt(hex.substring(0, 2), 16);
        assert.ok((firstByte & 0x80) !== 0, "Compression flag (bit 7) should be set");
    });

    it("should produce Zcash-format compressed G2 (compression flag set)", () => {
        const hex = g2CompressedHex(curve, vk.vk_gamma_2);
        const firstByte = parseInt(hex.substring(0, 2), 16);
        assert.ok((firstByte & 0x80) !== 0, "Compression flag (bit 7) should be set");
    });

    it("should produce consistent G1 compress output", () => {
        const hex1 = g1CompressedHex(curve, vk.vk_alpha_1);
        const hex2 = g1CompressedHex(curve, vk.vk_alpha_1);
        assert.strictEqual(hex1, hex2, "Same G1 input should produce same output");
    });

    it("should produce consistent G2 compress output", () => {
        const hex1 = g2CompressedHex(curve, vk.vk_beta_2);
        const hex2 = g2CompressedHex(curve, vk.vk_beta_2);
        assert.strictEqual(hex1, hex2, "Same G2 input should produce same output");
    });
});

describe("Aiken verifier export", () => {
    const zkeyPath = path.join(bls12381Dir, "circuit.zkey");
    let templates;

    before(() => {
        const templatePath = path.join(__dirname, "..", "templates", "verifier_groth16.ak.ejs");
        templates = {
            groth16: readFileSync(templatePath, "utf8"),
        };
    });

    it("should export a valid Aiken verifier from BLS12-381 zkey", async () => {
        const code = await exportAikenVerifier(zkeyPath, templates);

        assert.ok(code.includes("pub fn verify("), "Should contain verify function");
        assert.ok(code.includes("bls12_381_miller_loop"), "Should contain pairing operations");
        assert.ok(code.includes("bls12_381_g1_uncompress"), "Should contain G1 uncompress");
        assert.ok(code.includes("bls12_381_g2_uncompress"), "Should contain G2 uncompress");
        assert.ok(code.includes("bls12_381_final_verify"), "Should contain final verify");
    });

    it("should embed correct number of IC points", async () => {
        const code = await exportAikenVerifier(zkeyPath, templates);

        // vk has nPublic=2 so IC should have 3 points (IC[0], IC[1], IC[2])
        assert.ok(code.includes("const ic_0"), "Should have ic_0");
        assert.ok(code.includes("const ic_1"), "Should have ic_1");
        assert.ok(code.includes("const ic_2"), "Should have ic_2");
    });

    it("should embed VK points as hex byte arrays", async () => {
        const code = await exportAikenVerifier(zkeyPath, templates);

        // Check that hex constants are present (96 chars for G1, 192 for G2)
        const g1Pattern = /#"[0-9a-f]{96}"/;
        const g2Pattern = /#"[0-9a-f]{192}"/;
        assert.ok(g1Pattern.test(code), "Should contain G1 hex byte arrays");
        assert.ok(g2Pattern.test(code), "Should contain G2 hex byte arrays");
    });

    it("should embed test proof when provided", async () => {
        const curve = await getCurveFromName("bls12381");
        try {
            const testProof = {
                pi_a: g1CompressedHex(curve, proof.pi_a),
                pi_b: g2CompressedHex(curve, proof.pi_b),
                pi_c: g1CompressedHex(curve, proof.pi_c),
            };
            const code = await exportAikenVerifier(zkeyPath, templates, null, {
                testProof,
                testPublicSignals: publicSignals,
            });

            assert.ok(code.includes("test verify_valid_proof()"), "Should contain valid proof test");
            assert.ok(code.includes("test verify_invalid_proof() fail"), "Should contain invalid proof test");
        } finally {
            await curve.terminate();
        }
    });

    it("should reject non-BLS12-381 Groth16 zkeys", async () => {
        // circuit2/circuit.zkey is a PLONK key on BN128 — should be rejected
        const nonBls12381ZkeyPath = path.join(__dirname, "circuit2", "circuit.zkey");
        try {
            readFileSync(nonBls12381ZkeyPath);
        } catch {
            // Skip test if zkey not available
            return;
        }

        await assert.rejects(
            () => exportAikenVerifier(nonBls12381ZkeyPath, templates),
            /only supports/,
            "Should reject non-BLS12-381/non-Groth16 zkeys"
        );
    });
});

describe("Aiken calldata export", () => {
    it("should export valid JSON", async () => {
        const result = await groth16ExportAikenCallData(proof, publicSignals);
        const parsed = JSON.parse(result);
        assert.ok(parsed.pi_a, "Should have pi_a");
        assert.ok(parsed.pi_b, "Should have pi_b");
        assert.ok(parsed.pi_c, "Should have pi_c");
        assert.ok(Array.isArray(parsed.public_signals), "Should have public_signals array");
    });

    it("should produce correct hex lengths", async () => {
        const result = await groth16ExportAikenCallData(proof, publicSignals);
        const parsed = JSON.parse(result);
        assert.strictEqual(parsed.pi_a.length, 96, "G1 pi_a should be 96 hex chars");
        assert.strictEqual(parsed.pi_b.length, 192, "G2 pi_b should be 192 hex chars");
        assert.strictEqual(parsed.pi_c.length, 96, "G1 pi_c should be 96 hex chars");
        assert.match(parsed.pi_a, /^[0-9a-f]+$/, "pi_a should be valid hex");
        assert.match(parsed.pi_b, /^[0-9a-f]+$/, "pi_b should be valid hex");
        assert.match(parsed.pi_c, /^[0-9a-f]+$/, "pi_c should be valid hex");
    });

    it("should preserve public signals", async () => {
        const result = await groth16ExportAikenCallData(proof, publicSignals);
        const parsed = JSON.parse(result);
        assert.strictEqual(parsed.public_signals.length, publicSignals.length, "Should have same number of signals");
        for (let i = 0; i < publicSignals.length; i++) {
            assert.strictEqual(parsed.public_signals[i], publicSignals[i].toString(), `Signal ${i} should match`);
        }
    });

    it("should be accessible via snarkjs.groth16.exportAikenCallData", async () => {
        assert.strictEqual(typeof snarkjs.groth16.exportAikenCallData, "function", "Should be exported from facade");
    });
});
