import assert from "assert";
import * as path from "path";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { utils } from "ffjavascript";
import * as snarkjs from "../main.js";
import { g1CompressedHex, g2CompressedHex } from "../src/aiken_utils.js";
import { getCurveFromName } from "../src/curves.js";
import exportAikenVerifier from "../src/zkey_export_aikenverifier.js";
import groth16ExportAikenCallData from "../src/groth16_exportaikencalldata.js";
import exportPlonkAikenVerifier from "../src/plonk_exportaikenverifier.js";
import plonkExportAikenCallData from "../src/plonk_exportaikencalldata.js";
import exportFflonkAikenVerifier from "../src/fflonk_exportaikenverifier.js";
import fflonkExportAikenCallData from "../src/fflonk_exportaikencalldata.js";

const { unstringifyBigInts } = utils;

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

// ===== BLS12-381 PLONK Aiken tests =====

const plonkDir = path.join(__dirname, "plonk_bls12381");
const plonkProof = JSON.parse(readFileSync(path.join(plonkDir, "proof.json"), "utf8"));
const plonkPublicSignals = JSON.parse(readFileSync(path.join(plonkDir, "public.json"), "utf8"));
const plonkVk = JSON.parse(readFileSync(path.join(plonkDir, "verification_key.json"), "utf8"));
const plonkZkeyPath = path.join(plonkDir, "circuit.zkey");

describe("BLS12-381 PLONK round-trip", () => {
    it("should verify the pre-generated BLS12-381 PLONK proof", async () => {
        assert.strictEqual(plonkVk.curve, "bls12381");
        assert.strictEqual(plonkVk.protocol, "plonk");

        const isValid = await snarkjs.plonk.verify(plonkVk, plonkPublicSignals, plonkProof);
        assert.strictEqual(isValid, true, "BLS12-381 PLONK proof should verify successfully");
    });

    it("should reject a tampered BLS12-381 PLONK proof", async () => {
        const tamperedSignals = [...plonkPublicSignals];
        tamperedSignals[0] = "999";

        const isValid = await snarkjs.plonk.verify(plonkVk, tamperedSignals, plonkProof);
        assert.strictEqual(isValid, false, "Tampered PLONK proof should not verify");
    });
});

describe("Aiken PLONK verifier export", () => {
    const templatePath = path.join(__dirname, "..", "templates", "verifier_plonk.ak.ejs");
    let templates;

    before(() => {
        templates = {
            plonk: readFileSync(templatePath, "utf8"),
        };
    });

    it("should export a valid Aiken PLONK verifier from BLS12-381 zkey", async () => {
        const code = await exportPlonkAikenVerifier(plonkZkeyPath, templates);

        assert.ok(code.includes("pub fn verify("), "Should contain verify function");
        assert.ok(code.includes("keccak_challenge"), "Should contain Keccak transcript");
        assert.ok(code.includes("builtin.bls12_381_g1_scalar_mul"), "Should use G1 scalar mul");
        assert.ok(code.includes("builtin.bls12_381_final_verify"), "Should use final verify");
        assert.ok(code.includes("builtin.keccak_256"), "Should use Keccak-256");
        assert.ok(code.includes("fr_inv"), "Should contain field inversion");
    });

    it("should embed VK points as hex byte arrays", async () => {
        const code = await exportPlonkAikenVerifier(plonkZkeyPath, templates);

        const g1Pattern = /#"[0-9a-f]{96}"/;
        const g2Pattern = /#"[0-9a-f]{192}"/;
        assert.ok(g1Pattern.test(code), "Should contain G1 hex byte arrays (48 bytes)");
        assert.ok(g2Pattern.test(code), "Should contain G2 hex byte arrays (96 bytes)");
    });

    it("should embed test proof when provided", async () => {
        const curve = await getCurveFromName("bls12381");
        try {
            const p = unstringifyBigInts(plonkProof);
            const testProof = {
                a:    g1CompressedHex(curve, p.A),
                b:    g1CompressedHex(curve, p.B),
                c:    g1CompressedHex(curve, p.C),
                z:    g1CompressedHex(curve, p.Z),
                t1:   g1CompressedHex(curve, p.T1),
                t2:   g1CompressedHex(curve, p.T2),
                t3:   g1CompressedHex(curve, p.T3),
                wxi:  g1CompressedHex(curve, p.Wxi),
                wxiw: g1CompressedHex(curve, p.Wxiw),
                eval_a:  p.eval_a.toString(),
                eval_b:  p.eval_b.toString(),
                eval_c:  p.eval_c.toString(),
                eval_s1: p.eval_s1.toString(),
                eval_s2: p.eval_s2.toString(),
                eval_zw: p.eval_zw.toString(),
            };
            const code = await exportPlonkAikenVerifier(plonkZkeyPath, templates, null, {
                testProof,
                testPublicSignals: plonkPublicSignals,
            });

            assert.ok(code.includes("test verify_valid_proof()"), "Should contain valid proof test");
            assert.ok(code.includes("test verify_invalid_proof() fail"), "Should contain invalid proof test");
        } finally {
            await curve.terminate();
        }
    });

    it("should reject non-PLONK or non-BLS12-381 zkeys", async () => {
        const groth16ZkeyPath = path.join(__dirname, "groth16_bls12381", "circuit.zkey");
        await assert.rejects(
            () => exportPlonkAikenVerifier(groth16ZkeyPath, templates),
            /only supports plonk/,
            "Should reject non-PLONK zkeys"
        );
    });

    it("should be accessible via snarkjs.plonk.exportAikenVerifier", () => {
        assert.strictEqual(typeof snarkjs.plonk.exportAikenVerifier, "function", "Should be exported from facade");
    });
});

describe("Aiken PLONK calldata export", () => {
    it("should export valid JSON with all proof fields", async () => {
        const result = await plonkExportAikenCallData(plonkProof, plonkPublicSignals);
        const parsed = JSON.parse(result);

        // Check all G1 compressed fields
        for (const field of ["a", "b", "c", "z", "t1", "t2", "t3", "wxi", "wxiw"]) {
            assert.ok(parsed[field], `Should have ${field}`);
            assert.strictEqual(parsed[field].length, 96, `${field} should be 96 hex chars (48 bytes)`);
            assert.match(parsed[field], /^[0-9a-f]+$/, `${field} should be valid hex`);
        }

        // Check Fr scalar evaluations
        for (const field of ["eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw"]) {
            assert.ok(parsed[field], `Should have ${field}`);
            assert.match(parsed[field], /^\d+$/, `${field} should be a decimal string`);
        }

        // Check public signals
        assert.ok(Array.isArray(parsed.public_signals), "Should have public_signals array");
        assert.strictEqual(parsed.public_signals.length, plonkPublicSignals.length, "Should have correct number of public signals");
    });

    it("should have Zcash-format compression flags on G1 points", async () => {
        const result = await plonkExportAikenCallData(plonkProof, plonkPublicSignals);
        const parsed = JSON.parse(result);

        const firstByte = parseInt(parsed.a.substring(0, 2), 16);
        assert.ok((firstByte & 0x80) !== 0, "Compression flag (bit 7) should be set");
    });

    it("should be accessible via snarkjs.plonk.exportAikenCallData", () => {
        assert.strictEqual(typeof snarkjs.plonk.exportAikenCallData, "function", "Should be exported from facade");
    });
});

// ===== BLS12-381 FFLONK Aiken tests =====

const fflonkDir = path.join(__dirname, "fflonk_bls12381");
const fflonkProof = JSON.parse(readFileSync(path.join(fflonkDir, "proof.json"), "utf8"));
const fflonkPublicSignals = JSON.parse(readFileSync(path.join(fflonkDir, "public.json"), "utf8"));
const fflonkVk = JSON.parse(readFileSync(path.join(fflonkDir, "verification_key.json"), "utf8"));
const fflonkZkeyPath = path.join(fflonkDir, "circuit.zkey");

describe("BLS12-381 FFLONK round-trip", () => {
    it("should verify the pre-generated BLS12-381 FFLONK proof", async () => {
        assert.strictEqual(fflonkVk.curve, "bls12381");
        assert.strictEqual(fflonkVk.protocol, "fflonk");

        const isValid = await snarkjs.fflonk.verify(fflonkVk, fflonkPublicSignals, fflonkProof);
        assert.strictEqual(isValid, true, "BLS12-381 FFLONK proof should verify successfully");
    });

    it("should reject a tampered BLS12-381 FFLONK proof", async () => {
        const tamperedSignals = [...fflonkPublicSignals];
        tamperedSignals[0] = "999";

        const isValid = await snarkjs.fflonk.verify(fflonkVk, tamperedSignals, fflonkProof);
        assert.strictEqual(isValid, false, "Tampered FFLONK proof should not verify");
    });
});

describe("Aiken FFLONK verifier export", () => {
    const templatePath = path.join(__dirname, "..", "templates", "verifier_fflonk.ak.ejs");
    let templates;

    before(() => {
        templates = {
            fflonk: readFileSync(templatePath, "utf8"),
        };
    });

    it("should export a valid Aiken FFLONK verifier from BLS12-381 zkey", async () => {
        const code = await exportFflonkAikenVerifier(fflonkZkeyPath, templates);

        assert.ok(code.includes("pub fn verify("), "Should contain verify function");
        assert.ok(code.includes("FflonkProof"), "Should contain FflonkProof type");
        assert.ok(code.includes("keccak_challenge"), "Should contain Keccak transcript");
        assert.ok(code.includes("builtin.bls12_381_g1_scalar_mul"), "Should use G1 scalar mul");
        assert.ok(code.includes("builtin.bls12_381_final_verify"), "Should use final verify");
        assert.ok(code.includes("fr_inv"), "Should contain field inversion");
    });

    it("should embed VK points as hex byte arrays", async () => {
        const code = await exportFflonkAikenVerifier(fflonkZkeyPath, templates);

        const g1Pattern = /#"[0-9a-f]{96}"/;
        const g2Pattern = /#"[0-9a-f]{192}"/;
        assert.ok(g1Pattern.test(code), "Should contain G1 hex byte arrays (48 bytes)");
        assert.ok(g2Pattern.test(code), "Should contain G2 hex byte arrays (96 bytes)");
    });

    it("should embed domain parameters", async () => {
        const code = await exportFflonkAikenVerifier(fflonkZkeyPath, templates);

        assert.ok(code.includes("const domain_size: Int = 32"), "Should embed domain_size");
        assert.ok(code.includes("const k1: Int = 2"), "Should embed k1");
        assert.ok(code.includes("const k2: Int = 3"), "Should embed k2");
    });

    it("should embed test proof when provided", async () => {
        const curve = await getCurveFromName("bls12381");
        try {
            const p = unstringifyBigInts(fflonkProof);
            const testProof = {
                c1:  g1CompressedHex(curve, p.polynomials.C1),
                c2:  g1CompressedHex(curve, p.polynomials.C2),
                w1:  g1CompressedHex(curve, p.polynomials.W1),
                w2:  g1CompressedHex(curve, p.polynomials.W2),
                eval_ql:  p.evaluations.ql.toString(),
                eval_qr:  p.evaluations.qr.toString(),
                eval_qm:  p.evaluations.qm.toString(),
                eval_qo:  p.evaluations.qo.toString(),
                eval_qc:  p.evaluations.qc.toString(),
                eval_s1:  p.evaluations.s1.toString(),
                eval_s2:  p.evaluations.s2.toString(),
                eval_s3:  p.evaluations.s3.toString(),
                eval_a:   p.evaluations.a.toString(),
                eval_b:   p.evaluations.b.toString(),
                eval_c:   p.evaluations.c.toString(),
                eval_z:   p.evaluations.z.toString(),
                eval_zw:  p.evaluations.zw.toString(),
                eval_t1w: p.evaluations.t1w.toString(),
                eval_t2w: p.evaluations.t2w.toString(),
            };
            const code = await exportFflonkAikenVerifier(fflonkZkeyPath, templates, null, {
                testProof,
                testPublicSignals: fflonkPublicSignals,
            });

            assert.ok(code.includes("test verify_valid_proof()"), "Should contain valid proof test");
            assert.ok(code.includes("test verify_invalid_proof() fail"), "Should contain invalid proof test");
        } finally {
            await curve.terminate();
        }
    });

    it("should reject non-FFLONK or non-BLS12-381 zkeys", async () => {
        const plonkZkey = path.join(__dirname, "plonk_bls12381", "circuit.zkey");
        await assert.rejects(
            () => exportFflonkAikenVerifier(plonkZkey, templates),
            /only supports fflonk/,
            "Should reject non-FFLONK zkeys"
        );
    });

    it("should be accessible via snarkjs.fflonk.exportAikenVerifier", () => {
        assert.strictEqual(typeof snarkjs.fflonk.exportAikenVerifier, "function", "Should be exported from facade");
    });
});

describe("Aiken FFLONK calldata export", () => {
    it("should export valid JSON with all proof fields", async () => {
        const result = await fflonkExportAikenCallData(fflonkProof, fflonkPublicSignals);
        const parsed = JSON.parse(result);

        // Check all G1 compressed fields
        for (const field of ["c1", "c2", "w1", "w2"]) {
            assert.ok(parsed[field], `Should have ${field}`);
            assert.strictEqual(parsed[field].length, 96, `${field} should be 96 hex chars (48 bytes)`);
            assert.match(parsed[field], /^[0-9a-f]+$/, `${field} should be valid hex`);
        }

        // Check Fr scalar evaluations
        for (const field of ["eval_ql", "eval_qr", "eval_qm", "eval_qo", "eval_qc",
                             "eval_s1", "eval_s2", "eval_s3", "eval_a", "eval_b", "eval_c",
                             "eval_z", "eval_zw", "eval_t1w", "eval_t2w", "eval_inv"]) {
            assert.ok(parsed[field] !== undefined, `Should have ${field}`);
            assert.match(parsed[field], /^\d+$/, `${field} should be a decimal string`);
        }

        // Check public signals
        assert.ok(Array.isArray(parsed.public_signals), "Should have public_signals array");
        assert.strictEqual(parsed.public_signals.length, fflonkPublicSignals.length, "Should have correct number of public signals");
    });

    it("should have Zcash-format compression flags on G1 points", async () => {
        const result = await fflonkExportAikenCallData(fflonkProof, fflonkPublicSignals);
        const parsed = JSON.parse(result);

        for (const field of ["c1", "c2", "w1", "w2"]) {
            const firstByte = parseInt(parsed[field].substring(0, 2), 16);
            assert.ok((firstByte & 0x80) !== 0, `${field}: compression flag (bit 7) should be set`);
        }
    });

    it("should be accessible via snarkjs.fflonk.exportAikenCallData", () => {
        assert.strictEqual(typeof snarkjs.fflonk.exportAikenCallData, "function", "Should be exported from facade");
    });
});
