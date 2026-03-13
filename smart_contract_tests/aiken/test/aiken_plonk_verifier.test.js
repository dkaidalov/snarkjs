import assert from "assert";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import { utils } from "ffjavascript";
import { g1CompressedHex } from "../../../src/aiken_utils.js";
import { getCurveFromName } from "../../../src/curves.js";
import exportPlonkAikenVerifier from "../../../src/plonk_exportaikenverifier.js";

const { unstringifyBigInts } = utils;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const aikenProjectDir = path.join(__dirname, "..");
const plonkDir = path.join(__dirname, "..", "..", "..", "test", "plonk_bls12381");

const proof = JSON.parse(fs.readFileSync(path.join(plonkDir, "proof.json"), "utf8"));
const publicSignals = JSON.parse(fs.readFileSync(path.join(plonkDir, "public.json"), "utf8"));
const zkeyPath = path.join(plonkDir, "circuit.zkey");

describe("Aiken PLONK verifier integration test", function () {
    this.timeout(180000);

    let verifierCode;

    before(async () => {
        const templatePath = path.join(__dirname, "..", "..", "..", "templates", "verifier_plonk.ak.ejs");
        const templates = {
            plonk: fs.readFileSync(templatePath, "utf8"),
        };

        // Compress proof G1 points for test embedding
        const curve = await getCurveFromName("bls12381");
        let testProof;
        try {
            const p = unstringifyBigInts(proof);
            testProof = {
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
        } finally {
            await curve.terminate();
        }

        // Export verifier with embedded test proof
        verifierCode = await exportPlonkAikenVerifier(zkeyPath, templates, null, {
            testProof,
            testPublicSignals: publicSignals,
        });

        // Write to validators directory
        const validatorsDir = path.join(aikenProjectDir, "validators");
        fs.mkdirSync(validatorsDir, { recursive: true });
        fs.writeFileSync(path.join(validatorsDir, "plonk_verifier.ak"), verifierCode, "utf-8");
    });

    it("should generate verifier code with expected structure", () => {
        assert.ok(verifierCode, "Verifier code should be generated");
        assert.ok(verifierCode.includes("pub fn verify("), "Should contain verify function");
        assert.ok(verifierCode.includes("keccak_challenge"), "Should contain Keccak transcript");
        assert.ok(verifierCode.includes("builtin.bls12_381_g1_scalar_mul"), "Should use G1 scalar mul");
        assert.ok(verifierCode.includes("builtin.bls12_381_final_verify"), "Should use final verify");
    });

    it("should embed VK points as hex byte arrays", () => {
        const g1Pattern = /#"[0-9a-f]{96}"/;
        const g2Pattern = /#"[0-9a-f]{192}"/;
        assert.ok(g1Pattern.test(verifierCode), "Should contain G1 hex byte arrays (48 bytes)");
        assert.ok(g2Pattern.test(verifierCode), "Should contain G2 hex byte arrays (96 bytes)");
    });

    it("should embed test proof", () => {
        assert.ok(verifierCode.includes("test verify_valid_proof()"), "Should contain valid proof test");
        assert.ok(verifierCode.includes("test verify_invalid_proof() fail"), "Should contain invalid proof test");
    });

    it("should compile and pass inline tests with aiken check", () => {
        execSync("aiken check", {
            cwd: aikenProjectDir,
            encoding: "utf-8",
            timeout: 120000,
        });

        assert.ok(true, "aiken check passed");
    });
});
