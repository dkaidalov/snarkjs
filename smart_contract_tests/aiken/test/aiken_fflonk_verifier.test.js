import assert from "assert";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import { utils } from "ffjavascript";
import { g1CompressedHex } from "../../../src/aiken_utils.js";
import { getCurveFromName } from "../../../src/curves.js";
import exportFflonkAikenVerifier from "../../../src/fflonk_exportaikenverifier.js";

const { unstringifyBigInts } = utils;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const aikenProjectDir = path.join(__dirname, "..");
const fflonkDir = path.join(__dirname, "..", "..", "..", "test", "fflonk_bls12381");

const proof = JSON.parse(fs.readFileSync(path.join(fflonkDir, "proof.json"), "utf8"));
const publicSignals = JSON.parse(fs.readFileSync(path.join(fflonkDir, "public.json"), "utf8"));
const zkeyPath = path.join(fflonkDir, "circuit.zkey");

describe("Aiken FFLONK verifier integration test", function () {
    this.timeout(300000);

    let verifierCode;

    before(async () => {
        const templatePath = path.join(__dirname, "..", "..", "..", "templates", "verifier_fflonk.ak.ejs");
        const templates = {
            fflonk: fs.readFileSync(templatePath, "utf8"),
        };

        // Compress proof G1 points for test embedding
        const curve = await getCurveFromName("bls12381");
        let testProof;
        try {
            const p = unstringifyBigInts(proof);
            testProof = {
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
        } finally {
            await curve.terminate();
        }

        // Export verifier with embedded test proof
        verifierCode = await exportFflonkAikenVerifier(zkeyPath, templates, null, {
            testProof,
            testPublicSignals: publicSignals,
        });

        // Write to validators directory
        const validatorsDir = path.join(aikenProjectDir, "validators");
        fs.mkdirSync(validatorsDir, { recursive: true });
        fs.writeFileSync(path.join(validatorsDir, "fflonk_verifier.ak"), verifierCode, "utf-8");
    });

    it("should generate verifier code with expected structure", () => {
        assert.ok(verifierCode, "Verifier code should be generated");
        assert.ok(verifierCode.includes("pub fn verify("), "Should contain verify function");
        assert.ok(verifierCode.includes("FflonkProof"), "Should contain FflonkProof type");
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
        const output = execSync("aiken check", {
            cwd: aikenProjectDir,
            encoding: "utf-8",
            timeout: 240000,
        });

        assert.ok(true, "aiken check passed");
    });
});
