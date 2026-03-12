import assert from "assert";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import { g1CompressedHex, g2CompressedHex } from "../../../src/aiken_utils.js";
import { getCurveFromName } from "../../../src/curves.js";
import exportAikenVerifier from "../../../src/zkey_export_aikenverifier.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const aikenProjectDir = path.join(__dirname, "..");
const bls12381Dir = path.join(__dirname, "..", "..", "..", "test", "groth16_bls12381");

const proof = JSON.parse(fs.readFileSync(path.join(bls12381Dir, "proof.json"), "utf8"));
const publicSignals = JSON.parse(fs.readFileSync(path.join(bls12381Dir, "public.json"), "utf8"));
const zkeyPath = path.join(bls12381Dir, "circuit.zkey");

describe("Aiken Groth16 verifier integration test", function () {
    this.timeout(120000);

    let verifierCode;

    before(async () => {
        // Load Aiken template
        const templatePath = path.join(__dirname, "..", "..", "..", "templates", "verifier_groth16.ak.ejs");
        const templates = {
            groth16: fs.readFileSync(templatePath, "utf8"),
        };

        // Compress proof points for test embedding
        const curve = await getCurveFromName("bls12381");
        try {
            const testProof = {
                pi_a: g1CompressedHex(curve, proof.pi_a),
                pi_b: g2CompressedHex(curve, proof.pi_b),
                pi_c: g1CompressedHex(curve, proof.pi_c),
            };

            // Export verifier with embedded tests
            verifierCode = await exportAikenVerifier(zkeyPath, templates, null, {
                testProof,
                testPublicSignals: publicSignals,
            });
        } finally {
            await curve.terminate();
        }

        // Write to validators directory
        const validatorsDir = path.join(aikenProjectDir, "validators");
        fs.mkdirSync(validatorsDir, { recursive: true });
        fs.writeFileSync(path.join(validatorsDir, "groth16_verifier.ak"), verifierCode, "utf-8");
    });

    it("should generate verifier code", () => {
        assert.ok(verifierCode, "Verifier code should be generated");
        assert.ok(verifierCode.includes("pub fn verify("), "Should contain verify function");
    });

    it("should compile and pass inline tests with aiken check", () => {
        const result = execSync("aiken check", {
            cwd: aikenProjectDir,
            encoding: "utf-8",
            timeout: 60000,
        });

        // aiken check runs compilation + inline tests
        assert.ok(true, "aiken check passed");
    });
});
