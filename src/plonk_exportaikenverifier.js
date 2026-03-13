import ejs from "ejs";
import { utils } from "ffjavascript";
const { unstringifyBigInts } = utils;

import exportVerificationKey from "./zkey_export_verificationkey.js";
import { getCurveFromName } from "./curves.js";
import { g1CompressedHex, g2CompressedHex } from "./aiken_utils.js";

export default async function exportPlonkAikenVerifier(zKeyName, templates, logger, options) {

    const verificationKey = await exportVerificationKey(zKeyName, logger);

    if (verificationKey.protocol !== "plonk") {
        throw new Error(`Aiken PLONK verifier only supports plonk protocol. This zkey uses "${verificationKey.protocol}".`);
    }

    if (verificationKey.curve !== "bls12381") {
        throw new Error(`Aiken PLONK verifier only supports BLS12-381 curve. This zkey uses "${verificationKey.curve}".`);
    }

    const curve = await getCurveFromName("bls12381");

    try {
        const domainSize = Math.pow(2, verificationKey.power);

        const templateData = {
            nPublic: verificationKey.nPublic,
            domain_size: domainSize,
            power: verificationKey.power,
            k1: unstringifyBigInts(verificationKey.k1).toString(),
            k2: unstringifyBigInts(verificationKey.k2).toString(),
            omega: unstringifyBigInts(verificationKey.w).toString(),

            vk_qm: g1CompressedHex(curve, verificationKey.Qm),
            vk_ql: g1CompressedHex(curve, verificationKey.Ql),
            vk_qr: g1CompressedHex(curve, verificationKey.Qr),
            vk_qo: g1CompressedHex(curve, verificationKey.Qo),
            vk_qc: g1CompressedHex(curve, verificationKey.Qc),
            vk_s1: g1CompressedHex(curve, verificationKey.S1),
            vk_s2: g1CompressedHex(curve, verificationKey.S2),
            vk_s3: g1CompressedHex(curve, verificationKey.S3),
            vk_x2: g2CompressedHex(curve, verificationKey.X_2),

            // Precomputed VK bytes (all 8 G1 commitments concatenated)
            vk_bytes: [
                g1CompressedHex(curve, verificationKey.Qm),
                g1CompressedHex(curve, verificationKey.Ql),
                g1CompressedHex(curve, verificationKey.Qr),
                g1CompressedHex(curve, verificationKey.Qo),
                g1CompressedHex(curve, verificationKey.Qc),
                g1CompressedHex(curve, verificationKey.S1),
                g1CompressedHex(curve, verificationKey.S2),
                g1CompressedHex(curve, verificationKey.S3),
            ].join(""),

            // Curve generators
            g1_gen: g1CompressedHex(curve, curve.G1.toObject(curve.G1.g)),
            g2_gen: g2CompressedHex(curve, curve.G2.toObject(curve.G2.g)),

            // Optional embedded test proof
            test_proof: options && options.testProof ? options.testProof : null,
            test_public_signals: options && options.testPublicSignals ? options.testPublicSignals : null,
        };

        const template = templates.plonk;

        return ejs.render(template, templateData);
    } finally {
        await curve.terminate();
    }
}
