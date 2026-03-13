import ejs from "ejs";
import { utils } from "ffjavascript";
const { unstringifyBigInts } = utils;

import exportVerificationKey from "./zkey_export_verificationkey.js";
import { getCurveFromName } from "./curves.js";
import { g1CompressedHex, g2CompressedHex } from "./aiken_utils.js";

export default async function exportFflonkAikenVerifier(zKeyName, templates, logger, options) {

    const verificationKey = await exportVerificationKey(zKeyName, logger);

    if (verificationKey.protocol !== "fflonk") {
        throw new Error(`Aiken FFLONK verifier only supports fflonk protocol. This zkey uses "${verificationKey.protocol}".`);
    }

    if (verificationKey.curve !== "bls12381") {
        throw new Error(`Aiken FFLONK verifier only supports BLS12-381 curve. This zkey uses "${verificationKey.curve}".`);
    }

    const curve = await getCurveFromName("bls12381");
    const Fr = curve.Fr;

    try {
        const domainSize = Math.pow(2, verificationKey.power);

        // Precompute root-of-unity powers (following fflonk_export_solidity_verifier.js)
        const w3 = Fr.fromObject(unstringifyBigInts(verificationKey.w3));
        const w3_2 = Fr.square(w3);

        const w4 = Fr.fromObject(unstringifyBigInts(verificationKey.w4));
        const w4_2 = Fr.square(w4);
        const w4_3 = Fr.mul(w4_2, w4);

        const w8 = Fr.fromObject(unstringifyBigInts(verificationKey.w8));
        const w8Powers = [Fr.one];
        for (let i = 1; i < 8; i++) {
            w8Powers[i] = Fr.mul(w8Powers[i - 1], w8);
        }

        const templateData = {
            nPublic: verificationKey.nPublic,
            domain_size: domainSize,
            power: verificationKey.power,
            k1: unstringifyBigInts(verificationKey.k1).toString(),
            k2: unstringifyBigInts(verificationKey.k2).toString(),
            omega: unstringifyBigInts(verificationKey.w).toString(),
            wr: unstringifyBigInts(verificationKey.wr).toString(),

            // Root-of-unity powers
            w3: Fr.toObject(w3).toString(),
            w3_2: Fr.toObject(w3_2).toString(),
            w4: Fr.toObject(w4).toString(),
            w4_2: Fr.toObject(w4_2).toString(),
            w4_3: Fr.toObject(w4_3).toString(),
            w8_1: Fr.toObject(w8Powers[1]).toString(),
            w8_2: Fr.toObject(w8Powers[2]).toString(),
            w8_3: Fr.toObject(w8Powers[3]).toString(),
            w8_4: Fr.toObject(w8Powers[4]).toString(),
            w8_5: Fr.toObject(w8Powers[5]).toString(),
            w8_6: Fr.toObject(w8Powers[6]).toString(),
            w8_7: Fr.toObject(w8Powers[7]).toString(),

            // Compressed VK commitments
            vk_c0: g1CompressedHex(curve, verificationKey.C0),
            vk_x2: g2CompressedHex(curve, verificationKey.X_2),

            // Curve generators
            g1_gen: g1CompressedHex(curve, curve.G1.toObject(curve.G1.g)),
            g2_gen: g2CompressedHex(curve, curve.G2.toObject(curve.G2.g)),

            // Optional embedded test proof
            test_proof: options && options.testProof ? options.testProof : null,
            test_public_signals: options && options.testPublicSignals ? options.testPublicSignals : null,
        };

        const template = templates.fflonk;

        return ejs.render(template, templateData);
    } finally {
        await curve.terminate();
    }
}
