import { utils } from "ffjavascript";
import { getCurveFromName } from "./curves.js";
import { g1CompressedHex, g2CompressedHex } from "./aiken_utils.js";
const { unstringifyBigInts } = utils;

export default async function groth16ExportAikenCallData(_proof, _pub) {
    const proof = unstringifyBigInts(_proof);
    const pub = unstringifyBigInts(_pub);

    const curve = await getCurveFromName("bls12381");

    try {
        const result = {
            pi_a: g1CompressedHex(curve, proof.pi_a),
            pi_b: g2CompressedHex(curve, proof.pi_b),
            pi_c: g1CompressedHex(curve, proof.pi_c),
            public_signals: pub.map(s => s.toString()),
        };

        return JSON.stringify(result, null, 2);
    } finally {
        await curve.terminate();
    }
}
