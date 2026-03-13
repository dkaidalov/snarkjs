import { utils } from "ffjavascript";
import { getCurveFromName } from "./curves.js";
import { g1CompressedHex } from "./aiken_utils.js";
const { unstringifyBigInts } = utils;

export default async function plonkExportAikenCallData(_proof, _pub) {
    const proof = unstringifyBigInts(_proof);
    const pub = unstringifyBigInts(_pub);

    const curve = await getCurveFromName("bls12381");

    try {
        const result = {
            // G1 polynomial commitments (compressed, Zcash format)
            a:    g1CompressedHex(curve, proof.A),
            b:    g1CompressedHex(curve, proof.B),
            c:    g1CompressedHex(curve, proof.C),
            z:    g1CompressedHex(curve, proof.Z),
            t1:   g1CompressedHex(curve, proof.T1),
            t2:   g1CompressedHex(curve, proof.T2),
            t3:   g1CompressedHex(curve, proof.T3),
            wxi:  g1CompressedHex(curve, proof.Wxi),
            wxiw: g1CompressedHex(curve, proof.Wxiw),
            // Polynomial evaluations (Fr scalars as decimal strings)
            eval_a:   proof.eval_a.toString(),
            eval_b:   proof.eval_b.toString(),
            eval_c:   proof.eval_c.toString(),
            eval_s1:  proof.eval_s1.toString(),
            eval_s2:  proof.eval_s2.toString(),
            eval_zw:  proof.eval_zw.toString(),
            // Public inputs
            public_signals: pub.map(s => s.toString()),
        };

        return JSON.stringify(result, null, 2);
    } finally {
        await curve.terminate();
    }
}
