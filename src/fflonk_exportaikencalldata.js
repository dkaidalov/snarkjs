import { utils } from "ffjavascript";
import { getCurveFromName } from "./curves.js";
import { g1CompressedHex } from "./aiken_utils.js";
const { unstringifyBigInts } = utils;

export default async function fflonkExportAikenCallData(_proof, _pub) {
    const proof = unstringifyBigInts(_proof);
    const pub = unstringifyBigInts(_pub);

    const curve = await getCurveFromName("bls12381");

    try {
        const result = {
            // G1 polynomial commitments (compressed, Zcash format)
            c1: g1CompressedHex(curve, proof.polynomials.C1),
            c2: g1CompressedHex(curve, proof.polynomials.C2),
            w1: g1CompressedHex(curve, proof.polynomials.W1),
            w2: g1CompressedHex(curve, proof.polynomials.W2),
            // Polynomial evaluations (Fr scalars as decimal strings)
            eval_ql:  proof.evaluations.ql.toString(),
            eval_qr:  proof.evaluations.qr.toString(),
            eval_qm:  proof.evaluations.qm.toString(),
            eval_qo:  proof.evaluations.qo.toString(),
            eval_qc:  proof.evaluations.qc.toString(),
            eval_s1:  proof.evaluations.s1.toString(),
            eval_s2:  proof.evaluations.s2.toString(),
            eval_s3:  proof.evaluations.s3.toString(),
            eval_a:   proof.evaluations.a.toString(),
            eval_b:   proof.evaluations.b.toString(),
            eval_c:   proof.evaluations.c.toString(),
            eval_z:   proof.evaluations.z.toString(),
            eval_zw:  proof.evaluations.zw.toString(),
            eval_t1w: proof.evaluations.t1w.toString(),
            eval_t2w: proof.evaluations.t2w.toString(),
            eval_inv: proof.evaluations.inv.toString(),
            // Public inputs
            public_signals: pub.map(s => s.toString()),
        };

        return JSON.stringify(result, null, 2);
    } finally {
        await curve.terminate();
    }
}
