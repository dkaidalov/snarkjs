/*
    Copyright 2024 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

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
