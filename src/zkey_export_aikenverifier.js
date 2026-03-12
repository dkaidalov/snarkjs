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

import ejs from "ejs";

import exportVerificationKey from "./zkey_export_verificationkey.js";
import { getCurveFromName } from "./curves.js";
import { g1CompressedHex, g2CompressedHex } from "./aiken_utils.js";

export default async function exportAikenVerifier(zKeyName, templates, logger, options) {

    const verificationKey = await exportVerificationKey(zKeyName, logger);

    if (verificationKey.protocol !== "groth16") {
        throw new Error(`Aiken verifier currently only supports Groth16 protocol. This zkey uses "${verificationKey.protocol}".`);
    }

    if (verificationKey.curve !== "bls12381") {
        throw new Error(`Aiken verifier only supports BLS12-381 curve. This zkey uses "${verificationKey.curve}".`);
    }

    const curve = await getCurveFromName("bls12381");

    try {
        const templateData = {
            nPublic: verificationKey.nPublic,
            vk_alpha_1: g1CompressedHex(curve, verificationKey.vk_alpha_1),
            vk_beta_2: g2CompressedHex(curve, verificationKey.vk_beta_2),
            vk_gamma_2: g2CompressedHex(curve, verificationKey.vk_gamma_2),
            vk_delta_2: g2CompressedHex(curve, verificationKey.vk_delta_2),
            IC: verificationKey.IC.map(ic => g1CompressedHex(curve, ic)),
            test_proof: options && options.testProof ? options.testProof : null,
            test_public_signals: options && options.testPublicSignals ? options.testPublicSignals : null,
        };

        const template = templates.groth16;

        return ejs.render(template, templateData);
    } finally {
        await curve.terminate();
    }
}
