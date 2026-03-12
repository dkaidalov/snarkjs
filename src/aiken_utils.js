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
const { unstringifyBigInts } = utils;

export function g1CompressedHex(curve, pointObj) {
    const p = unstringifyBigInts(pointObj);
    const internal = curve.G1.fromObject(p);
    const buff = new Uint8Array(curve.G1.F.n8);
    curve.G1.toRprCompressed(buff, 0, internal);
    return Buffer.from(buff).toString("hex");
}

export function g2CompressedHex(curve, pointObj) {
    const p = unstringifyBigInts(pointObj);
    const internal = curve.G2.fromObject(p);
    const buff = new Uint8Array(curve.G2.F.n8);
    curve.G2.toRprCompressed(buff, 0, internal);
    return Buffer.from(buff).toString("hex");
}
