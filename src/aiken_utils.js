import { utils } from "ffjavascript";
const { unstringifyBigInts } = utils;

// ffjavascript toRprCompressed uses flag layout:
//   bit 7 = "y is greatest", bit 6 = infinity, no compression bit
// Zcash/BLST format (used by Cardano) uses:
//   bit 7 = compressed, bit 6 = infinity, bit 5 = "y is greatest"
// This function converts from ffjavascript to Zcash/BLST format.
function toZcashFlags(buff) {
    const yGreatest = (buff[0] & 0x80) !== 0;
    const infinity = (buff[0] & 0x40) !== 0;
    buff[0] &= 0x1f; // clear top 3 bits
    buff[0] |= 0x80; // set compression flag (bit 7)
    if (infinity) buff[0] |= 0x40;
    if (yGreatest) buff[0] |= 0x20;
}

export function g1CompressedHex(curve, pointObj) {
    const p = unstringifyBigInts(pointObj);
    const internal = curve.G1.fromObject(p);
    const buff = new Uint8Array(curve.G1.F.n8);
    curve.G1.toRprCompressed(buff, 0, internal);
    toZcashFlags(buff);
    return Buffer.from(buff).toString("hex");
}

export function g2CompressedHex(curve, pointObj) {
    const p = unstringifyBigInts(pointObj);
    const internal = curve.G2.fromObject(p);
    const buff = new Uint8Array(curve.G2.F.n8);
    curve.G2.toRprCompressed(buff, 0, internal);
    toZcashFlags(buff);
    return Buffer.from(buff).toString("hex");
}
