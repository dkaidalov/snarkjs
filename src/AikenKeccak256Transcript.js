import {Scalar} from "ffjavascript";
import {keccak_256} from "@noble/hashes/sha3";

const POLYNOMIAL = 0;
const SCALAR = 1;

// Converts ffjavascript compressed flag layout to Zcash/BLST format (used by Cardano).
// ffjavascript: bit 7 = "y is greatest", bit 6 = infinity (no compression bit)
// Zcash/BLST:   bit 7 = compressed,      bit 6 = infinity, bit 5 = "y is greatest"
function toZcashFlags(buff) {
    const yGreatest = (buff[0] & 0x80) !== 0;
    const infinity = (buff[0] & 0x40) !== 0;
    buff[0] &= 0x1f;
    buff[0] |= 0x80; // set compression flag
    if (infinity) buff[0] |= 0x40;
    if (yGreatest) buff[0] |= 0x20;
}

// Variant of Keccak256Transcript that uses compressed G1 points (Zcash/BLST format, 48 bytes)
// instead of uncompressed (96 bytes). Used for BLS12-381 PLONK so that the Aiken on-chain
// verifier can compute the same challenges using the compressed calldata bytes directly.
export class AikenKeccak256Transcript {
    constructor(curve) {
        this.G1 = curve.G1;
        this.Fr = curve.Fr;

        this.reset();
    }

    reset() {
        this.data = [];
    }

    addPolCommitment(polynomialCommitment) {
        this.data.push({type: POLYNOMIAL, data: polynomialCommitment});
    }

    addScalar(scalar) {
        this.data.push({type: SCALAR, data: scalar});
    }

    getChallenge() {
        if(0 === this.data.length) {
            throw new Error("AikenKeccak256Transcript: No data to generate a transcript");
        }

        let nPolynomials = 0;
        let nScalars = 0;

        this.data.forEach(element => POLYNOMIAL === element.type ? nPolynomials++ : nScalars++);

        // G1 compressed size = G1.F.n8 (48 bytes for BLS12-381), not G1.F.n8 * 2 (uncompressed)
        let buffer = new Uint8Array(nScalars * this.Fr.n8 + nPolynomials * this.G1.F.n8);
        let offset = 0;

        for (let i = 0; i < this.data.length; i++) {
            if (POLYNOMIAL === this.data[i].type) {
                const compressed = new Uint8Array(this.G1.F.n8);
                this.G1.toRprCompressed(compressed, 0, this.data[i].data);
                toZcashFlags(compressed);
                buffer.set(compressed, offset);
                offset += this.G1.F.n8;
            } else {
                this.Fr.toRprBE(buffer, offset, this.data[i].data);
                offset += this.Fr.n8;
            }
        }

        const value = Scalar.fromRprBE(keccak_256(buffer));
        return this.Fr.e(value);
    }
}
