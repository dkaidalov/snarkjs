// Generated with snarkJS
//
// snarkJS is a free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// FFLONK BLS12-381 verifier for Aiken (Cardano).
// Fiat-Shamir transcript uses Keccak-256 with compressed G1 points (Zcash/BLST format).

use aiken/builtin

// ===== Verification Key =====

// C0 commitment (G1 compressed, 48 bytes, Zcash format)
const vk_c0: ByteArray = #"93f8dd89ecc8c1ddcaac28407d7852b7d91f7801007740cc1bdd52a0fd80166af001e9efc56e90008cb172d0dc2dfd76"

// KZG SRS commitment (G2 compressed, 96 bytes)
const vk_x2: ByteArray = #"9709a836290e4301d14d5522b1b1f44d948cac2a9673f7d8128c0cbe453538e330d9cf8ef005d9abfca87542344b70c518ec0d5f56f7b23dc6749d35d8d46cd94706c64863669360b6de19b01446c41d628f250c6e81671c50ad4cfb3a657f26"

// Domain parameters (embedded from zkey)
const domain_size: Int = 32
const k1: Int = 2
const k2: Int = 3
const omega: Int = 32311457133713125762627935188100354218453688428796477340173861531654182464166
const wr: Int = 39328881859443649819318207548060215749094715634259317161033277606721139812495

// Precomputed roots of unity
const w3: Int = 228988810152649578064853576960394133503
const w3_2: Int = 52435875175126190479447740508185965837461563690374988244538805122978187051009
const w4: Int = 3465144826073652318776269530687742778270252468765361963008
const w4_2: Int = 52435875175126190479447740508185965837690552500527637822603658699938581184512
const w4_3: Int = 52435875175126190475982595682112313518914282969839895044333406231173219221505
const w8_1: Int = 28761180743467419819834788392525162889723178799021384024940474588120723734663
const w8_2: Int = 3465144826073652318776269530687742778270252468765361963008
const w8_3: Int = 43750592090951839482975286585531043674810095682058858279538876507215901405139
const w8_4: Int = 52435875175126190479447740508185965837690552500527637822603658699938581184512
const w8_5: Int = 23674694431658770659612952115660802947967373701506253797663184111817857449850
const w8_6: Int = 52435875175126190475982595682112313518914282969839895044333406231173219221505
const w8_7: Int = 8685283084174350996472453922654922162880456818468779543064782192722679779374

// BLS12-381 scalar field modulus r
const r: Int =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

// Curve generators (compressed)
const g1_gen: ByteArray = #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
const g2_gen: ByteArray = #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// ===== Proof type =====

pub type FflonkProof {
  // G1 polynomial commitments (compressed, 48 bytes each, Zcash format)
  c1: ByteArray,
  c2: ByteArray,
  w1: ByteArray,
  w2: ByteArray,
  // Polynomial evaluations at challenge xi (scalars in Fr)
  eval_ql: Int,
  eval_qr: Int,
  eval_qm: Int,
  eval_qo: Int,
  eval_qc: Int,
  eval_s1: Int,
  eval_s2: Int,
  eval_s3: Int,
  eval_a: Int,
  eval_b: Int,
  eval_c: Int,
  eval_z: Int,
  eval_zw: Int,
  eval_t1w: Int,
  eval_t2w: Int,
}

// ===== FFLONK verifier =====

/// FFLONK proof verification for BLS12-381.
///
/// Arguments:
///   proof          - FFLONK proof (4 G1 commitments + 15 polynomial evaluations)
///   public_signals - list of public input scalars (must have 2 element(s))
///
/// Returns True if the proof is valid.
pub fn verify(proof: FflonkProof, public_signals: List<Int>) -> Bool {
  // ----- Uncompress proof G1 points -----
  let pt_c1 = builtin.bls12_381_g1_uncompress(proof.c1)
  let pt_c2 = builtin.bls12_381_g1_uncompress(proof.c2)
  let pt_w1 = builtin.bls12_381_g1_uncompress(proof.w1)
  let pt_w2 = builtin.bls12_381_g1_uncompress(proof.w2)

  // ----- Uncompress VK points -----
  let pt_c0 = builtin.bls12_381_g1_uncompress(vk_c0)
  let pt_x2 = builtin.bls12_381_g2_uncompress(vk_x2)
  let pt_g1 = builtin.bls12_381_g1_uncompress(g1_gen)
  let pt_g2 = builtin.bls12_381_g2_uncompress(g2_gen)

  // ----- Fiat-Shamir challenges (Keccak256 with compressed G1 points, with resets) -----

  // beta = H(C0 || public_inputs || C1)
  let beta =
    keccak_challenge(
      ba(ba(vk_c0, signals_to_bytes(public_signals)), proof.c1)
    )

  // gamma = H(beta)
  let gamma = keccak_challenge(fr_to_bytes(beta))

  // xiSeed = H(gamma || C2)
  let xi_seed = keccak_challenge(ba(fr_to_bytes(gamma), proof.c2))
  let xi_seed2 = fr_mul(xi_seed, xi_seed)

  // ----- Compute evaluation roots -----

  // h0 = xiSeed^3
  let h0 = fr_mul(xi_seed2, xi_seed)
  // h0w8[0..7] = h0 * w8^i
  let h0w8_0 = h0
  let h0w8_1 = fr_mul(h0, w8_1)
  let h0w8_2 = fr_mul(h0, w8_2)
  let h0w8_3 = fr_mul(h0, w8_3)
  let h0w8_4 = fr_mul(h0, w8_4)
  let h0w8_5 = fr_mul(h0, w8_5)
  let h0w8_6 = fr_mul(h0, w8_6)
  let h0w8_7 = fr_mul(h0, w8_7)

  // h1 = xiSeed^6 = h0^2
  let h1 = fr_mul(h0, h0)
  // h1w4[0..3] = h1 * w4^i
  let h1w4_0 = h1
  let h1w4_1 = fr_mul(h1, w4)
  let h1w4_2 = fr_mul(h1, w4_2)
  let h1w4_3 = fr_mul(h1, w4_3)

  // h2 = xiSeed^8 = h1 * xiSeed^2
  let h2 = fr_mul(h1, xi_seed2)
  // h2w3[0..2] = h2 * w3^i
  let h2w3_0 = h2
  let h2w3_1 = fr_mul(h2, w3)
  let h2w3_2 = fr_mul(h2, w3_2)

  // h3 = h2 * wr (cube root of omega)
  let h3 = fr_mul(h2, wr)
  // h3w3[0..2] = h3 * w3^i
  let h3w3_0 = h3
  let h3w3_1 = fr_mul(h3, w3)
  let h3w3_2 = fr_mul(h3, w3_2)

  // xi = h2^3 = xiSeed^24
  let xi = fr_mul(fr_mul(h2, h2), h2)
  let xiw = fr_mul(xi, omega)

  // xiN = xi^domainSize
  let xin = fr_pow(xi, domain_size)
  // zh = xiN - 1 (vanishing polynomial at xi)
  let zh = fr_sub(xin, 1)

  // alpha = H(xiSeed || ql || qr || qm || qo || qc || s1 || s2 || s3 || a || b || c || z || zw || t1w || t2w)
  let alpha =
    keccak_challenge(
      ba(ba(ba(ba(ba(ba(ba(ba(ba(ba(ba(ba(ba(ba(ba(
        fr_to_bytes(xi_seed),
        fr_to_bytes(proof.eval_ql)),
        fr_to_bytes(proof.eval_qr)),
        fr_to_bytes(proof.eval_qm)),
        fr_to_bytes(proof.eval_qo)),
        fr_to_bytes(proof.eval_qc)),
        fr_to_bytes(proof.eval_s1)),
        fr_to_bytes(proof.eval_s2)),
        fr_to_bytes(proof.eval_s3)),
        fr_to_bytes(proof.eval_a)),
        fr_to_bytes(proof.eval_b)),
        fr_to_bytes(proof.eval_c)),
        fr_to_bytes(proof.eval_z)),
        fr_to_bytes(proof.eval_zw)),
        fr_to_bytes(proof.eval_t1w)),
        fr_to_bytes(proof.eval_t2w))
    )

  // y = H(alpha || W1)
  let y = keccak_challenge(ba(fr_to_bytes(alpha), proof.w1))

  // ----- Lagrange evaluations for PI(xi) -----
  // L_i(xi) = omega^(i-1) * zh / (domainSize * (xi - omega^(i-1)))
  let inv_zh = fr_inv(zh)
  let l1 = fr_mul(zh, fr_inv(fr_mul(domain_size, fr_sub(xi, 1))))

  let l2_w = fr_pow(omega, 1)
  let l2 =
    fr_mul(
      fr_mul(l2_w, zh),
      fr_inv(fr_mul(domain_size, fr_sub(xi, l2_w)))
    )

  // ----- PI polynomial: PI(xi) = -sum_{i=0}^{nPublic-1}(public_signals[i] * L[i+1]) -----
  let pi_pos =
    fr_add(
      fr_mul(list_at_or_zero(public_signals, 0), l1),
    fr_mul(list_at_or_zero(public_signals, 1), l2)
    )
  let pi = fr_neg(pi_pos)

  // ----- Batch inversion for Lagrange denominators -----
  // We need 18 inversions total: 8 for S0, 4 for S1, 6 for S2.
  // Use Montgomery's trick to reduce to 1 inversion + ~50 multiplications.

  // S0 Lagrange: Li = (y^8 - xi) / (8 * h0^7 * w8[(7*i)%8] * (y - h0w8[i]))
  let y2 = fr_mul(y, y)
  let y3 = fr_mul(y2, y)
  let y4 = fr_mul(y2, y2)
  let y6 = fr_mul(y4, y2)
  let y8 = fr_mul(y4, y4)

  let num_s0 = fr_sub(y8, xi)
  // den1_s0 = 8 * h0^7
  let h0_2 = h1
  let h0_3 = fr_mul(h0_2, h0)
  let h0_6 = fr_mul(h0_3, h0_3)
  let h0_7 = fr_mul(h0_6, h0)
  let den1_s0 = fr_mul(8, h0_7)

  // den3 factors: (y - h0w8[i]) for each i
  let d_s0_0 = fr_sub(y, h0w8_0)
  let d_s0_1 = fr_sub(y, h0w8_1)
  let d_s0_2 = fr_sub(y, h0w8_2)
  let d_s0_3 = fr_sub(y, h0w8_3)
  let d_s0_4 = fr_sub(y, h0w8_4)
  let d_s0_5 = fr_sub(y, h0w8_5)
  let d_s0_6 = fr_sub(y, h0w8_6)
  let d_s0_7 = fr_sub(y, h0w8_7)

  // Full denominators: den1_s0 * w8[(7*i)%8] * (y - h0w8[i])
  let full_d_s0_0 = fr_mul(den1_s0, d_s0_0)
  let full_d_s0_1 = fr_mul(fr_mul(den1_s0, w8_7), d_s0_1)
  let full_d_s0_2 = fr_mul(fr_mul(den1_s0, w8_6), d_s0_2)
  let full_d_s0_3 = fr_mul(fr_mul(den1_s0, w8_5), d_s0_3)
  let full_d_s0_4 = fr_mul(fr_mul(den1_s0, w8_4), d_s0_4)
  let full_d_s0_5 = fr_mul(fr_mul(den1_s0, w8_3), d_s0_5)
  let full_d_s0_6 = fr_mul(fr_mul(den1_s0, w8_2), d_s0_6)
  let full_d_s0_7 = fr_mul(fr_mul(den1_s0, w8_1), d_s0_7)

  // S1 Lagrange: Li = (y^4 - xi) / (4 * h1^3 * w4[(3*i)%4] * (y - h1w4[i]))
  let num_s1 = fr_sub(y4, xi)
  // den1_s1 = 4 * h1^3
  let h1_2 = fr_mul(h1, h1)
  let h1_3 = fr_mul(h1_2, h1)
  let den1_s1 = fr_mul(4, h1_3)

  let d_s1_0 = fr_sub(y, h1w4_0)
  let d_s1_1 = fr_sub(y, h1w4_1)
  let d_s1_2 = fr_sub(y, h1w4_2)
  let d_s1_3 = fr_sub(y, h1w4_3)

  // Full denominators: den1_s1 * w4[(3*i)%4] * (y - h1w4[i])
  let full_d_s1_0 = fr_mul(den1_s1, d_s1_0)
  let full_d_s1_1 = fr_mul(fr_mul(den1_s1, w4_3), d_s1_1)
  let full_d_s1_2 = fr_mul(fr_mul(den1_s1, w4_2), d_s1_2)
  let full_d_s1_3 = fr_mul(fr_mul(den1_s1, w4), d_s1_3)

  // S2 Lagrange (two groups sharing a numerator):
  // num = y^6 - (xi + xiw)*y^3 + xi*xiw
  let num_s2 = fr_add(fr_sub(y6, fr_mul(fr_add(xi, xiw), y3)), fr_mul(xi, xiw))

  // Group h2w3: den = 3 * h2^2 * (xi - xiw) * w3[(2*i)%3] * (y - h2w3[i])
  let xi_diff = fr_sub(xi, xiw)
  let h2_2 = fr_mul(h2, h2)
  let den1_h2 = fr_mul(fr_mul(3, h2_2), xi_diff)

  let d_h2_0 = fr_sub(y, h2w3_0)
  let d_h2_1 = fr_sub(y, h2w3_1)
  let d_h2_2 = fr_sub(y, h2w3_2)

  let full_d_h2_0 = fr_mul(den1_h2, d_h2_0)
  let full_d_h2_1 = fr_mul(fr_mul(den1_h2, w3_2), d_h2_1)
  let full_d_h2_2 = fr_mul(fr_mul(den1_h2, w3), d_h2_2)

  // Group h3w3: den = 3 * h3^2 * (xiw - xi) * w3[(2*i)%3] * (y - h3w3[i])
  let xiw_diff = fr_sub(xiw, xi)
  let h3_2 = fr_mul(h3, h3)
  let den1_h3 = fr_mul(fr_mul(3, h3_2), xiw_diff)

  let d_h3_0 = fr_sub(y, h3w3_0)
  let d_h3_1 = fr_sub(y, h3w3_1)
  let d_h3_2 = fr_sub(y, h3w3_2)

  let full_d_h3_0 = fr_mul(den1_h3, d_h3_0)
  let full_d_h3_1 = fr_mul(fr_mul(den1_h3, w3_2), d_h3_1)
  let full_d_h3_2 = fr_mul(fr_mul(den1_h3, w3), d_h3_2)

  // ----- Montgomery batch inversion (18 inversions -> 1) -----
  let p0 = full_d_s0_0
  let p1 = fr_mul(p0, full_d_s0_1)
  let p2 = fr_mul(p1, full_d_s0_2)
  let p3 = fr_mul(p2, full_d_s0_3)
  let p4 = fr_mul(p3, full_d_s0_4)
  let p5 = fr_mul(p4, full_d_s0_5)
  let p6 = fr_mul(p5, full_d_s0_6)
  let p7 = fr_mul(p6, full_d_s0_7)
  let p8 = fr_mul(p7, full_d_s1_0)
  let p9 = fr_mul(p8, full_d_s1_1)
  let p10 = fr_mul(p9, full_d_s1_2)
  let p11 = fr_mul(p10, full_d_s1_3)
  let p12 = fr_mul(p11, full_d_h2_0)
  let p13 = fr_mul(p12, full_d_h2_1)
  let p14 = fr_mul(p13, full_d_h2_2)
  let p15 = fr_mul(p14, full_d_h3_0)
  let p16 = fr_mul(p15, full_d_h3_1)
  let p17 = fr_mul(p16, full_d_h3_2)

  // Single inversion
  let inv_all = fr_inv(p17)

  // Back-propagate individual inverses
  let inv_d_h3_2 = fr_mul(inv_all, p16)
  let inv_all_16 = fr_mul(inv_all, full_d_h3_2)
  let inv_d_h3_1 = fr_mul(inv_all_16, p15)
  let inv_all_15 = fr_mul(inv_all_16, full_d_h3_1)
  let inv_d_h3_0 = fr_mul(inv_all_15, p14)
  let inv_all_14 = fr_mul(inv_all_15, full_d_h3_0)
  let inv_d_h2_2 = fr_mul(inv_all_14, p13)
  let inv_all_13 = fr_mul(inv_all_14, full_d_h2_2)
  let inv_d_h2_1 = fr_mul(inv_all_13, p12)
  let inv_all_12 = fr_mul(inv_all_13, full_d_h2_1)
  let inv_d_h2_0 = fr_mul(inv_all_12, p11)
  let inv_all_11 = fr_mul(inv_all_12, full_d_h2_0)
  let inv_d_s1_3 = fr_mul(inv_all_11, p10)
  let inv_all_10 = fr_mul(inv_all_11, full_d_s1_3)
  let inv_d_s1_2 = fr_mul(inv_all_10, p9)
  let inv_all_9 = fr_mul(inv_all_10, full_d_s1_2)
  let inv_d_s1_1 = fr_mul(inv_all_9, p8)
  let inv_all_8 = fr_mul(inv_all_9, full_d_s1_1)
  let inv_d_s1_0 = fr_mul(inv_all_8, p7)
  let inv_all_7 = fr_mul(inv_all_8, full_d_s1_0)
  let inv_d_s0_7 = fr_mul(inv_all_7, p6)
  let inv_all_6 = fr_mul(inv_all_7, full_d_s0_7)
  let inv_d_s0_6 = fr_mul(inv_all_6, p5)
  let inv_all_5 = fr_mul(inv_all_6, full_d_s0_6)
  let inv_d_s0_5 = fr_mul(inv_all_5, p4)
  let inv_all_4 = fr_mul(inv_all_5, full_d_s0_5)
  let inv_d_s0_4 = fr_mul(inv_all_4, p3)
  let inv_all_3 = fr_mul(inv_all_4, full_d_s0_4)
  let inv_d_s0_3 = fr_mul(inv_all_3, p2)
  let inv_all_2 = fr_mul(inv_all_3, full_d_s0_3)
  let inv_d_s0_2 = fr_mul(inv_all_2, p1)
  let inv_all_1 = fr_mul(inv_all_2, full_d_s0_2)
  let inv_d_s0_1 = fr_mul(inv_all_1, p0)
  let inv_d_s0_0 = fr_mul(inv_all_1, full_d_s0_1)

  // Lagrange basis values: Li = num * inv_den
  let li_s0_0 = fr_mul(num_s0, inv_d_s0_0)
  let li_s0_1 = fr_mul(num_s0, inv_d_s0_1)
  let li_s0_2 = fr_mul(num_s0, inv_d_s0_2)
  let li_s0_3 = fr_mul(num_s0, inv_d_s0_3)
  let li_s0_4 = fr_mul(num_s0, inv_d_s0_4)
  let li_s0_5 = fr_mul(num_s0, inv_d_s0_5)
  let li_s0_6 = fr_mul(num_s0, inv_d_s0_6)
  let li_s0_7 = fr_mul(num_s0, inv_d_s0_7)

  let li_s1_0 = fr_mul(num_s1, inv_d_s1_0)
  let li_s1_1 = fr_mul(num_s1, inv_d_s1_1)
  let li_s1_2 = fr_mul(num_s1, inv_d_s1_2)
  let li_s1_3 = fr_mul(num_s1, inv_d_s1_3)

  let li_h2_0 = fr_mul(num_s2, inv_d_h2_0)
  let li_h2_1 = fr_mul(num_s2, inv_d_h2_1)
  let li_h2_2 = fr_mul(num_s2, inv_d_h2_2)

  let li_h3_0 = fr_mul(num_s2, inv_d_h3_0)
  let li_h3_1 = fr_mul(num_s2, inv_d_h3_1)
  let li_h3_2 = fr_mul(num_s2, inv_d_h3_2)

  // ----- Compute r0 (Lagrange interpolation at 8 roots h0w8) -----
  // For each i: c0_i = ql + qr*h + qo*h^2 + qm*h^3 + qc*h^4 + s1*h^5 + s2*h^6 + s3*h^7
  // where h = h0w8[i]

  let hv0_1 = h0w8_0
  let hv0_2 = fr_mul(hv0_1, h0w8_0)
  let hv0_3 = fr_mul(hv0_2, h0w8_0)
  let hv0_4 = fr_mul(hv0_3, h0w8_0)
  let hv0_5 = fr_mul(hv0_4, h0w8_0)
  let hv0_6 = fr_mul(hv0_5, h0w8_0)
  let hv0_7 = fr_mul(hv0_6, h0w8_0)
  let c0_0 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv0_1)),
      fr_mul(proof.eval_qo, hv0_2)),
      fr_mul(proof.eval_qm, hv0_3)),
      fr_mul(proof.eval_qc, hv0_4)),
      fr_mul(proof.eval_s1, hv0_5)),
      fr_mul(proof.eval_s2, hv0_6)),
      fr_mul(proof.eval_s3, hv0_7))

  let hv1_1 = h0w8_1
  let hv1_2 = fr_mul(hv1_1, h0w8_1)
  let hv1_3 = fr_mul(hv1_2, h0w8_1)
  let hv1_4 = fr_mul(hv1_3, h0w8_1)
  let hv1_5 = fr_mul(hv1_4, h0w8_1)
  let hv1_6 = fr_mul(hv1_5, h0w8_1)
  let hv1_7 = fr_mul(hv1_6, h0w8_1)
  let c0_1 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv1_1)),
      fr_mul(proof.eval_qo, hv1_2)),
      fr_mul(proof.eval_qm, hv1_3)),
      fr_mul(proof.eval_qc, hv1_4)),
      fr_mul(proof.eval_s1, hv1_5)),
      fr_mul(proof.eval_s2, hv1_6)),
      fr_mul(proof.eval_s3, hv1_7))

  let hv2_1 = h0w8_2
  let hv2_2 = fr_mul(hv2_1, h0w8_2)
  let hv2_3 = fr_mul(hv2_2, h0w8_2)
  let hv2_4 = fr_mul(hv2_3, h0w8_2)
  let hv2_5 = fr_mul(hv2_4, h0w8_2)
  let hv2_6 = fr_mul(hv2_5, h0w8_2)
  let hv2_7 = fr_mul(hv2_6, h0w8_2)
  let c0_2 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv2_1)),
      fr_mul(proof.eval_qo, hv2_2)),
      fr_mul(proof.eval_qm, hv2_3)),
      fr_mul(proof.eval_qc, hv2_4)),
      fr_mul(proof.eval_s1, hv2_5)),
      fr_mul(proof.eval_s2, hv2_6)),
      fr_mul(proof.eval_s3, hv2_7))

  let hv3_1 = h0w8_3
  let hv3_2 = fr_mul(hv3_1, h0w8_3)
  let hv3_3 = fr_mul(hv3_2, h0w8_3)
  let hv3_4 = fr_mul(hv3_3, h0w8_3)
  let hv3_5 = fr_mul(hv3_4, h0w8_3)
  let hv3_6 = fr_mul(hv3_5, h0w8_3)
  let hv3_7 = fr_mul(hv3_6, h0w8_3)
  let c0_3 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv3_1)),
      fr_mul(proof.eval_qo, hv3_2)),
      fr_mul(proof.eval_qm, hv3_3)),
      fr_mul(proof.eval_qc, hv3_4)),
      fr_mul(proof.eval_s1, hv3_5)),
      fr_mul(proof.eval_s2, hv3_6)),
      fr_mul(proof.eval_s3, hv3_7))

  let hv4_1 = h0w8_4
  let hv4_2 = fr_mul(hv4_1, h0w8_4)
  let hv4_3 = fr_mul(hv4_2, h0w8_4)
  let hv4_4 = fr_mul(hv4_3, h0w8_4)
  let hv4_5 = fr_mul(hv4_4, h0w8_4)
  let hv4_6 = fr_mul(hv4_5, h0w8_4)
  let hv4_7 = fr_mul(hv4_6, h0w8_4)
  let c0_4 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv4_1)),
      fr_mul(proof.eval_qo, hv4_2)),
      fr_mul(proof.eval_qm, hv4_3)),
      fr_mul(proof.eval_qc, hv4_4)),
      fr_mul(proof.eval_s1, hv4_5)),
      fr_mul(proof.eval_s2, hv4_6)),
      fr_mul(proof.eval_s3, hv4_7))

  let hv5_1 = h0w8_5
  let hv5_2 = fr_mul(hv5_1, h0w8_5)
  let hv5_3 = fr_mul(hv5_2, h0w8_5)
  let hv5_4 = fr_mul(hv5_3, h0w8_5)
  let hv5_5 = fr_mul(hv5_4, h0w8_5)
  let hv5_6 = fr_mul(hv5_5, h0w8_5)
  let hv5_7 = fr_mul(hv5_6, h0w8_5)
  let c0_5 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv5_1)),
      fr_mul(proof.eval_qo, hv5_2)),
      fr_mul(proof.eval_qm, hv5_3)),
      fr_mul(proof.eval_qc, hv5_4)),
      fr_mul(proof.eval_s1, hv5_5)),
      fr_mul(proof.eval_s2, hv5_6)),
      fr_mul(proof.eval_s3, hv5_7))

  let hv6_1 = h0w8_6
  let hv6_2 = fr_mul(hv6_1, h0w8_6)
  let hv6_3 = fr_mul(hv6_2, h0w8_6)
  let hv6_4 = fr_mul(hv6_3, h0w8_6)
  let hv6_5 = fr_mul(hv6_4, h0w8_6)
  let hv6_6 = fr_mul(hv6_5, h0w8_6)
  let hv6_7 = fr_mul(hv6_6, h0w8_6)
  let c0_6 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv6_1)),
      fr_mul(proof.eval_qo, hv6_2)),
      fr_mul(proof.eval_qm, hv6_3)),
      fr_mul(proof.eval_qc, hv6_4)),
      fr_mul(proof.eval_s1, hv6_5)),
      fr_mul(proof.eval_s2, hv6_6)),
      fr_mul(proof.eval_s3, hv6_7))

  let hv7_1 = h0w8_7
  let hv7_2 = fr_mul(hv7_1, h0w8_7)
  let hv7_3 = fr_mul(hv7_2, h0w8_7)
  let hv7_4 = fr_mul(hv7_3, h0w8_7)
  let hv7_5 = fr_mul(hv7_4, h0w8_7)
  let hv7_6 = fr_mul(hv7_5, h0w8_7)
  let hv7_7 = fr_mul(hv7_6, h0w8_7)
  let c0_7 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      proof.eval_ql,
      fr_mul(proof.eval_qr, hv7_1)),
      fr_mul(proof.eval_qo, hv7_2)),
      fr_mul(proof.eval_qm, hv7_3)),
      fr_mul(proof.eval_qc, hv7_4)),
      fr_mul(proof.eval_s1, hv7_5)),
      fr_mul(proof.eval_s2, hv7_6)),
      fr_mul(proof.eval_s3, hv7_7))

  let r0 =
    fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(fr_add(
      fr_mul(c0_0, li_s0_0),
      fr_mul(c0_1, li_s0_1)),
      fr_mul(c0_2, li_s0_2)),
      fr_mul(c0_3, li_s0_3)),
      fr_mul(c0_4, li_s0_4)),
      fr_mul(c0_5, li_s0_5)),
      fr_mul(c0_6, li_s0_6)),
      fr_mul(c0_7, li_s0_7))

  // ----- Compute r1 (Lagrange interpolation at 4 roots h1w4) -----
  // T0(xi) = (ql*a + qr*b + qm*a*b + qo*c + qc + pi) / zh
  let t0_num =
    fr_add(fr_add(fr_add(fr_add(fr_add(
      fr_mul(proof.eval_ql, proof.eval_a),
      fr_mul(proof.eval_qr, proof.eval_b)),
      fr_mul(proof.eval_qm, fr_mul(proof.eval_a, proof.eval_b))),
      fr_mul(proof.eval_qo, proof.eval_c)),
      proof.eval_qc),
      pi)
  let t0 = fr_mul(t0_num, inv_zh)

  // For each i: c1_i = a + h1w4_i*b + h1w4_i^2*c + h1w4_i^3*t0
  let h1w4_0_sq = fr_mul(h1w4_0, h1w4_0)
  let c1_0 = fr_add(fr_add(fr_add(
    proof.eval_a,
    fr_mul(h1w4_0, proof.eval_b)),
    fr_mul(h1w4_0_sq, proof.eval_c)),
    fr_mul(fr_mul(h1w4_0_sq, h1w4_0), t0))

  let h1w4_1_sq = fr_mul(h1w4_1, h1w4_1)
  let c1_1 = fr_add(fr_add(fr_add(
    proof.eval_a,
    fr_mul(h1w4_1, proof.eval_b)),
    fr_mul(h1w4_1_sq, proof.eval_c)),
    fr_mul(fr_mul(h1w4_1_sq, h1w4_1), t0))

  let h1w4_2_sq = fr_mul(h1w4_2, h1w4_2)
  let c1_2 = fr_add(fr_add(fr_add(
    proof.eval_a,
    fr_mul(h1w4_2, proof.eval_b)),
    fr_mul(h1w4_2_sq, proof.eval_c)),
    fr_mul(fr_mul(h1w4_2_sq, h1w4_2), t0))

  let h1w4_3_sq = fr_mul(h1w4_3, h1w4_3)
  let c1_3 = fr_add(fr_add(fr_add(
    proof.eval_a,
    fr_mul(h1w4_3, proof.eval_b)),
    fr_mul(h1w4_3_sq, proof.eval_c)),
    fr_mul(fr_mul(h1w4_3_sq, h1w4_3), t0))

  let r1 =
    fr_add(fr_add(fr_add(
      fr_mul(c1_0, li_s1_0),
      fr_mul(c1_1, li_s1_1)),
      fr_mul(c1_2, li_s1_2)),
      fr_mul(c1_3, li_s1_3))

  // ----- Compute r2 (Lagrange interpolation at 6 roots: h2w3 and h3w3) -----
  // T1(xi) = (z - 1) * L1 / zh
  let t1 = fr_mul(fr_mul(fr_sub(proof.eval_z, 1), l1), inv_zh)

  // T2(xi) = [(a+beta*xi+gamma)(b+beta*xi*k1+gamma)(c+beta*xi*k2+gamma)*z
  //          -(a+beta*s1+gamma)(b+beta*s2+gamma)(c+beta*s3+gamma)*zw] / zh
  let betaxi = fr_mul(beta, xi)
  let t211 = fr_add(fr_add(proof.eval_a, betaxi), gamma)
  let t212 = fr_add(fr_add(proof.eval_b, fr_mul(betaxi, k1)), gamma)
  let t213 = fr_add(fr_add(proof.eval_c, fr_mul(betaxi, k2)), gamma)
  let t21 = fr_mul(fr_mul(fr_mul(t211, t212), t213), proof.eval_z)

  let t221 = fr_add(fr_add(proof.eval_a, fr_mul(beta, proof.eval_s1)), gamma)
  let t222 = fr_add(fr_add(proof.eval_b, fr_mul(beta, proof.eval_s2)), gamma)
  let t223 = fr_add(fr_add(proof.eval_c, fr_mul(beta, proof.eval_s3)), gamma)
  let t22 = fr_mul(fr_mul(fr_mul(t221, t222), t223), proof.eval_zw)

  let t2 = fr_mul(fr_sub(t21, t22), inv_zh)

  // h2w3 group: c2_i = z + h2w3_i * t1 + h2w3_i^2 * t2
  let c2_h2_0 = fr_add(fr_add(proof.eval_z, fr_mul(h2w3_0, t1)), fr_mul(fr_mul(h2w3_0, h2w3_0), t2))
  let c2_h2_1 = fr_add(fr_add(proof.eval_z, fr_mul(h2w3_1, t1)), fr_mul(fr_mul(h2w3_1, h2w3_1), t2))
  let c2_h2_2 = fr_add(fr_add(proof.eval_z, fr_mul(h2w3_2, t1)), fr_mul(fr_mul(h2w3_2, h2w3_2), t2))

  // h3w3 group: c2_i = zw + h3w3_i * t1w + h3w3_i^2 * t2w
  let c2_h3_0 = fr_add(fr_add(proof.eval_zw, fr_mul(h3w3_0, proof.eval_t1w)), fr_mul(fr_mul(h3w3_0, h3w3_0), proof.eval_t2w))
  let c2_h3_1 = fr_add(fr_add(proof.eval_zw, fr_mul(h3w3_1, proof.eval_t1w)), fr_mul(fr_mul(h3w3_1, h3w3_1), proof.eval_t2w))
  let c2_h3_2 = fr_add(fr_add(proof.eval_zw, fr_mul(h3w3_2, proof.eval_t1w)), fr_mul(fr_mul(h3w3_2, h3w3_2), proof.eval_t2w))

  let r2 =
    fr_add(fr_add(fr_add(fr_add(fr_add(
      fr_mul(c2_h2_0, li_h2_0),
      fr_mul(c2_h2_1, li_h2_1)),
      fr_mul(c2_h2_2, li_h2_2)),
      fr_mul(c2_h3_0, li_h3_0)),
      fr_mul(c2_h3_1, li_h3_1)),
      fr_mul(c2_h3_2, li_h3_2))

  // ----- Compute F (G1 point) -----
  // mulH0 = prod(y - h0w8[i]) for i=0..7
  let mul_h0 = fr_mul(fr_mul(fr_mul(fr_mul(fr_mul(fr_mul(fr_mul(
    d_s0_0, d_s0_1), d_s0_2), d_s0_3), d_s0_4), d_s0_5), d_s0_6), d_s0_7)

  // mulH1 = prod(y - h1w4[i]) for i=0..3
  let mul_h1 = fr_mul(fr_mul(fr_mul(d_s1_0, d_s1_1), d_s1_2), d_s1_3)

  // mulH2 = prod(y - h2w3[i]) * prod(y - h3w3[i])
  let mul_h2 = fr_mul(fr_mul(fr_mul(fr_mul(fr_mul(
    d_h2_0, d_h2_1), d_h2_2), d_h3_0), d_h3_1), d_h3_2)

  // quotient1 = alpha * mulH0 / mulH1
  let quotient1 = fr_mul(alpha, fr_mul(mul_h0, fr_inv(mul_h1)))
  // quotient2 = alpha^2 * mulH0 / mulH2
  let alpha2 = fr_mul(alpha, alpha)
  let quotient2 = fr_mul(alpha2, fr_mul(mul_h0, fr_inv(mul_h2)))

  // F = C0 + quotient1*C1 + quotient2*C2
  let pt_f =
    builtin.bls12_381_g1_add(
      builtin.bls12_381_g1_add(
        pt_c0,
        builtin.bls12_381_g1_scalar_mul(quotient1, pt_c1),
      ),
      builtin.bls12_381_g1_scalar_mul(quotient2, pt_c2),
    )

  // ----- Compute E (G1 point) -----
  // E = G1_gen * (r0 + quotient1*r1 + quotient2*r2)
  let e_scalar = fr_add(fr_add(r0, fr_mul(quotient1, r1)), fr_mul(quotient2, r2))
  let pt_e = builtin.bls12_381_g1_scalar_mul(e_scalar, pt_g1)

  // ----- Compute J (G1 point) -----
  // J = W1 * mulH0
  let pt_j = builtin.bls12_381_g1_scalar_mul(mul_h0, pt_w1)

  // ----- Pairing check -----
  // A1 = (F - E - J) + y*W2
  let pt_a1 =
    builtin.bls12_381_g1_add(
      g1_sub(g1_sub(pt_f, pt_e), pt_j),
      builtin.bls12_381_g1_scalar_mul(y, pt_w2),
    )

  // Check: e(-A1, G2_one) * e(W2, X_2) == 1
  // Equivalent: e(A1, G2_one) == e(W2, X_2)
  builtin.bls12_381_final_verify(
    builtin.bls12_381_miller_loop(pt_a1, pt_g2),
    builtin.bls12_381_miller_loop(pt_w2, pt_x2),
  )
}

// ===== Fr field arithmetic =====

fn fr_add(a: Int, b: Int) -> Int {
  ( a + b ) % r
}

fn fr_sub(a: Int, b: Int) -> Int {
  ( a - b + r ) % r
}

fn fr_mul(a: Int, b: Int) -> Int {
  a * b % r
}

fn fr_neg(a: Int) -> Int {
  if a == 0 {
    0
  } else {
    r - a
  }
}

// Fast exponentiation (square-and-multiply)
fn fr_pow(base: Int, exp: Int) -> Int {
  fr_pow_acc(base % r, exp, 1)
}

fn fr_pow_acc(base: Int, exp: Int, acc: Int) -> Int {
  if exp == 0 {
    acc
  } else if exp % 2 == 1 {
    fr_pow_acc(base * base % r, exp / 2, acc * base % r)
  } else {
    fr_pow_acc(base * base % r, exp / 2, acc)
  }
}

// Field inversion via Fermat's little theorem: a^(r-2) mod r
fn fr_inv(a: Int) -> Int {
  fr_pow(a, r - 2)
}

// ===== G1 point helpers =====

// Negate a G1 point: -P = (r-1)*P  (since r*P = 0 in the group)
fn g1_neg(p: G1Element) -> G1Element {
  builtin.bls12_381_g1_scalar_mul(r - 1, p)
}

// Subtract G1 points: P - Q = P + (-Q)
fn g1_sub(p: G1Element, q: G1Element) -> G1Element {
  builtin.bls12_381_g1_add(p, g1_neg(q))
}

// ===== ByteArray / transcript helpers =====

// Concatenate two byte arrays
fn ba(a: ByteArray, b: ByteArray) -> ByteArray {
  builtin.append_bytearray(a, b)
}

// Serialize an Fr scalar as 32 big-endian bytes (matches Fr.toRprBE in JS)
fn fr_to_bytes(n: Int) -> ByteArray {
  builtin.integer_to_bytearray(True, 32, n)
}

// Hash bytes with Keccak-256, interpret result as big-endian integer, reduce mod r
fn keccak_challenge(data: ByteArray) -> Int {
  builtin.bytearray_to_integer(True, builtin.keccak_256(data)) % r
}

// ===== List / public signal helpers =====

fn signals_to_bytes(signals: List<Int>) -> ByteArray {
  when signals is {
    [] -> #""
    [h, ..t] -> builtin.append_bytearray(fr_to_bytes(h), signals_to_bytes(t))
  }
}

fn list_at_or_zero(lst: List<Int>, index: Int) -> Int {
  when lst is {
    [] -> 0
    [head, ..tail] ->
      if index == 0 {
        head
      } else {
        list_at_or_zero(tail, index - 1)
      }
  }
}


// ===== Embedded Tests =====
// Run with: aiken check

test verify_valid_proof() {
  let proof =
    FflonkProof {
      c1: #"b0b50ecbb0888528a5484d44d60505e50f44b34d0a8485f0f926b207af54a4189b51f7cabf5f211bfb1e87d0f9c20a3e",
      c2: #"b57009185126a00798b6450214e1e1b35cce4b2b68aca7b9318fa595692acb7f4e22921ca33cd93c8d398b90ff622304",
      w1: #"a08e14b69706be8efb22016c60ecd75957a062460d131e5ca61eb7eeba12a96f5a4eeb0e1ff01fb8ea9b9f1021936c49",
      w2: #"a93eae3f79be8dbc9dc35a226a9195a2dd3d063b362edcdfb5ce94af390cae54253feee193ea81b79429a2970eb42343",
      eval_ql: 3003095556982463088596526113484607676445805534559314057092678767328355477957,
      eval_qr: 4227560315378861796605599128117434990096097727818762348311076158195918636426,
      eval_qm: 47795437186206937914062988194792447677543677502106847026629305771899427175550,
      eval_qo: 12118227401226401046823663472857990066653426259077813866353681166743685722192,
      eval_qc: 0,
      eval_s1: 27020245718070748150901080588473296977551181618949316376690882145438180642772,
      eval_s2: 45302755603858259709809229976373885848121788284978199916290810358461860056182,
      eval_s3: 50644614583428047139008908237546564327472375988004905237502577855312113838876,
      eval_a: 1466963128400323941480011632919927928221414485809490697289939673487217427721,
      eval_b: 33339465271183933082857694231961363118698079194539453720541590464570348883049,
      eval_c: 45687347517819650684986898287026706058320743646466648436235708995099196908889,
      eval_z: 15854295134058337586336078298714606241538940582673387290200433178698869732882,
      eval_zw: 45978046419647112102662210831459325157879828376928577511174303146424463795516,
      eval_t1w: 7527050096634986803640466449663252136506801793821552481519132231839343905389,
      eval_t2w: 51964732879730932550562982442002177109917221520211042564253866730399635836635,
    }
  verify(proof, [25801652392718964477554083943848435234218040631732384812634576957435112216313, 11])
}

test verify_invalid_proof() fail {
  let proof =
    FflonkProof {
      c1: #"b0b50ecbb0888528a5484d44d60505e50f44b34d0a8485f0f926b207af54a4189b51f7cabf5f211bfb1e87d0f9c20a3e",
      c2: #"b57009185126a00798b6450214e1e1b35cce4b2b68aca7b9318fa595692acb7f4e22921ca33cd93c8d398b90ff622304",
      w1: #"a08e14b69706be8efb22016c60ecd75957a062460d131e5ca61eb7eeba12a96f5a4eeb0e1ff01fb8ea9b9f1021936c49",
      w2: #"a93eae3f79be8dbc9dc35a226a9195a2dd3d063b362edcdfb5ce94af390cae54253feee193ea81b79429a2970eb42343",
      eval_ql: 3003095556982463088596526113484607676445805534559314057092678767328355477957,
      eval_qr: 4227560315378861796605599128117434990096097727818762348311076158195918636426,
      eval_qm: 47795437186206937914062988194792447677543677502106847026629305771899427175550,
      eval_qo: 12118227401226401046823663472857990066653426259077813866353681166743685722192,
      eval_qc: 0,
      eval_s1: 27020245718070748150901080588473296977551181618949316376690882145438180642772,
      eval_s2: 45302755603858259709809229976373885848121788284978199916290810358461860056182,
      eval_s3: 50644614583428047139008908237546564327472375988004905237502577855312113838876,
      eval_a: 1466963128400323941480011632919927928221414485809490697289939673487217427721,
      eval_b: 33339465271183933082857694231961363118698079194539453720541590464570348883049,
      eval_c: 45687347517819650684986898287026706058320743646466648436235708995099196908889,
      eval_z: 15854295134058337586336078298714606241538940582673387290200433178698869732882,
      eval_zw: 45978046419647112102662210831459325157879828376928577511174303146424463795516,
      eval_t1w: 7527050096634986803640466449663252136506801793821552481519132231839343905389,
      eval_t2w: 51964732879730932550562982442002177109917221520211042564253866730399635836635,
    }
  verify(proof, [999, 11])
}
