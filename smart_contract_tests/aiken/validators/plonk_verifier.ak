// Generated with snarkJS.
//
// snarkJS is a free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// PLONK BLS12-381 verifier for Aiken (Cardano).
// Fiat-Shamir transcript uses Keccak-256 with compressed G1 points (Zcash/BLST format).

use aiken/builtin

// ===== Verification Key =====

// Selector polynomial commitments (G1 compressed, 48 bytes, Zcash format)
const vk_qm: ByteArray = #"ab6ced6b97a7f88640940c6dde9d90ffb195b63b68570f63e834be1e94fb6555b7a193bc4d7e767d7caeac1854f824c0"
const vk_ql: ByteArray = #"ac032fed5db03eddc38a5008bb658ef7289a8ce69f3eff4c15089ac5406f22c4d56fbfe355eb474db433b4038a22e20b"
const vk_qr: ByteArray = #"a8293b3b2711d7183a3e9dd664bdb81080c4faf40e905dec5aed3a5bf231dbfb30e15530bdd44b1ea647939208e98814"
const vk_qo: ByteArray = #"8ac717d1652b9927ccfa4fe3563f7ff2353f7dd7ce70b5e4eecf4e3d3a89ec4dc8f159abe409dc714a0abfdf99fbf060"
const vk_qc: ByteArray = #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// Permutation polynomial commitments (G1 compressed, 48 bytes)
const vk_s1: ByteArray = #"89ae89c8cc1d6ec2bd1cf53d70c9d6bd665c8991dc1c3f5950f4e19bce863f90e4f7fe8cf17d9fdbf3eb77b5ae979543"
const vk_s2: ByteArray = #"8e180c8dc477d49eba1838741f593ed2fe61e03d7f7649a42c9bd2d8e148827ddfbd9b88e2e18274d62ccbe6fc8af01f"
const vk_s3: ByteArray = #"85c9b976b00c3a13dd016deca600869efd24464ba0cfa3439d906a25131998b1508d29e64bd7814548471fe7df042da2"

// KZG SRS commitment (G2 compressed, 96 bytes)
const vk_x2: ByteArray = #"9709a836290e4301d14d5522b1b1f44d948cac2a9673f7d8128c0cbe453538e330d9cf8ef005d9abfca87542344b70c518ec0d5f56f7b23dc6749d35d8d46cd94706c64863669360b6de19b01446c41d628f250c6e81671c50ad4cfb3a657f26"

// Domain parameters (embedded from zkey)
const domain_size: Int = 256
const k1: Int = 2
const k2: Int = 3
const omega: Int = 21071158244812412064791010377580296085971058123779034548857891862303448703672

// BLS12-381 scalar field modulus r
const r: Int =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

// Curve generators (compressed)
const g1_gen: ByteArray = #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
const g2_gen: ByteArray = #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// Concatenated VK G1 bytes: used as transcript prefix in beta/gamma round
const vk_bytes: ByteArray = #"ab6ced6b97a7f88640940c6dde9d90ffb195b63b68570f63e834be1e94fb6555b7a193bc4d7e767d7caeac1854f824c0ac032fed5db03eddc38a5008bb658ef7289a8ce69f3eff4c15089ac5406f22c4d56fbfe355eb474db433b4038a22e20ba8293b3b2711d7183a3e9dd664bdb81080c4faf40e905dec5aed3a5bf231dbfb30e15530bdd44b1ea647939208e988148ac717d1652b9927ccfa4fe3563f7ff2353f7dd7ce70b5e4eecf4e3d3a89ec4dc8f159abe409dc714a0abfdf99fbf060c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000089ae89c8cc1d6ec2bd1cf53d70c9d6bd665c8991dc1c3f5950f4e19bce863f90e4f7fe8cf17d9fdbf3eb77b5ae9795438e180c8dc477d49eba1838741f593ed2fe61e03d7f7649a42c9bd2d8e148827ddfbd9b88e2e18274d62ccbe6fc8af01f85c9b976b00c3a13dd016deca600869efd24464ba0cfa3439d906a25131998b1508d29e64bd7814548471fe7df042da2"

// ===== Proof type =====

pub type PlonkProof {
  // G1 polynomial commitments (compressed, 48 bytes each, Zcash format)
  a: ByteArray,
  b: ByteArray,
  c: ByteArray,
  z: ByteArray,
  t1: ByteArray,
  t2: ByteArray,
  t3: ByteArray,
  wxi: ByteArray,
  wxiw: ByteArray,
  // Polynomial evaluations at challenge xi (scalars in Fr)
  eval_a: Int,
  eval_b: Int,
  eval_c: Int,
  eval_s1: Int,
  eval_s2: Int,
  eval_zw: Int,
}

// ===== PLONK verifier =====

/// PLONK proof verification for BLS12-381.
///
/// Arguments:
///   proof          - PLONK proof (9 G1 commitments + 6 polynomial evaluations)
///   public_signals - list of public input scalars (must have 2 element(s))
///
/// Returns True if the proof is valid.
pub fn verify(proof: PlonkProof, public_signals: List<Int>) -> Bool {
  // ----- Uncompress proof G1 points -----
  let pt_a    = builtin.bls12_381_g1_uncompress(proof.a)
  let pt_b    = builtin.bls12_381_g1_uncompress(proof.b)
  let pt_c    = builtin.bls12_381_g1_uncompress(proof.c)
  let pt_z    = builtin.bls12_381_g1_uncompress(proof.z)
  let pt_t1   = builtin.bls12_381_g1_uncompress(proof.t1)
  let pt_t2   = builtin.bls12_381_g1_uncompress(proof.t2)
  let pt_t3   = builtin.bls12_381_g1_uncompress(proof.t3)
  let pt_wxi  = builtin.bls12_381_g1_uncompress(proof.wxi)
  let pt_wxiw = builtin.bls12_381_g1_uncompress(proof.wxiw)

  // ----- Uncompress VK points -----
  let pt_qm = builtin.bls12_381_g1_uncompress(vk_qm)
  let pt_ql = builtin.bls12_381_g1_uncompress(vk_ql)
  let pt_qr = builtin.bls12_381_g1_uncompress(vk_qr)
  let pt_qo = builtin.bls12_381_g1_uncompress(vk_qo)
  let pt_qc = builtin.bls12_381_g1_uncompress(vk_qc)
  let pt_s1 = builtin.bls12_381_g1_uncompress(vk_s1)
  let pt_s2 = builtin.bls12_381_g1_uncompress(vk_s2)
  let pt_s3 = builtin.bls12_381_g1_uncompress(vk_s3)
  let pt_x2 = builtin.bls12_381_g2_uncompress(vk_x2)
  let pt_g1 = builtin.bls12_381_g1_uncompress(g1_gen)
  let pt_g2 = builtin.bls12_381_g2_uncompress(g2_gen)

  // ----- Fiat-Shamir challenges (Keccak256 with compressed G1 points) -----

  // Round 1: beta = H(VK_bytes || public_inputs_bytes || A || B || C)
  let beta =
    keccak_challenge(
      ba(ba(ba(ba(vk_bytes, signals_to_bytes(public_signals)), proof.a), proof.b), proof.c)
    )

  // Round 1: gamma = H(beta)
  let gamma = keccak_challenge(fr_to_bytes(beta))

  // Round 2: alpha = H(beta || gamma || Z)
  let alpha =
    keccak_challenge(ba(ba(fr_to_bytes(beta), fr_to_bytes(gamma)), proof.z))

  // Round 3: xi = H(alpha || T1 || T2 || T3)
  let xi =
    keccak_challenge(
      ba(ba(ba(fr_to_bytes(alpha), proof.t1), proof.t2), proof.t3)
    )

  // Round 4: v1 = H(xi || eval_a || eval_b || eval_c || eval_s1 || eval_s2 || eval_zw)
  let v1 =
    keccak_challenge(
      ba(ba(ba(ba(ba(ba(fr_to_bytes(xi), fr_to_bytes(proof.eval_a)), fr_to_bytes(proof.eval_b)), fr_to_bytes(proof.eval_c)), fr_to_bytes(proof.eval_s1)), fr_to_bytes(proof.eval_s2)), fr_to_bytes(proof.eval_zw))
    )
  let v2 = fr_mul(v1, v1)
  let v3 = fr_mul(v2, v1)
  let v4 = fr_mul(v3, v1)
  let v5 = fr_mul(v4, v1)

  // Round 5: u = H(Wxi || Wxiw)
  let u = keccak_challenge(ba(proof.wxi, proof.wxiw))

  // ----- Domain evaluations -----

  // xin = xi^domain_size
  let xin = fr_pow(xi, domain_size)
  // zh = xin - 1  (vanishing polynomial)
  let zh = fr_sub(xin, 1)

  // ----- Lagrange polynomial evaluations -----
  // L_i(xi) = w_i * zh / (n * (xi - w_i))  where w_i = omega^(i-1), w_1 = 1
  //
  // l1 (w=1, always computed, used in permutation boundary check and PI)
  let l1 = fr_mul(zh, fr_inv(fr_mul(domain_size, fr_sub(xi, 1))))

  // Additional Lagrange evaluations for public inputs (l2 = L[2], l3 = L[3], ...)
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

  // ----- r0 (linear combination for pairing) -----
  let alpha2 = fr_mul(alpha, alpha)
  let e3a = fr_add(fr_add(proof.eval_a, fr_mul(beta, proof.eval_s1)), gamma)
  let e3b = fr_add(fr_add(proof.eval_b, fr_mul(beta, proof.eval_s2)), gamma)
  let e3c = fr_add(proof.eval_c, gamma)
  let e3 =
    fr_mul(fr_mul(fr_mul(fr_mul(e3a, e3b), e3c), proof.eval_zw), alpha)
  let r0 = fr_sub(fr_sub(pi, fr_mul(l1, alpha2)), e3)

  // ----- D point -----
  // d1 = Qm*(a*b) + Ql*a + Qr*b + Qo*c + Qc
  let d1 =
    builtin.bls12_381_g1_add(
      builtin.bls12_381_g1_add(
        builtin.bls12_381_g1_add(
          builtin.bls12_381_g1_add(
            builtin.bls12_381_g1_scalar_mul(
              fr_mul(proof.eval_a, proof.eval_b),
              pt_qm,
            ),
            builtin.bls12_381_g1_scalar_mul(proof.eval_a, pt_ql),
          ),
          builtin.bls12_381_g1_scalar_mul(proof.eval_b, pt_qr),
        ),
        builtin.bls12_381_g1_scalar_mul(proof.eval_c, pt_qo),
      ),
      pt_qc,
    )

  // d2 = Z * (d2a + d2b + u)
  let betaxi = fr_mul(beta, xi)
  let d2a1 = fr_add(fr_add(proof.eval_a, betaxi), gamma)
  let d2a2 = fr_add(fr_add(proof.eval_b, fr_mul(betaxi, k1)), gamma)
  let d2a3 = fr_add(fr_add(proof.eval_c, fr_mul(betaxi, k2)), gamma)
  let d2a = fr_mul(fr_mul(fr_mul(d2a1, d2a2), d2a3), alpha)
  let d2b = fr_mul(l1, alpha2)
  let d2 =
    builtin.bls12_381_g1_scalar_mul(fr_add(fr_add(d2a, d2b), u), pt_z)

  // d3 = S3 * (d3a * d3b * d3c)
  let d3a = fr_add(fr_add(proof.eval_a, fr_mul(beta, proof.eval_s1)), gamma)
  let d3b = fr_add(fr_add(proof.eval_b, fr_mul(beta, proof.eval_s2)), gamma)
  let d3c = fr_mul(fr_mul(alpha, beta), proof.eval_zw)
  let d3 =
    builtin.bls12_381_g1_scalar_mul(fr_mul(fr_mul(d3a, d3b), d3c), pt_s3)

  // d4 = (T1 + T2*xin + T3*xin^2) * zh
  let d4 =
    builtin.bls12_381_g1_scalar_mul(
      zh,
      builtin.bls12_381_g1_add(
        builtin.bls12_381_g1_add(
          pt_t1,
          builtin.bls12_381_g1_scalar_mul(xin, pt_t2),
        ),
        builtin.bls12_381_g1_scalar_mul(fr_mul(xin, xin), pt_t3),
      ),
    )

  // D = d1 + d2 - d3 - d4
  let pt_d =
    g1_sub(g1_sub(builtin.bls12_381_g1_add(d1, d2), d3), d4)

  // ----- F point: D + A*v1 + B*v2 + C*v3 + S1*v4 + S2*v5 -----
  let pt_f =
    builtin.bls12_381_g1_add(
      builtin.bls12_381_g1_add(
        builtin.bls12_381_g1_add(
          builtin.bls12_381_g1_add(
            builtin.bls12_381_g1_add(
              pt_d,
              builtin.bls12_381_g1_scalar_mul(v1, pt_a),
            ),
            builtin.bls12_381_g1_scalar_mul(v2, pt_b),
          ),
          builtin.bls12_381_g1_scalar_mul(v3, pt_c),
        ),
        builtin.bls12_381_g1_scalar_mul(v4, pt_s1),
      ),
      builtin.bls12_381_g1_scalar_mul(v5, pt_s2),
    )

  // ----- E point: G1_gen * e_scalar -----
  let e_scalar =
    fr_add(
      fr_add(
        fr_add(
          fr_add(
            fr_add(
              fr_add(fr_neg(r0), fr_mul(v1, proof.eval_a)),
              fr_mul(v2, proof.eval_b),
            ),
            fr_mul(v3, proof.eval_c),
          ),
          fr_mul(v4, proof.eval_s1),
        ),
        fr_mul(v5, proof.eval_s2),
      ),
      fr_mul(u, proof.eval_zw),
    )
  let pt_e = builtin.bls12_381_g1_scalar_mul(e_scalar, pt_g1)

  // ----- KZG pairing check -----
  // A1 = Wxi + u*Wxiw
  let pt_a1 =
    builtin.bls12_381_g1_add(
      pt_wxi,
      builtin.bls12_381_g1_scalar_mul(u, pt_wxiw),
    )

  // s = u * xi * omega
  let s = fr_mul(fr_mul(u, xi), omega)

  // B1 = xi*Wxi + s*Wxiw + F - E
  let pt_b1 =
    g1_sub(
      builtin.bls12_381_g1_add(
        builtin.bls12_381_g1_add(
          builtin.bls12_381_g1_scalar_mul(xi, pt_wxi),
          builtin.bls12_381_g1_scalar_mul(s, pt_wxiw),
        ),
        pt_f,
      ),
      pt_e,
    )

  // Check: e(A1, X2) == e(B1, G2_gen)
  // Equivalent to the original: e(-A1, X2) * e(B1, G2_gen) == 1
  builtin.bls12_381_final_verify(
    builtin.bls12_381_miller_loop(pt_a1, pt_x2),
    builtin.bls12_381_miller_loop(pt_b1, pt_g2),
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
    PlonkProof {
      a: #"a0a13930d4602d48d1ef07afd39f206d1ae681bc00d93597e5c1bd02229b53e7353c1ebce785d17955a1961b07fd84af",
      b: #"8a2ccba9914e7ade023dc4150b495576359744801b883930c85e9a6b076c16e76b822e26430f977776e7b2e95f2ebb4c",
      c: #"92d7d1c03a3485d2e783b3b5bfca8e4cd1d463dd05e5adba64083cccaddf3c47b45b963080ea6d80813a10e5159b5807",
      z: #"ac0c4071a90f8fe40c7784b3e0fbfa5ef749c6bdb5793673e3a1c4bfc42fb573dadf875627957f3e76d42a9d8605e7c4",
      t1: #"b6bda497dbaa02746379e2bbb66270315a462cd42395d744676c8a6d67e22b93e673b63cfa8818e6896ac9359ab6a11b",
      t2: #"b6817d5d8461592299eb41146200a1ffd9460132459fa7af5bd4067b4eb87375217311407e9f4c49582a3c6443733129",
      t3: #"80b5cf3a8c3e527a4c544bbe394c7b68edba95ba6d5b719026b04b5f00d9800cee577a69a2fa6d329e820608ed6c99ec",
      wxi: #"83cb191c5e2dc0e68a4d363cd111e9829e648ea845eb74c5125ee3ab24954c5a6b6fc098faf544b11ff3bb9e4b3fcd7b",
      wxiw: #"a8b6093dc2197b9a6feccd266fd67cd499b7944c32dd9b4ff0061c12845e267f32714d78b9e312e2ee7935dbfc51da05",
      eval_a: 31964810142508251606623984834234199152137975128345863809464433959523903355156,
      eval_b: 13173257834899989992695976105648594023358532641748561175577722405312983737154,
      eval_c: 14780992182110583905950122751064492187577777461104027586124306835164588483942,
      eval_s1: 46353686564117469227232072265231983217108228824405027059123712078248313435354,
      eval_s2: 20025955105998436226418095277351849797574115332561390098320031899786155829866,
      eval_zw: 30705752883237189852731836791066499476443410229149126949840645219964106298381,
    }
  verify(proof, [44073357286276920367386691488995082668693688496384134357725726509176848452944, 11])
}

test verify_invalid_proof() fail {
  let proof =
    PlonkProof {
      a: #"a0a13930d4602d48d1ef07afd39f206d1ae681bc00d93597e5c1bd02229b53e7353c1ebce785d17955a1961b07fd84af",
      b: #"8a2ccba9914e7ade023dc4150b495576359744801b883930c85e9a6b076c16e76b822e26430f977776e7b2e95f2ebb4c",
      c: #"92d7d1c03a3485d2e783b3b5bfca8e4cd1d463dd05e5adba64083cccaddf3c47b45b963080ea6d80813a10e5159b5807",
      z: #"ac0c4071a90f8fe40c7784b3e0fbfa5ef749c6bdb5793673e3a1c4bfc42fb573dadf875627957f3e76d42a9d8605e7c4",
      t1: #"b6bda497dbaa02746379e2bbb66270315a462cd42395d744676c8a6d67e22b93e673b63cfa8818e6896ac9359ab6a11b",
      t2: #"b6817d5d8461592299eb41146200a1ffd9460132459fa7af5bd4067b4eb87375217311407e9f4c49582a3c6443733129",
      t3: #"80b5cf3a8c3e527a4c544bbe394c7b68edba95ba6d5b719026b04b5f00d9800cee577a69a2fa6d329e820608ed6c99ec",
      wxi: #"83cb191c5e2dc0e68a4d363cd111e9829e648ea845eb74c5125ee3ab24954c5a6b6fc098faf544b11ff3bb9e4b3fcd7b",
      wxiw: #"a8b6093dc2197b9a6feccd266fd67cd499b7944c32dd9b4ff0061c12845e267f32714d78b9e312e2ee7935dbfc51da05",
      eval_a: 31964810142508251606623984834234199152137975128345863809464433959523903355156,
      eval_b: 13173257834899989992695976105648594023358532641748561175577722405312983737154,
      eval_c: 14780992182110583905950122751064492187577777461104027586124306835164588483942,
      eval_s1: 46353686564117469227232072265231983217108228824405027059123712078248313435354,
      eval_s2: 20025955105998436226418095277351849797574115332561390098320031899786155829866,
      eval_zw: 30705752883237189852731836791066499476443410229149126949840645219964106298381,
    }
  verify(proof, [999, 11])
}
