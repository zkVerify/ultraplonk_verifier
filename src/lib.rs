// Copyright 2022 Aztec
// Copyright 2024 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod errors;
mod key;
mod macros;
mod proof;
mod resources;
mod srs;
mod testhooks;
mod types;
mod utils;

use crate::{
    key::{read_g2, VerificationKey},
    proof::Proof,
    srs::SRS_G2,
};
use ark_bn254_ext::{Config, CurveHooks};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{Field, MontConfig, One};
use ark_models_ext::bn::{BnConfig, G1Prepared, G2Prepared};
use errors::VerifyError;
use macros::u256;
use sha3::{Digest, Keccak256};
use utils::{IntoBytes, IntoFr, IntoU256};

pub use types::*;

extern crate alloc;
extern crate core;
use alloc::vec::Vec;

const PROOF_SIZE: usize = 2144; // = 67 * 32
const PUBS_SIZE: usize = 32;
const VK_SIZE: usize = 1714; // TODO: Revise if necessary once recursive proofs are supported

#[derive(Debug)]
pub struct Challenges {
    alpha: Fr,
    alpha_sqr: Fr,
    alpha_cube: Fr,
    alpha_quad: Fr,
    alpha_base: Fr,
    beta: Fr,
    gamma: Fr,
    zeta: Fr,
    zeta_pow_n: Fr,
    eta: Fr,
    eta_sqr: Fr,
    eta_cube: Fr,
}

impl Challenges {
    fn new(alpha: Fr, beta: Fr, gamma: Fr, zeta: Fr, eta: Fr, n: u32) -> Self {
        // compute and store some powers of alpha and eta for future computations
        let alpha_sqr = alpha.square();
        let alpha_cube = alpha_sqr * alpha;
        let alpha_quad = alpha_cube * alpha;
        let alpha_base = alpha;
        let eta_sqr = eta.square();
        let eta_cube = eta_sqr * eta;

        // compute zeta^n, where n is a power of 2
        let mut zeta_pow_n = zeta;
        {
            // pow small
            let exponent = n;
            let mut count = 1;
            while count < exponent {
                zeta_pow_n.square_in_place();
                count <<= 1;
            }
        }

        Challenges {
            alpha,
            alpha_sqr,
            alpha_cube,
            alpha_quad,
            alpha_base,
            beta,
            gamma,
            zeta,
            zeta_pow_n,
            eta,
            eta_sqr,
            eta_cube,
        }
    }
}

#[derive(Debug)]
pub struct NuChallenges {
    c_v: [Fr; 31],
    c_u: Fr,
}

impl NuChallenges {
    fn new<H: CurveHooks>(
        proof: &Proof<H>,
        c_current: &[u8],
        quotient_eval: &Fr,
    ) -> Result<Self, ()> {
        if c_current.len() != 32 {
            return Err(());
        }
        let current_challenge = c_current;

        // assert_eq!(
        //     current_challenge,
        //     crate::macros::u256!(
        //         "802605d8a0f13f61f89a8efb2632b86aae9a4fcec0cb67f914a547b82e4238b4"
        //     )
        //     .into_bytes()
        // );

        let nu_challenge_input_a = current_challenge;
        let nu_challenge_input_b = quotient_eval;

        let mut hasher = Keccak256::new();

        let mut buffer = [0u8; 1376]; // 1376 = (41 + 2) * 32
        buffer[..32].copy_from_slice(nu_challenge_input_a);
        buffer[32..64].copy_from_slice(&nu_challenge_input_b.into_bytes());

        buffer[64..96].copy_from_slice(&proof.w1_eval.into_bytes());
        buffer[96..128].copy_from_slice(&proof.w2_eval.into_bytes());
        buffer[128..160].copy_from_slice(&proof.w3_eval.into_bytes());
        buffer[160..192].copy_from_slice(&proof.w4_eval.into_bytes());

        buffer[192..224].copy_from_slice(&proof.s_eval.into_bytes());
        buffer[224..256].copy_from_slice(&proof.z_eval.into_bytes());
        buffer[256..288].copy_from_slice(&proof.z_lookup_eval.into_bytes());

        buffer[288..320].copy_from_slice(&proof.q1_eval.into_bytes());
        buffer[320..352].copy_from_slice(&proof.q2_eval.into_bytes());
        buffer[352..384].copy_from_slice(&proof.q3_eval.into_bytes());
        buffer[384..416].copy_from_slice(&proof.q4_eval.into_bytes());

        buffer[416..448].copy_from_slice(&proof.qm_eval.into_bytes());
        buffer[448..480].copy_from_slice(&proof.qc_eval.into_bytes());

        buffer[480..512].copy_from_slice(&proof.q_arith_eval.into_bytes());
        buffer[512..544].copy_from_slice(&proof.q_sort_eval.into_bytes());
        buffer[544..576].copy_from_slice(&proof.q_elliptic_eval.into_bytes());
        buffer[576..608].copy_from_slice(&proof.q_aux_eval.into_bytes());

        buffer[608..640].copy_from_slice(&proof.sigma1_eval.into_bytes());
        buffer[640..672].copy_from_slice(&proof.sigma2_eval.into_bytes());
        buffer[672..704].copy_from_slice(&proof.sigma3_eval.into_bytes());
        buffer[704..736].copy_from_slice(&proof.sigma4_eval.into_bytes());

        buffer[736..768].copy_from_slice(&proof.table1_eval.into_bytes());
        buffer[768..800].copy_from_slice(&proof.table2_eval.into_bytes());
        buffer[800..832].copy_from_slice(&proof.table3_eval.into_bytes());
        buffer[832..864].copy_from_slice(&proof.table4_eval.into_bytes());
        buffer[864..896].copy_from_slice(&proof.table_type_eval.into_bytes());

        buffer[896..928].copy_from_slice(&proof.id1_eval.into_bytes());
        buffer[928..960].copy_from_slice(&proof.id2_eval.into_bytes());
        buffer[960..992].copy_from_slice(&proof.id3_eval.into_bytes());
        buffer[992..1024].copy_from_slice(&proof.id4_eval.into_bytes());

        buffer[1024..1056].copy_from_slice(&proof.w1_omega_eval.into_bytes());
        buffer[1056..1088].copy_from_slice(&proof.w2_omega_eval.into_bytes());
        buffer[1088..1120].copy_from_slice(&proof.w3_omega_eval.into_bytes());
        buffer[1120..1152].copy_from_slice(&proof.w4_omega_eval.into_bytes());

        buffer[1152..1184].copy_from_slice(&proof.s_omega_eval.into_bytes());
        buffer[1184..1216].copy_from_slice(&proof.z_omega_eval.into_bytes());
        buffer[1216..1248].copy_from_slice(&proof.z_lookup_omega_eval.into_bytes());

        buffer[1248..1280].copy_from_slice(&proof.table1_omega_eval.into_bytes());
        buffer[1280..1312].copy_from_slice(&proof.table2_omega_eval.into_bytes());
        buffer[1312..1344].copy_from_slice(&proof.table3_omega_eval.into_bytes());
        buffer[1344..1376].copy_from_slice(&proof.table4_omega_eval.into_bytes());

        // nu challenges
        let mut c_v: [Fr; 31] = [Fr::one(); 31];

        hasher.update(buffer);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize_reset());
        let mut challenge = hash;

        // assert_eq!(
        //     challenge,
        //     crate::macros::u256!(
        //         "769d4ae9acae5f1e11f7ea48f7167f309cece8da71a6c2f886a1aff61048cd2e"
        //     )
        //     .into_bytes()
        // );

        c_v[0] = challenge.into_fr();

        // We need THIRTY-ONE independent nu challenges!
        let mut buffer = [0u8; 33];
        buffer[..32].copy_from_slice(&challenge);
        for i in 1..30_usize {
            buffer[32] = i as u8;
            hasher.update(buffer);
            hash.copy_from_slice(&hasher.finalize_reset());
            c_v[i] = hash.into_fr();
        }

        // @follow-up - Why are both v29 and v30 using appending 0x1d to the prior challenge and hashing, should it not change?
        buffer[32] = 0x1d_u8;
        hasher.update(buffer);
        hash.copy_from_slice(&hasher.finalize_reset());
        challenge = hash;
        c_v[30] = challenge.into_fr();

        // separator
        let mut buffer = [0u8; 160]; // 160 = 32 * 5
        buffer[..32].copy_from_slice(&challenge);
        buffer[32..64].copy_from_slice(&proof.pi_z.y.into_bytes());
        buffer[64..96].copy_from_slice(&proof.pi_z.x.into_bytes());
        buffer[96..128].copy_from_slice(&proof.pi_z_omega.y.into_bytes());
        buffer[128..160].copy_from_slice(&proof.pi_z_omega.x.into_bytes());

        hasher.update(buffer);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let c_u = hash.into_fr();

        Ok(Self { c_v, c_u })
    }
}

struct AuxiliaryEvaluations {
    aux_memory_evaluation: Fr,
    aux_rom_consistency_evaluation: Fr,
    aux_ram_consistency_evaluation: Fr,
    aux_non_native_field_evaluation: Fr,
    aux_limb_accumulator_evaluation: Fr,
}

pub fn verify<H: CurveHooks>(
    raw_vk: &[u8],
    raw_proof: &[u8],
    pubs: &[[u8; PUBS_SIZE]],
) -> Result<(), VerifyError> {
    /*
     * PARSE VERIFICATION KEY
     */
    let vk =
        VerificationKey::<H>::try_from(raw_vk).map_err(|_| VerifyError::InvalidVerificationKey)?;

    /*
     * PARSE PROOF
     */
    let proof = Proof::<H>::try_from(raw_proof).map_err(|_| VerifyError::InvalidProofData)?;

    // TODO: PARSE RECURSIVE PROOF

    /*
     * PARSE PUBLIC INPUTS
     */
    let public_inputs = &pubs
        .iter()
        .map(|pi_bytes| pi_bytes.into_u256())
        .collect::<Vec<U256>>();

    /*
     * GENERATE CHALLENGES
     */

    // Initial Challenge
    let mut challenge = generate_initial_challenge(vk.circuit_size, vk.num_public_inputs);

    // assert_eq!(
    //     challenge,
    //     crate::macros::u256!("e2ea8b7ebb1c3baf6697641e614c44a88bc17efa13d1c86e283b4662fe9a1d05")
    //         .into_bytes() // expected output
    // );

    // Eta Challenge
    challenge = generate_eta_challenge::<H>(&proof, public_inputs, &challenge);

    // assert_eq!(
    //     challenge,
    //     crate::macros::u256!("ac5020942cd0e8a2d7ea16f03ff2d90c0ed7082432d8caa93918aab86b09bcf7")
    //         .into_bytes() // expected output
    // );

    let eta = challenge.into_fr();

    // Beta challenge
    challenge = generate_beta_challenge::<H>(&proof, &challenge);

    // assert_eq!(
    //     challenge,
    //     crate::macros::u256!("6a55ee92866db968ed1233e27e4902feb54f9fed60904d7e24899f108b9b9a4c")
    //         .into_bytes() // expected output
    // );

    let beta = challenge.into_fr();

    // Gamma challenge
    challenge = generate_gamma_challenge(&challenge);

    // assert_eq!(
    //     challenge,
    //     crate::macros::u256!("7594d2d6aed54232381fa8d2103aabb6806c2cb37943e2012e84cea756a04578")
    //         .into_bytes() // expected output
    // );

    let gamma = challenge.into_fr();

    // Alpha challenge
    challenge = generate_alpha_challenge::<H>(&proof, &challenge);

    // assert_eq!(
    //     challenge,
    //     crate::macros::u256!("3e437396c11f77796537424853cba05cb5478ac4f2cc3718bc94177e04a40623")
    //         .into_bytes() // expected output
    // );

    let alpha = challenge.into_fr();

    // Zeta challenge
    challenge = generate_zeta_challenge::<H>(&proof, &challenge);
    let zeta = challenge.into_fr();

    // assert_eq!(
    //     zeta,
    //     crate::macros::fr!("1f5d68f2de8dff0e87fa038e233007b05e327f3dcd5886d68ce15c904e4238b2")
    // );

    let c_current = challenge;

    // assert_eq!(
    //     c_current,
    //     crate::macros::u256!("802605d8a0f13f61f89a8efb2632b86aae9a4fcec0cb67f914a547b82e4238b4")
    //         .into_bytes() // expected output
    // );

    let mut challenges = Challenges::new(alpha, beta, gamma, zeta, eta, vk.circuit_size);

    // assert_eq!(
    //     challenges.zeta_pow_n,
    //     crate::macros::fr!("0551acf450da38cc8f866b3135ff7b5742f55614eae8361d00c479e3c4a32482")
    // );

    /*
     *   EVALUATE FIELD OPERATIONS
     */

    /*
     *   COMPUTE PUBLIC INPUT DELTA
     *   ΔPI = ∏ᵢ∈ℓ(wᵢ + β σ(i) + γ) / ∏ᵢ∈ℓ(wᵢ + β σ'(i) + γ)
     */
    let (delta_numerator, delta_denominator) =
        compute_public_input_delta(public_inputs, &vk.work_root, &mut challenges);

    // assert_eq!(
    //     delta_numerator,
    //     crate::macros::fr!("142a7fdddf74bf207d6721f9f4163df5005780a82daaae1772bb7176e0aa48f1")
    // );

    // assert_eq!(
    //     delta_denominator,
    //     crate::macros::fr!("26a36d245a8c6e8d2c327779d18125769a7a43e6afbf34077841673fa1eb80f6")
    // );

    /*
     *  Compute Plookup delta factor [γ(1 + β)]^{n-k}
     *  k = num roots cut out of Z_H = 4
     */
    let (plookup_delta_numerator, plookup_delta_denominator) =
        compute_plookup_delta_factor(vk.circuit_size, &challenges);

    // assert_eq!(
    //     plookup_delta_numerator,
    //     crate::macros::fr!("03a30d522722de22dfe21f63a4cba0ec297c6a02d03ae0cbff647e0e052a8193")
    // );

    // assert_eq!(
    //     plookup_delta_denominator,
    //     crate::macros::fr!("0f66d4b19a12385466977c27c25162e333ff1295f45292753b2e25d823e3629c")
    // );

    /*
     * Compute lagrange poly and vanishing poly fractions
     */
    let [public_input_delta, _zero_poly, zero_poly_inverse, plookup_delta, l_start, l_end] =
        compute_lagrange_and_vanishing_poly::<H>(
            &challenges,
            &vk,
            &delta_numerator, // Q: Maybe combine numerator and denominator into one struct?
            &delta_denominator,
            &plookup_delta_numerator, // Same as above
            &plookup_delta_denominator,
        );

    // assert_eq!(
    //     public_input_delta,
    //     crate::macros::fr!("0b6abc592553a9e92da907e1a2b8bb35f8b6694169a540ebae80f627c210ef65")
    // );

    // assert_eq!(
    //     zero_poly,
    //     crate::macros::fr!("1a483a8e1a5bc10f1e26b02dc6109744b9c57755987302e7979461c2941beb0c")
    // );

    // assert_eq!(
    //     zero_poly_inverse,
    //     crate::macros::fr!("2dc243ba08117f3958824e7934100d0c49e1a21a8f1527e2f2e800965ae7ec6e")
    // );

    // assert_eq!(
    //     plookup_delta,
    //     crate::macros::fr!("0474099bf2133bd17d79f5081b0b743397cd879603e3ef32e32c2c1ce277c05e")
    // );

    // assert_eq!(
    //     l_start,
    //     crate::macros::fr!("18ad94627bf75e2f186f990afea1f1ac7973d09ad752fd644663150b0ffba7e4")
    // );

    // assert_eq!(
    //     l_end,
    //     crate::macros::fr!("212aac641a1a1ea11ef222aee8995efc54ed55c2adbcd7470e96ed17895f8364")
    // );

    /*
     * UltraPlonk Widget Ordering:
     *
     * 1. Permutation widget
     * 2. Plookup widget
     * 3. Arithmetic widget
     * 4. Fixed base widget (?)
     * 5. GenPermSort widget
     * 6. Elliptic widget
     * 7. Auxiliary widget
     */

    /*
     * COMPUTE PERMUTATION WIDGET EVALUATION
     */
    let permutation_identity = compute_permutation_widget_evaluation::<H>(
        &proof,
        &mut challenges,
        &l_start,
        &l_end,
        &public_input_delta,
    );

    // assert_eq!(
    //     permutation_identity,
    //     crate::macros::fr!("07de1f4206c238b084b02fbf7c9275c69bfa2d8fcafcd805fd7abba7b5a81cbd")
    // );

    /*
     * COMPUTE PLOOKUP WIDGET EVALUATION
     */
    let plookup_identity = compute_plookup_widget_evaluation::<H>(
        &proof,
        &mut challenges,
        &l_start,
        &l_end,
        &plookup_delta,
    );

    // assert_eq!(
    //     plookup_identity,
    //     crate::macros::fr!("182aa25c5a92378b0292f0742fe03c14b4c1556372f7c78265be639a92c08aa8")
    // );

    /*
     * COMPUTE ARITHMETIC WIDGET EVALUATION
     */
    let arithmetic_identity = compute_arithmetic_widget_evaluation::<H>(&proof, &mut challenges);

    // assert_eq!(
    //     arithmetic_identity,
    //     crate::macros::fr!("2773137c5e574993b2407d7cd70ad46c900d1b4ecd8eb925ae4272fee9159c5e")
    // );

    /*
     * COMPUTE GENPERMSORT WIDGET EVALUATION
     */
    let sort_identity = compute_genpermsort_widget_evaluation::<H>(&proof, &mut challenges);

    // assert_eq!(
    //     sort_identity,
    //     crate::macros::fr!("079d6b36013ffbe5fc5b76136bae9a9a63989bda11044e3f276aaf28dfcae36d")
    // );

    /*
     * COMPUTE ELLIPTIC WIDGET EVALUATION
     */
    let elliptic_identity = compute_elliptic_widget_evaluation::<H>(&proof, &mut challenges);

    // assert_eq!(
    //     elliptic_identity,
    //     crate::macros::fr!("1a645471486e9e0917e4b710d31adab734b97376928df0230d25ca5f1c53cefa")
    // );

    /*
     * COMPUTE AUXILIARY WIDGET EVALUATION
     */
    let aux_identity = compute_auxiliary_widget_evaluation::<H>(&proof, &mut challenges);

    // assert_eq!(
    //     aux_identity,
    //     crate::macros::fr!("2545253e8c90b125eb57be54ad39b4491c6c3585a1e8efd141c8c89f2e9d5795")
    // );

    /*
     * QUOTIENT EVALUATION
     */
    let quotient_eval = quotient_evaluation(
        &permutation_identity,
        &plookup_identity,
        &arithmetic_identity,
        &sort_identity,
        &elliptic_identity,
        &aux_identity,
        &zero_poly_inverse,
    );

    // assert_eq!(
    //     quotient_eval,
    //     crate::macros::fr!("1f6eeb3c59606f4a302bf15cd31da47ff915fc8a066e7919ae2defa9cea5f02a")
    // );

    /*
     * GENERATE NU AND SEPARATOR CHALLENGES
     */
    let nu_challenges = NuChallenges::new(&proof, &c_current, &quotient_eval).unwrap();

    // let expected_c_v = [
    //     crate::macros::fr!("15d4ae03ea4b1ecaa1575edbf413ce764c8518497e33e1d5feddc4ce3048cd2c"),
    //     crate::macros::fr!("015bd919d73b1aedf38a35d4e73db09c00e1f37752fa6469df82f03e606f16d6"),
    //     crate::macros::fr!("2267f04915850d1a9e4f3db39612c71c79321610c0c6f056c42184c1f6f4b40f"),
    //     crate::macros::fr!("2813ed668d0e87d010f517999846368d06b7052296c862c312a4b1fcacbee9a6"),
    //     crate::macros::fr!("23fa2e334e0e056934b8fc98d89bb581cfb040a3ce326ef193e56d416dc8a1bd"),
    //     crate::macros::fr!("0196ee9d2542e01bc6c847728cad89db1ea842a5d1a9b70a1a6a9f55b4936f94"),
    //     crate::macros::fr!("11d843ef02ef1f8353aa0edb1330450b4092900be85237009453200dfe8c1378"),
    //     crate::macros::fr!("093babb324cebf412b19bba33c7052e2af0539d475d4154c7599b530aeb1ba0c"),
    //     crate::macros::fr!("220eaebb15254dad6376aecfbdd67b1ded236e7e4caa41eaa0e45449f885ca58"),
    //     crate::macros::fr!("1c97dee1ddf83386a271cb8ace1846f070139f7c5236bbeaf5d3b60d6dbc231b"),
    //     crate::macros::fr!("0374c384ebe5a9978a64991cf58a6c163eef12f6d67bd96a2cdd83b2f6a0cc9c"),
    //     crate::macros::fr!("040ca0fd1a44634d419c4ab001ef3114bf70b765b86979208ac0e387be981a3c"),
    //     crate::macros::fr!("13add2c050c03d1e7d28d64f6f2da808874cac99cc2ab36902754257c1cd5ddd"),
    //     crate::macros::fr!("2d21c7e5c27e1c317b9ed60dbbce489926219f3d069d38ee08d02836892443e2"),
    //     crate::macros::fr!("1251af0498381b5f5c3bb17729a390f81c5f14d889b7aa026597a2efa09f5363"),
    //     crate::macros::fr!("2621c704b3bfd547bcaaccef7cfffbc387c3bbc06fc706cf414ddee885c143b8"),
    //     crate::macros::fr!("0ade26efdcd4bbede24270b0ac58c885cd34149db75f14dbcbb133afabc4a6e7"),
    //     crate::macros::fr!("03a1403d83796abbf5837b08468142bf5b1e3a34f94777f1b03623f707e53a89"),
    //     crate::macros::fr!("15832f94b9d94169b4bce882b3e63dad1ecd5d43b77abf0339872855f08a2ee9"),
    //     crate::macros::fr!("2fa60afe3363b3abece69c07368663b8a9c50c4540398345990db4d63fcc2f70"),
    //     crate::macros::fr!("1bc6bef215dc394d887bff2321b219ee3d7a2017acc1d16840f083a17c2ba6d0"),
    //     crate::macros::fr!("08c3d018670ed7f468fe6f06c8f4f28646cb39ea9ccbfa0ddd934c523117c0ce"),
    //     crate::macros::fr!("1f10acae56484911cd25506e8b46a33a062368a8e5d0da59973db0e9015c245e"),
    //     crate::macros::fr!("0a6dcb0c408b2ed8f0d5e70b832d4f928753180450e3a5d8321509128193d22b"),
    //     crate::macros::fr!("10482eb5e55eb43b4fb25466d08a8f071ba6d377cd0272180a8da87989153a95"),
    //     crate::macros::fr!("23d23854bf5e1f16464d61b428aaa7969d4f167c9fd83813cb1100b89a3a504c"),
    //     crate::macros::fr!("25ac39ef063b4c3abb8226cb71e713e14e245e62a7d44ebda83ebd9a664b6ece"),
    //     crate::macros::fr!("276bd73e859d2a6ee90ac32aac000b8dd7c449914ad5364a3282aa51ef13827a"),
    //     crate::macros::fr!("04dcd4929af7387f9a64b568567e6f5586c3c2bd14bdf0ebcc3447b55afef9cf"),
    //     crate::macros::fr!("25424b7da95a0deb4b217f22f5f216608ed0469984692a7732923e3bd4ebe4c1"),
    //     crate::macros::fr!("25424b7da95a0deb4b217f22f5f216608ed0469984692a7732923e3bd4ebe4c1"),
    // ];

    // for i in 0..=30 {
    //     assert_eq!(nu_challenges.c_v[i], expected_c_v[i]);
    // }

    // assert_eq!(
    //     nu_challenges.c_u,
    //     crate::macros::fr!("06f6272c85636c826afebd2f0945accb6460e69a3c2299cfef1ea7dc9c6e95ef")
    // );

    /*
     * PERFORM FINAL CHECKS
     */

    if perform_final_checks::<H>(&proof, &vk, &challenges, &nu_challenges, &quotient_eval) {
        Ok(())
    } else {
        Err(VerifyError::VerifyError)
    }
}

/**
 * Generate initial challenge
 */
fn generate_initial_challenge(n: u32, num_public_inputs: u32) -> [u8; 32] {
    Keccak256::new()
        .chain_update(n.to_be_bytes())
        .chain_update(num_public_inputs.to_be_bytes())
        .finalize()
        .into()
}

/**
 * Generate eta challenge
 */
fn generate_eta_challenge<H: CurveHooks>(
    proof: &Proof<H>,
    public_inputs: &[U256],
    initial_challenge: &[u8; 32],
) -> [u8; 32] {
    // Challenge is the old challenge + public inputs + W1, W2, W3 (0x20 + public_input_size + 0xc0)
    let mut hasher = Keccak256::new();
    let mut buffer = Vec::new(); // [0u8; 32 + public_inputs.len() * 32 + 3 * 64];

    // copy initial challenge bytes
    buffer.extend_from_slice(initial_challenge);
    // copy public input bytes
    for input in public_inputs {
        buffer.extend_from_slice(&input.into_bytes());
    }
    // copy w1, w2, and w3 bytes
    buffer.extend_from_slice(&proof.w1.y.into_bytes());
    buffer.extend_from_slice(&proof.w1.x.into_bytes());
    buffer.extend_from_slice(&proof.w2.y.into_bytes());
    buffer.extend_from_slice(&proof.w2.x.into_bytes());
    buffer.extend_from_slice(&proof.w3.y.into_bytes());
    buffer.extend_from_slice(&proof.w3.x.into_bytes());

    hasher.update(&buffer);

    let mut hash = [0u8; 32];

    hash.copy_from_slice(&hasher.finalize());

    hash
}

/**
 * Generate beta challenge
 */
fn generate_beta_challenge<H: CurveHooks>(proof: &Proof<H>, challenge: &[u8; 32]) -> [u8; 32] {
    Keccak256::new()
        .chain_update(challenge)
        .chain_update(&proof.w4.y.into_bytes())
        .chain_update(&proof.w4.x.into_bytes())
        .chain_update(&proof.s.y.into_bytes())
        .chain_update(&proof.s.x.into_bytes())
        .finalize()
        .into()
}

/**
 * Generate gamma challenge
 */
fn generate_gamma_challenge(challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    let mut buffer = [1u8; 33];
    buffer[..32].copy_from_slice(challenge);
    hasher.update(buffer);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

/**
 * Generate alpha challenge
 */
fn generate_alpha_challenge<H: CurveHooks>(proof: &Proof<H>, challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    let mut buffer = [0u8; 160];
    buffer[..32].copy_from_slice(challenge);
    buffer[32..64].copy_from_slice(&proof.z.y.into_bytes());
    buffer[64..96].copy_from_slice(&proof.z.x.into_bytes());
    buffer[96..128].copy_from_slice(&proof.z_lookup.y.into_bytes());
    buffer[128..160].copy_from_slice(&proof.z_lookup.x.into_bytes());
    hasher.update(buffer);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

/**
 * Generate zeta challenge
 */
fn generate_zeta_challenge<H: CurveHooks>(proof: &Proof<H>, challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    let mut buffer = [0u8; 288];
    buffer[..32].copy_from_slice(challenge);
    buffer[32..64].copy_from_slice(&proof.t1.y.into_bytes());
    buffer[64..96].copy_from_slice(&proof.t1.x.into_bytes());
    buffer[96..128].copy_from_slice(&proof.t2.y.into_bytes());
    buffer[128..160].copy_from_slice(&proof.t2.x.into_bytes());
    buffer[160..192].copy_from_slice(&proof.t3.y.into_bytes());
    buffer[192..224].copy_from_slice(&proof.t3.x.into_bytes());
    buffer[224..256].copy_from_slice(&proof.t4.y.into_bytes());
    buffer[256..288].copy_from_slice(&proof.t4.x.into_bytes());
    hasher.update(buffer);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

fn compute_public_input_delta(
    public_inputs: &[U256],
    work_root: &Fr,
    challenges: &mut Challenges,
) -> (Fr, Fr) {
    let mut numerator_value = Fr::one();
    let mut denominator_value = Fr::one();
    let mut valid_inputs = true;

    // root_1 = β * 0x05
    let mut root_1 = challenges.beta * Fr::from(5); // k1.β

    // root_2 = β * 0x0c
    let mut root_2 = challenges.beta * Fr::from(12);
    // @note 0x05 + 0x07 == 0x0c == external coset

    for &input in public_inputs {
        /*
           input = public_input[i]
           valid_inputs &= input < p
           temp = input + gamma
           numerator_value *= (β.σ(i) + wᵢ + γ)  // σ(i) = 0x05.ωⁱ
           denominator_value *= (β.σ'(i) + wᵢ + γ) // σ'(i) = 0x0c.ωⁱ
           root_1 *= ω
           root_2 *= ω
        */
        valid_inputs &= input < FrConfig::MODULUS;
        let temp = input.into_fr() + challenges.gamma;
        numerator_value *= root_1 + temp;
        denominator_value *= root_2 + temp;

        root_1 *= work_root;
        root_2 *= work_root;
    }

    // assert_eq!(
    //     numerator_value,
    //     crate::macros::fr!("142a7fdddf74bf207d6721f9f4163df5005780a82daaae1772bb7176e0aa48f1")
    // );
    // assert_eq!(
    //     denominator_value,
    //     crate::macros::fr!("26a36d245a8c6e8d2c327779d18125769a7a43e6afbf34077841673fa1eb80f6")
    // );

    if !valid_inputs {
        panic!("Invalid inputs provided!"); // Q: Is this the desired handling approach?

        // mstore(0x00, PUBLIC_INPUT_GE_P_SELECTOR)
        // revert(0x00, 0x04)
    }

    (numerator_value, denominator_value)
}

fn compute_plookup_delta_factor(circuit_size: u32, challenges: &Challenges) -> (Fr, Fr) {
    let delta_base = challenges.gamma * (challenges.beta + Fr::one());
    let mut delta_numerator = delta_base;
    {
        let exponent = circuit_size;
        let mut count = 1;
        while count < exponent {
            delta_numerator *= delta_numerator;
            count <<= 1;
        }
    }
    let plookup_delta_numerator = delta_numerator;

    let mut delta_denominator = delta_base * delta_base;
    delta_denominator *= delta_denominator;
    let plookup_delta_denominator = delta_denominator;

    (plookup_delta_numerator, plookup_delta_denominator)
}

fn compute_lagrange_and_vanishing_poly<H: CurveHooks>(
    challenges: &Challenges,
    vk: &VerificationKey<H>,
    delta_numerator: &Fr,
    delta_denominator: &Fr,
    plookup_delta_numerator: &Fr,
    plookup_delta_denominator: &Fr,
) -> [Fr; 6] {
    /*
     * vanishing_numerator = zeta
     * ZETA_POW_N = zeta^n
     * vanishing_numerator -= 1
     * accumulating_root = omega_inverse
     * work_root = p - accumulating_root
     * domain_inverse = domain_inverse
     * vanishing_denominator = zeta + work_root
     * work_root *= accumulating_root
     * vanishing_denominator *= (zeta + work_root)
     * work_root *= accumulating_root
     * vanishing_denominator *= (zeta + work_root)
     * vanishing_denominator *= (zeta + (zeta + accumulating_root))
     * work_root = omega
     * lagrange_numerator = vanishing_numerator * domain_inverse
     * l_start_denominator = zeta - 1
     * accumulating_root = work_root^2
     * l_end_denominator = accumulating_root^2 * work_root * zeta - 1
     * Note: l_end_denominator term contains a term \omega^5 to cut out 5 roots of unity from vanishing poly
     */

    let mut vanishing_numerator = challenges.zeta_pow_n;

    // assert_eq!(
    //     challenges.zeta_pow_n,
    //     crate::macros::fr!("0551acf450da38cc8f866b3135ff7b5742f55614eae8361d00c479e3c4a32482")
    // );

    vanishing_numerator -= Fr::one();

    // assert_eq!(
    //     vanishing_numerator,
    //     crate::macros::fr!("0551acf450da38cc8f866b3135ff7b5742f55614eae8361d00c479e3c4a32481")
    // );

    let accumulating_root = vk.work_root_inverse;
    let mut work_root = -accumulating_root;
    let domain_inverse = vk.domain_inverse;

    let mut vanishing_denominator = challenges.zeta + work_root;
    work_root *= accumulating_root;
    vanishing_denominator *= challenges.zeta + work_root;
    work_root *= accumulating_root;
    vanishing_denominator *= challenges.zeta + work_root;
    vanishing_denominator *= challenges.zeta + work_root * accumulating_root;

    work_root = vk.work_root;
    let lagrange_numerator = vanishing_numerator * domain_inverse;
    let l_start_denominator = challenges.zeta - Fr::one();

    let accumulating_root = work_root.square();

    let l_end_denominator = accumulating_root.square() * work_root * challenges.zeta - Fr::one();

    /*
     * Compute inversions using Montgomery's batch inversion trick
     */
    let mut accumulator = *delta_denominator;
    let mut t0 = accumulator;
    accumulator *= vanishing_denominator;
    let mut t1 = accumulator;
    accumulator *= vanishing_numerator;
    let mut t2 = accumulator;
    accumulator *= l_start_denominator;
    let mut t3 = accumulator;
    accumulator *= plookup_delta_denominator;
    let mut t4 = accumulator;
    {
        // Q: Is it worthwhile to move modular exponentiation to native?
        let base = accumulator * l_end_denominator;
        let mut expon = FrConfig::MODULUS;
        expon.0[0] -= 2u64; // FrConfig::MODULUS - 2u32.into_u256()
        accumulator = base.pow(expon);
    }

    t4 *= accumulator;
    accumulator *= l_end_denominator;

    t3 *= accumulator;
    accumulator *= plookup_delta_denominator;

    t2 *= accumulator;
    accumulator *= l_start_denominator;

    t1 *= accumulator;
    accumulator *= vanishing_numerator;

    t0 *= accumulator;
    accumulator *= vanishing_denominator;

    accumulator = accumulator.square() * delta_denominator;

    let public_input_delta = *delta_numerator * accumulator;
    let zero_poly = vanishing_numerator * t0;
    let zero_poly_inverse = vanishing_denominator * t1;
    let l_start = lagrange_numerator * t2;
    let plookup_delta = *plookup_delta_numerator * t3;
    let l_end = lagrange_numerator * t4;

    [
        public_input_delta,
        zero_poly,
        zero_poly_inverse,
        plookup_delta,
        l_start,
        l_end,
    ]
}

fn compute_permutation_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
    l_start: &Fr,
    l_end: &Fr,
    public_input_delta: &Fr,
) -> Fr {
    /*
     * t1 = (W1 + gamma + beta * ID1) * (W2 + gamma + beta * ID2)
     * t2 = (W3 + gamma + beta * ID3) * (W4 + gamma + beta * ID4)
     * result = alpha_base * z_eval * t1 * t2
     * t1 = (W1 + gamma + beta * sigma_1_eval) * (W2 + gamma + beta * sigma_2_eval)
     * t2 = (W3 + gamma + beta * sigma_3_eval) * (W4 + gamma + beta * sigma_4_eval)
     * result -= (alpha_base * z_omega_eval * t1 * t2)
     */
    let w1_eval = proof.w1_eval.into_fr();
    let w2_eval = proof.w2_eval.into_fr();
    let w3_eval = proof.w3_eval.into_fr();
    let w4_eval = proof.w4_eval.into_fr();

    let z_eval = proof.z_eval.into_fr();
    let z_omega_eval = proof.z_omega_eval.into_fr();

    let mut t1 = (w1_eval + challenges.gamma + challenges.beta * proof.id1_eval.into_fr())
        * (w2_eval + challenges.gamma + challenges.beta * proof.id2_eval.into_fr());

    let mut t2 = (w3_eval + challenges.gamma + challenges.beta * proof.id3_eval.into_fr())
        * (w4_eval + challenges.gamma + challenges.beta * proof.id4_eval.into_fr());

    let mut result = challenges.alpha_base * z_eval * t1 * t2;

    t1 = (w1_eval + challenges.gamma + challenges.beta * proof.sigma1_eval.into_fr())
        * (w2_eval + challenges.gamma + challenges.beta * proof.sigma2_eval.into_fr());

    t2 = (w3_eval + challenges.gamma + challenges.beta * proof.sigma3_eval.into_fr())
        * (w4_eval + challenges.gamma + challenges.beta * proof.sigma4_eval.into_fr());

    result -= challenges.alpha_base * z_omega_eval * t1 * t2;

    /*
     * alpha_base *= alpha
     * result += alpha_base . (L_{n-k}(ʓ) . (z(ʓ.ω) - ∆_{PI}))
     * alpha_base *= alpha
     * result += alpha_base . (L_1(ʓ)(Z(ʓ) - 1))
     * alpha_Base *= alpha
     */

    challenges.alpha_base *= challenges.alpha;
    result += challenges.alpha_base * l_end * (z_omega_eval - public_input_delta);
    challenges.alpha_base *= challenges.alpha;
    let permutation_identity = result + challenges.alpha_base * l_start * (z_eval - Fr::one());
    challenges.alpha_base *= challenges.alpha;

    permutation_identity
}

fn compute_plookup_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
    l_start: &Fr,
    l_end: &Fr,
    plookup_delta: &Fr,
) -> Fr {
    /*
     * Goal: f = (w1(z) + q2.w1(zω)) + η(w2(z) + qm.w2(zω)) + η²(w3(z) + qc.w_3(zω)) + q3(z).η³
     * f = η.q3(z)
     * f += (w3(z) + qc.w_3(zω))
     * f *= η
     * f += (w2(z) + qm.w2(zω))
     * f *= η
     * f += (w1(z) + q2.w1(zω))
     */

    let mut f = challenges.eta * proof.q3_eval.into_fr();
    f += proof.w3_eval.into_fr() + proof.qc_eval.into_fr() * proof.w3_omega_eval.into_fr();
    f *= challenges.eta;
    f += proof.w2_eval.into_fr() + proof.qm_eval.into_fr() * proof.w2_omega_eval.into_fr();
    f *= challenges.eta;
    f += proof.w1_eval.into_fr() + proof.q2_eval.into_fr() * proof.w1_omega_eval.into_fr();

    // t(z) = table4(z).η³ + table3(z).η² + table2(z).η + table1(z)
    let t = proof.table4_eval.into_fr() * challenges.eta_cube
        + proof.table3_eval.into_fr() * challenges.eta_sqr
        + proof.table2_eval.into_fr() * challenges.eta
        + proof.table1_eval.into_fr();

    // t(zw) = table4(zw).η³ + table3(zw).η² + table2(zw).η + table1(zw)
    let t_omega = proof.table4_omega_eval.into_fr() * challenges.eta_cube
        + proof.table3_omega_eval.into_fr() * challenges.eta_sqr
        + proof.table2_omega_eval.into_fr() * challenges.eta
        + proof.table1_omega_eval.into_fr();

    /*
     * Goal: numerator = (TABLE_TYPE_EVAL * f(z) + γ) * (t(z) + βt(zω) + γ(β + 1)) * (β + 1)
     * gamma_beta_constant = γ(β + 1)
     * numerator = f * TABLE_TYPE_EVAL + gamma
     * temp0 = t(z) + t(zω) * β + gamma_beta_constant
     * numerator *= temp0
     * numerator *= (β + 1)
     * temp0 = alpha * l_1
     * numerator += temp0
     * numerator *= z_lookup(z)
     * numerator -= temp0
     */

    let gamma_beta_constant = challenges.gamma * (challenges.beta + Fr::one());
    let mut numerator = f * proof.table_type_eval.into_fr() + challenges.gamma;
    let temp0 = t + t_omega * challenges.beta + gamma_beta_constant;
    numerator *= temp0;
    numerator *= challenges.beta + Fr::one();
    let temp0 = challenges.alpha * l_start;
    numerator += temp0;
    numerator *= proof.z_lookup_eval.into_fr();
    numerator -= temp0;

    /*
     * Goal: denominator = z_lookup(zω)*[s(z) + βs(zω) + γ(1 + β)] - [z_lookup(zω) - [γ(1 + β)]^{n-k}]*α²L_end(z)
     * note: delta_factor = [γ(1 + β)]^{n-k}
     * denominator = s(z) + βs(zω) + γ(β + 1)
     * temp1 = α²L_end(z)
     * denominator -= temp1
     * denominator *= z_lookup(zω)
     * denominator += temp1 * delta_factor
     * PLOOKUP_IDENTITY = (numerator - denominator).alpha_base
     * alpha_base *= alpha^3
     */

    let mut denominator = proof.s_eval.into_fr()
        + proof.s_omega_eval.into_fr() * challenges.beta
        + gamma_beta_constant;
    let temp1 = challenges.alpha_sqr * l_end;
    denominator -= temp1;
    denominator *= proof.z_lookup_omega_eval.into_fr();
    denominator += temp1 * plookup_delta;

    let plookup_identity = (numerator - denominator) * challenges.alpha_base;

    // update alpha
    challenges.alpha_base *= challenges.alpha_cube;

    plookup_identity
}

fn compute_arithmetic_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
) -> Fr {
    /*
     * The basic arithmetic gate identity in standard plonk is as follows.
     * (w_1 . w_2 . q_m) + (w_1 . q_1) + (w_2 . q_2) + (w_3 . q_3) + (w_4 . q_4) + q_c = 0
     * However, for Ultraplonk, we extend this to support "passing" wires between rows (shown without alpha scaling below):
     * q_arith * ( ( (-1/2) * (q_arith - 3) * q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c ) +
     * (q_arith - 1)*( α * (q_arith - 2) * (w_1 + w_4 - w_1_omega + q_m) + w_4_omega) ) = 0
     *
     * This formula results in several cases depending on q_arith:
     * 1. q_arith == 0: Arithmetic gate is completely disabled
     *
     * 2. q_arith == 1: Everything in the minigate on the right is disabled. The equation is just a standard plonk equation
     * with extra wires: q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c = 0
     *
     * 3. q_arith == 2: The (w_1 + w_4 - ...) term is disabled. THe equation is:
     * (1/2) * q_m * w_1 * w_2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + w_4_omega = 0
     * It allows defining w_4 at next index (w_4_omega) in terms of current wire values
     *
     * 4. q_arith == 3: The product of w_1 and w_2 is disabled, but a mini addition gate is enabled. α allows us to split
     * the equation into two:
     *
     * q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + 2 * w_4_omega = 0
     * and
     * w_1 + w_4 - w_1_omega + q_m = 0  (we are reusing q_m here)
     *
     * 5. q_arith > 3: The product of w_1 and w_2 is scaled by (q_arith - 3), while the w_4_omega term is scaled by (q_arith - 1).
     * The equation can be split into two:
     *
     * (q_arith - 3)* q_m * w_1 * w_ 2 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 + q_4 * w_4 + q_c + (q_arith - 1) * w_4_omega = 0
     * and
     * w_1 + w_4 - w_1_omega + q_m = 0
     *
     * The problem that q_m is used both in both equations can be dealt with by appropriately changing selector values at
     * the next gate. Then we can treat (q_arith - 1) as a simulated q_6 selector and scale q_m to handle (q_arith - 3) at
     * product.
     */
    let negative_inverse_of_2_modulo_r =
        crate::macros::fr!("183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000"); // = -2^{-1} (mod r)

    let w1q1 = proof.w1_eval.into_fr() * proof.q1_eval.into_fr();
    let w2q2 = proof.w2_eval.into_fr() * proof.q2_eval.into_fr();
    let w3q3 = proof.w3_eval.into_fr() * proof.q3_eval.into_fr();
    let w4q4 = proof.w4_eval.into_fr() * proof.q4_eval.into_fr();

    // @todo - Add a explicit test that hits QARITH == 3
    // w1w2qm := (w_1 . w_2 . q_m . (QARITH_EVAL_LOC - 3)) / 2
    let w1w2qm = proof.w1_eval.into_fr()
        * proof.w2_eval.into_fr()
        * proof.qm_eval.into_fr()
        * (proof.q_arith_eval.into_fr() - Fr::from(3))
        * negative_inverse_of_2_modulo_r;

    // (w_1 . w_2 . q_m . (q_arith - 3)) / -2) + (w_1 . q_1) + (w_2 . q_2) + (w_3 . q_3) + (w_4 . q_4) + q_c
    let identity = w1w2qm + w1q1 + w2q2 + w3q3 + w4q4 + proof.qc_eval.into_fr();

    // if q_arith == 3 we evaluate an additional mini addition gate (on top of the regular one), where:
    // w_1 + w_4 - w_1_omega + q_m = 0
    // we use this gate to save an addition gate when adding or subtracting non-native field elements
    // α * (q_arith - 2) * (w_1 + w_4 - w_1_omega + q_m)
    let extra_small_addition_gate_identity = challenges.alpha
        * (proof.q_arith_eval.into_fr() - Fr::from(2))
        * (proof.w1_eval.into_fr() + proof.w4_eval.into_fr() - proof.w1_omega_eval.into_fr()
            + proof.qm_eval.into_fr());

    // if q_arith == 2 OR q_arith == 3 we add the 4th wire of the NEXT gate into the arithmetic identity
    // N.B. if q_arith > 2, this wire value will be scaled by (q_arith - 1) relative to the other gate wires!
    // alpha_base * q_arith * (identity + (q_arith - 1) * (w_4_omega + extra_small_addition_gate_identity))
    let arithmetic_identity = challenges.alpha_base
        * proof.q_arith_eval.into_fr()
        * (identity
            + (proof.q_arith_eval.into_fr() - Fr::one())
                * (proof.w4_omega_eval.into_fr() + extra_small_addition_gate_identity));

    // update alpha
    challenges.alpha_base *= challenges.alpha_sqr;

    arithmetic_identity
}

fn compute_genpermsort_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
) -> Fr {
    /*
     * D1 = (w2 - w1)
     * D2 = (w3 - w2)
     * D3 = (w4 - w3)
     * D4 = (w1_omega - w4)
     *
     * α_a = alpha_base
     * α_b = alpha_base * α
     * α_c = alpha_base * α^2
     * α_d = alpha_base * α^3
     *
     * range_accumulator = (
     *   D1(D1 - 1)(D1 - 2)(D1 - 3).α_a +
     *   D2(D2 - 1)(D2 - 2)(D2 - 3).α_b +
     *   D3(D3 - 1)(D3 - 2)(D3 - 3).α_c +
     *   D4(D4 - 1)(D4 - 2)(D4 - 3).α_d +
     * ) . q_sort
     */
    // let mut minus_two = FrConfig::MODULUS;
    // minus_two.0[0] -= 2u64;
    // let mut minus_three = FrConfig::MODULUS;
    // minus_three.0[0] -= 3u64;

    let d1 = proof.w2_eval.into_fr() - proof.w1_eval.into_fr();
    let d2 = proof.w3_eval.into_fr() - proof.w2_eval.into_fr();
    let d3 = proof.w4_eval.into_fr() - proof.w3_eval.into_fr();
    let d4 = proof.w1_omega_eval.into_fr() - proof.w4_eval.into_fr();

    let mut range_accumulator =
        d1 * (d1 - Fr::one()) * (d1 - Fr::from(2)) * (d1 - Fr::from(3)) * challenges.alpha_base;
    range_accumulator += d2
        * (d2 - Fr::one())
        * (d2 - Fr::from(2))
        * (d2 - Fr::from(3))
        * challenges.alpha_base
        * challenges.alpha;
    range_accumulator += d3
        * (d3 - Fr::one())
        * (d3 - Fr::from(2))
        * (d3 - Fr::from(3))
        * challenges.alpha_base
        * challenges.alpha_sqr;
    range_accumulator += d4
        * (d4 - Fr::one())
        * (d4 - Fr::from(2))
        * (d4 - Fr::from(3))
        * challenges.alpha_base
        * challenges.alpha_cube;
    range_accumulator *= proof.q_sort_eval.into_fr();

    let sort_identity = range_accumulator;

    // update alpha
    challenges.alpha_base *= challenges.alpha_quad;

    sort_identity
}

fn compute_elliptic_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
) -> Fr {
    /*
     * endo_term = (-x_2) * x_1 * (x_3 * 2 + x_1) * q_beta
     * endo_sqr_term = x_2^2
     * endo_sqr_term *= (x_3 - x_1)
     * endo_sqr_term *= q_beta^2
     * leftovers = x_2^2
     * leftovers *= x_2
     * leftovers += x_1^2 * (x_3 + x_1) @follow-up Invalid comment in BB widget
     * leftovers -= (y_2^2 + y_1^2)
     * sign_term = y_2 * y_1
     * sign_term += sign_term
     * sign_term *= q_sign
     */

    // Aliases:
    let x1_eval = &proof.w2_eval;
    let x2_eval = &proof.w1_omega_eval;
    let x3_eval = &proof.w2_omega_eval;
    let y1_eval = &proof.w3_eval;
    let y2_eval = &proof.w4_omega_eval;
    let y3_eval = &proof.w3_omega_eval;
    let qsign = &proof.q1_eval;

    // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
    let x_diff = x2_eval.into_fr() - x1_eval.into_fr();
    let y2_sqr = y2_eval.into_fr().square();
    let y1_sqr = y1_eval.into_fr().square();
    let y1y2 = y1_eval.into_fr() * y2_eval.into_fr() * qsign.into_fr();

    let mut x_add_identity = (x3_eval.into_fr() + x2_eval.into_fr() + x1_eval.into_fr())
        * x_diff.square()
        + y1y2.double()
        - (y1_sqr + y2_sqr);
    x_add_identity = x_add_identity * (Fr::one() - proof.qm_eval.into_fr()) * challenges.alpha_base;

    // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
    let y1_plus_y3 = y1_eval.into_fr() + y3_eval.into_fr();
    let y_diff = y2_eval.into_fr() * qsign.into_fr() - y1_eval.into_fr();
    let mut y_add_identity =
        y1_plus_y3 * x_diff + ((x3_eval.into_fr() - x1_eval.into_fr()) * y_diff);
    y_add_identity *=
        (Fr::one() - proof.qm_eval.into_fr()) * challenges.alpha_base * challenges.alpha;

    // ELLIPTIC_IDENTITY = (x_identity + y_identity) * Q_ELLIPTIC_EVAL
    let mut elliptic_identity = (x_add_identity + y_add_identity) * proof.q_elliptic_eval.into_fr();

    /*
     * x_pow_4 = (y_1_sqr - curve_b) * x_1;
     * y_1_sqr_mul_4 = y_1_sqr + y_1_sqr;
     * y_1_sqr_mul_4 += y_1_sqr_mul_4;
     * x_1_pow_4_mul_9 = x_pow_4;
     * x_1_pow_4_mul_9 += x_1_pow_4_mul_9;
     * x_1_pow_4_mul_9 += x_1_pow_4_mul_9;
     * x_1_pow_4_mul_9 += x_1_pow_4_mul_9;
     * x_1_pow_4_mul_9 += x_pow_4;
     * x_1_sqr_mul_3 = x_1_sqr + x_1_sqr + x_1_sqr;
     * x_double_identity = (x_3 + x_1 + x_1) * y_1_sqr_mul_4 - x_1_pow_4_mul_9;
     * y_double_identity = x_1_sqr_mul_3 * (x_1 - x_3) - (y_1 + y_1) * (y_1 + y_3);
     */

    // y^2 = x^3 + ax + b
    // for Grumpkin, a = 0 and b = -17. We use b in a custom gate relation that evaluates elliptic curve arithmetic
    let grumpkin_curve_b_parameter_negated = Fr::from(17);

    // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
    let x1_sqr = x1_eval.into_fr().square();
    let x_pow_4 = (y1_sqr + grumpkin_curve_b_parameter_negated) * x1_eval.into_fr();
    let y1_sqr_mul_4 = y1_sqr * Fr::from(4);
    let x1_pow_4_mul_9 = x_pow_4 * Fr::from(9);
    let x1_sqr_mul_3 = x1_sqr * Fr::from(3);
    let mut x_double_identity =
        (x3_eval.into_fr() + x1_eval.into_fr().double()) * y1_sqr_mul_4 - x1_pow_4_mul_9;

    // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
    let mut y_double_identity = x1_sqr_mul_3 * (x1_eval.into_fr() - x3_eval.into_fr())
        - y1_eval.into_fr().double() * (y1_eval.into_fr() + y3_eval.into_fr());

    x_double_identity *= challenges.alpha_base;
    y_double_identity *= challenges.alpha_base * challenges.alpha;
    x_double_identity *= proof.qm_eval.into_fr();
    y_double_identity *= proof.qm_eval.into_fr();

    // ELLIPTIC_IDENTITY += (x_double_identity + y_double_identity) * Q_DOUBLE_EVAL
    elliptic_identity += (x_double_identity + y_double_identity) * proof.q_elliptic_eval.into_fr();

    // update alpha
    challenges.alpha_base *= challenges.alpha_quad;

    elliptic_identity
}

fn compute_aux_non_native_field_evaluation<H: CurveHooks>(proof: &Proof<H>) -> Fr {
    /*
     * Non native field arithmetic gate 2
     *             _                                                                               _
     *            /   _                   _                               _       14                \
     * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
     *            \_                                                                               _/
     *
     * limb_subproduct = w_1 . w_2_omega + w_1_omega . w_2
     * non_native_field_gate_2 = w_1 * w_4 + w_4 * w_3 - w_3_omega
     * non_native_field_gate_2 = non_native_field_gate_2 * limb_size
     * non_native_field_gate_2 -= w_4_omega
     * non_native_field_gate_2 += limb_subproduct
     * non_native_field_gate_2 *= q_4
     * limb_subproduct *= limb_size
     * limb_subproduct += w_1_omega * w_2_omega
     * non_native_field_gate_1 = (limb_subproduct + w_3 + w_4) * q_3
     * non_native_field_gate_3 = (limb_subproduct + w_4 - (w_3_omega + w_4_omega)) * q_m
     * non_native_field_identity = (non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3) * q_2
     */

    let limb_size: Fr = U256::new([
        0x0000000000000000,
        0x0000000000000010,
        0x0000000000000000,
        0x0000000000000000,
    ])
    .into_fr(); // = 2 << 68 = 0x100000000000000000

    let mut limb_subproduct = proof.w1_eval.into_fr() * proof.w2_omega_eval.into_fr()
        + proof.w1_omega_eval.into_fr() * proof.w2_eval.into_fr();

    let mut non_native_field_gate_2 = proof.w1_eval.into_fr() * proof.w4_eval.into_fr()
        + proof.w2_eval.into_fr() * proof.w3_eval.into_fr()
        - proof.w3_omega_eval.into_fr();

    non_native_field_gate_2 *= limb_size;
    non_native_field_gate_2 -= proof.w4_omega_eval.into_fr();
    non_native_field_gate_2 += limb_subproduct;
    non_native_field_gate_2 *= proof.q4_eval.into_fr();
    limb_subproduct *= limb_size;
    limb_subproduct += proof.w1_omega_eval.into_fr() * proof.w2_omega_eval.into_fr();

    let non_native_field_gate_1 = (limb_subproduct
        - (proof.w3_eval.into_fr() + proof.w4_eval.into_fr()))
        * proof.q3_eval.into_fr();

    let non_native_field_gate_3 = (limb_subproduct + proof.w4_eval.into_fr()
        - (proof.w3_omega_eval.into_fr() + proof.w4_omega_eval.into_fr()))
        * proof.qm_eval.into_fr();

    // let non_native_field_identity =
    //     (non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3)
    //         * proof.q2_eval.into_fr();

    // compute non_native_field_identity
    (non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3)
        * proof.q2_eval.into_fr()

    // let aux_non_native_field_evaluation = non_native_field_identity;

    // // assert_eq!(
    // //     aux_non_native_field_evaluation,
    // //     crate::macros::fr!("0eb8b1fefb472249833127bf535e1e00d13df4faca4bf14da4b381c2a6b87319")
    // // );

    // aux_non_native_field_evaluation
}

fn compute_aux_limb_accumulator_evaluation<H: CurveHooks>(proof: &Proof<H>) -> Fr {
    /*
     * limb_accumulator_1 = w_2_omega;
     * limb_accumulator_1 *= SUBLIMB_SHIFT;
     * limb_accumulator_1 += w_1_omega;
     * limb_accumulator_1 *= SUBLIMB_SHIFT;
     * limb_accumulator_1 += w_3;
     * limb_accumulator_1 *= SUBLIMB_SHIFT;
     * limb_accumulator_1 += w_2;
     * limb_accumulator_1 *= SUBLIMB_SHIFT;
     * limb_accumulator_1 += w_1;
     * limb_accumulator_1 -= w_4;
     * limb_accumulator_1 *= q_4;
     */

    let sublimb_shift: Fr = Fr::from(0x4000); // 1 << 14 = 0x4000

    let mut limb_accumulator_1 = proof.w2_omega_eval.into_fr() * sublimb_shift;
    limb_accumulator_1 += proof.w1_omega_eval.into_fr();
    limb_accumulator_1 *= sublimb_shift;
    limb_accumulator_1 += proof.w3_eval.into_fr();
    limb_accumulator_1 *= sublimb_shift;
    limb_accumulator_1 += proof.w2_eval.into_fr();
    limb_accumulator_1 *= sublimb_shift;
    limb_accumulator_1 += proof.w1_eval.into_fr();
    limb_accumulator_1 += -proof.w4_eval.into_fr();
    limb_accumulator_1 *= proof.q4_eval.into_fr();

    /*
     * limb_accumulator_2 = w_3_omega;
     * limb_accumulator_2 *= SUBLIMB_SHIFT;
     * limb_accumulator_2 += w_2_omega;
     * limb_accumulator_2 *= SUBLIMB_SHIFT;
     * limb_accumulator_2 += w_1_omega;
     * limb_accumulator_2 *= SUBLIMB_SHIFT;
     * limb_accumulator_2 += w_4;
     * limb_accumulator_2 *= SUBLIMB_SHIFT;
     * limb_accumulator_2 += w_3;
     * limb_accumulator_2 -= w_4_omega;
     * limb_accumulator_2 *= q_m;
     */
    let mut limb_accumulator_2 = proof.w3_omega_eval.into_fr() * sublimb_shift;
    limb_accumulator_2 += proof.w2_omega_eval.into_fr();
    limb_accumulator_2 *= sublimb_shift;
    limb_accumulator_2 += proof.w1_omega_eval.into_fr();
    limb_accumulator_2 *= sublimb_shift;
    limb_accumulator_2 += proof.w4_eval.into_fr();
    limb_accumulator_2 *= sublimb_shift;
    limb_accumulator_2 += proof.w3_eval.into_fr();
    limb_accumulator_2 += -proof.w4_omega_eval.into_fr();
    limb_accumulator_2 *= proof.qm_eval.into_fr();

    (limb_accumulator_1 + limb_accumulator_2) * proof.q3_eval.into_fr()

    // let aux_limb_accumulator_evaluation =
    //     (limb_accumulator_1 + limb_accumulator_2) * proof.q3_eval.into_fr();

    // // assert_eq!(
    // //     aux_limb_accumulator_evaluation,
    // //     crate::macros::fr!("078280b92a0853ec534893876f5f66e23b8251c6ac222cde3027aa5ba19b0874")
    // // );

    // aux_limb_accumulator_evaluation
}

fn compute_aux_ram_consistency_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
    index_delta: &Fr,
    partial_record_check: &Fr,
    index_is_monotonically_increasing: &Fr,
) -> Fr {
    /*
     * next_gate_access_type = w_3_omega;
     * next_gate_access_type *= eta;
     * next_gate_access_type += w_2_omega;
     * next_gate_access_type *= eta;
     * next_gate_access_type += w_1_omega;
     * next_gate_access_type *= eta;
     * next_gate_access_type = w_4_omega - next_gate_access_type;
     */

    let mut next_gate_access_type = proof.w3_omega_eval.into_fr() * challenges.eta;
    next_gate_access_type += proof.w2_omega_eval.into_fr();
    next_gate_access_type *= challenges.eta;
    next_gate_access_type += proof.w1_omega_eval.into_fr();
    next_gate_access_type *= challenges.eta;
    next_gate_access_type = proof.w4_omega_eval.into_fr() - next_gate_access_type;

    // value_delta = w_3_omega - w_3
    let value_delta = proof.w3_omega_eval.into_fr() - proof.w3_eval.into_fr();

    //  adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation = (1 - index_delta) * value_delta * (1 - next_gate_access_type);
    let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
        (Fr::one() - index_delta) * value_delta * (Fr::one() - next_gate_access_type);

    // AUX_RAM_CONSISTENCY_EVALUATION

    /*
     * access_type = w_4 - partial_record_check
     * access_check = access_type^2 - access_type
     * next_gate_access_type_is_boolean = next_gate_access_type^2 - next_gate_access_type
     * RAM_consistency_check_identity = adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation;
     * RAM_consistency_check_identity *= alpha;
     * RAM_consistency_check_identity += index_is_monotonically_increasing;
     * RAM_consistency_check_identity *= alpha;
     * RAM_consistency_check_identity += next_gate_access_type_is_boolean;
     * RAM_consistency_check_identity *= alpha;
     * RAM_consistency_check_identity += access_check;
     */

    let access_type = proof.w4_eval.into_fr() - partial_record_check;

    let access_check = access_type * (access_type - Fr::one());

    let next_gate_access_type_is_boolean =
        next_gate_access_type * (next_gate_access_type - Fr::one());

    let mut ram_cci =
        adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
            * challenges.alpha;

    ram_cci += index_is_monotonically_increasing;
    ram_cci *= challenges.alpha;
    ram_cci += next_gate_access_type_is_boolean;
    ram_cci *= challenges.alpha;
    ram_cci += access_check;

    ram_cci
}

fn compute_auxiliary_identity<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
    index_delta: &Fr,
    aux_evaluations: &AuxiliaryEvaluations,
) -> Fr {
    // timestamp_delta = w_2_omega - w_2
    let timestamp_delta = proof.w2_omega_eval.into_fr() - proof.w2_eval.into_fr();

    // RAM_timestamp_check_identity = (1 - index_delta) * timestamp_delta - w_3
    let ram_timestamp_check_identity =
        (Fr::one() - index_delta) * timestamp_delta - proof.w3_eval.into_fr();

    /*
     * memory_identity = ROM_consistency_check_identity * q_2;
     * memory_identity += RAM_timestamp_check_identity * q_4;
     * memory_identity += AUX_MEMORY_EVALUATION * q_m;
     * memory_identity *= q_1;
     * memory_identity += (RAM_consistency_check_identity * q_arith);
     *
     * auxiliary_identity = memory_identity + non_native_field_identity + limb_accumulator_identity;
     * auxiliary_identity *= q_aux;
     * auxiliary_identity *= alpha_base;
     */

    let mut memory_identity =
        aux_evaluations.aux_rom_consistency_evaluation * proof.q2_eval.into_fr();
    memory_identity += ram_timestamp_check_identity * proof.q4_eval.into_fr();
    memory_identity += aux_evaluations.aux_memory_evaluation * proof.qm_eval.into_fr();
    memory_identity *= proof.q1_eval.into_fr();
    memory_identity +=
        aux_evaluations.aux_ram_consistency_evaluation * proof.q_arith_eval.into_fr();

    let mut auxiliary_identity = memory_identity + aux_evaluations.aux_non_native_field_evaluation;

    auxiliary_identity += aux_evaluations.aux_limb_accumulator_evaluation;

    auxiliary_identity *= proof.q_aux_eval.into_fr();

    auxiliary_identity *= challenges.alpha_base;

    // update alpha
    challenges.alpha_base *= challenges.alpha_cube;

    auxiliary_identity
}

fn compute_auxiliary_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &mut Challenges,
) -> Fr {
    /*
     * memory_record_check = w_3;
     * memory_record_check *= eta;
     * memory_record_check += w_2;
     * memory_record_check *= eta;
     * memory_record_check += w_1;
     * memory_record_check *= eta;
     * memory_record_check += q_c;
     *
     * partial_record_check = memory_record_check;
     *
     * memory_record_check -= w_4;
     */

    let aux_non_native_field_evaluation = compute_aux_non_native_field_evaluation::<H>(proof);
    let aux_limb_accumulator_evaluation = compute_aux_limb_accumulator_evaluation::<H>(proof);

    let mut memory_record_check = proof.w3_eval.into_fr() * challenges.eta;
    memory_record_check += proof.w2_eval.into_fr();
    memory_record_check *= challenges.eta;
    memory_record_check += proof.w1_eval.into_fr();
    memory_record_check *= challenges.eta;
    memory_record_check += proof.qc_eval.into_fr();

    let partial_record_check = memory_record_check;
    memory_record_check += -proof.w4_eval.into_fr();

    let aux_memory_evaluation = memory_record_check;

    // assert_eq!(
    //     aux_memory_evaluation,
    //     crate::macros::fr!("2a0addd6dddfc4d71e6ba910a84343f162a0857acf5df519d75e8a1489f3d710")
    // );

    // index_delta = w_1_omega - w_1
    let index_delta = proof.w1_omega_eval.into_fr() - proof.w1_eval.into_fr();
    // record_delta = w_4_omega - w_4
    let record_delta = proof.w4_omega_eval.into_fr() - proof.w4_eval.into_fr();
    // index_is_monotonically_increasing = index_delta * (index_delta - 1)
    let index_is_monotonically_increasing = index_delta * (index_delta - Fr::one());

    // adjacent_values_match_if_adjacent_indices_match = record_delta * (1 - index_delta)
    let adjacent_values_match_if_adjacent_indices_match = record_delta * (Fr::one() - index_delta);

    // AUX_ROM_CONSISTENCY_EVALUATION = ((adjacent_values_match_if_adjacent_indices_match * alpha) + index_is_monotonically_increasing) * alpha + memory_record_check
    let aux_rom_consistency_evaluation = (adjacent_values_match_if_adjacent_indices_match
        * challenges.alpha
        + index_is_monotonically_increasing)
        * challenges.alpha
        + memory_record_check;

    let aux_ram_consistency_evaluation = compute_aux_ram_consistency_evaluation::<H>(
        proof,
        challenges,
        &index_delta,
        &partial_record_check,
        &index_is_monotonically_increasing,
    );

    // assert_eq!(
    //     aux_rom_consistency_evaluation,
    //     crate::macros::fr!("27c8e9796351f7747ea1ecc0163ad32225528fa3802d0d87d98213346443bf65")
    // );

    // assert_eq!(
    //     aux_ram_consistency_evaluation,
    //     crate::macros::fr!("0bd9ace98d894621c4a5c719f2cbe4fea6b8522638d43cdd3868587a84cf433d")
    // );

    let aux_evaluations = AuxiliaryEvaluations {
        aux_memory_evaluation,
        aux_rom_consistency_evaluation,
        aux_ram_consistency_evaluation,
        aux_non_native_field_evaluation,
        aux_limb_accumulator_evaluation,
    };

    compute_auxiliary_identity::<H>(proof, challenges, &index_delta, &aux_evaluations)
}

fn quotient_evaluation(
    permutation_identity: &Fr,
    plookup_identity: &Fr,
    arithmetic_identity: &Fr,
    sort_identity: &Fr,
    elliptic_identity: &Fr,
    aux_identity: &Fr,
    zero_poly_inverse: &Fr,
) -> Fr {
    /*
     * quotient = ARITHMETIC_IDENTITY
     * quotient += PERMUTATION_IDENTITY
     * quotient += PLOOKUP_IDENTITY
     * quotient += SORT_IDENTITY
     * quotient += ELLIPTIC_IDENTITY
     * quotient += AUX_IDENTITY
     * quotient *= ZERO_POLY_INVERSE
     */

    (permutation_identity
        + plookup_identity
        + arithmetic_identity
        + sort_identity
        + elliptic_identity
        + aux_identity)
        * zero_poly_inverse
}

fn perform_final_checks<H: CurveHooks>(
    proof: &Proof<H>,
    vk: &VerificationKey<H>,
    challenges: &Challenges,
    nu_challenges: &NuChallenges,
    quotient_eval: &Fr,
) -> bool {
    /*
     * VALIDATIONS AND ACCUMULATIONS
     */

    // Note: Validations are performed automatically by Arkworks upon construction of EC points.
    let mut accumulator = proof.t1.into_group();

    // assert_eq!(
    //     accumulator.x,
    //     read_fq(&hex_literal::hex!(
    //         "2a927caded56827ac403fab8e088eb4e4b80da829ed406e1ef308b95f18181fd"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     accumulator.y,
    //     read_fq(&hex_literal::hex!(
    //         "00b8e0558b77daed027ad8a2d7f6027de8e2dc9ddafd572170312d511f0e5df8"
    //     ))
    //     .unwrap()
    // );

    // NOTE: EXPENSIVE OPERATIONS (SCALAR MULS and POINT ADDITIONS) OCCUR BELOW THIS POINT.
    // TODO: MAKE USE OF NATIVE!!!

    // T2

    let mut scalar = challenges.zeta_pow_n;
    // accumulator_2 = [T2].zeta^n
    let mut accumulator2 = proof.t2.into_group() * scalar;
    // accumulator = [T1] + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "1168bf9d60be65b1029b945ce70dd0457cd298692b410143152d8575df466f4e"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "221b867eeee1c324d9c77ea57a0e2978b36eec8868be10b01b19779bdf81566d"
    //     ))
    //     .unwrap()
    // );

    // T3

    scalar.square_in_place();
    // accumulator_2 = [T3].zeta^{2n}
    accumulator2 = proof.t3.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "021bdd4f0103fc1c96edbe883314b21be295d70a0a44850ffdd3b73bb81bfbaf"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "19e75758e39281e48044b10a2186bf27c5cf9d1b4917e1c401ebe67999208644"
    //     ))
    //     .unwrap()
    // );

    // T4

    scalar *= challenges.zeta_pow_n;
    // accumulator_2 = [T4].zeta^{3n}
    accumulator2 = proof.t4.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2a6a2b71b82c6922ab29f883a125a2cfef185bd0082d20eec73ca5da5c292d4f"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2db5e003e37435a1ed3a5c425823e094d78b508d03810cf0a102ea4dc593686e"
    //     ))
    //     .unwrap()
    // );

    // W1

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[0];
    // accumulator_2 = v0.(u + 1).[W1]
    accumulator2 = proof.w1.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "08d867cca9d35082658b756c7f5eaf79b30de2d914a06388e833b7bec160e631"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "1f6c55a518a3da8fbcc5a09e73f2327e6562260698358029e476f55edd23dfe7"
    //     ))
    //     .unwrap()
    // );

    // W2

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[1];
    // accumulator_2 = v1.(u + 1).[W2]
    accumulator2 = proof.w2.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "046d10f8563de265d4d466c6caa6f0675f9a6309d0be466fe52560c216f2c22c"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "116e082340f0c3277f2c621d1d18e1e5a878df850d727fdbd5eec902fee61b02"
    //     ))
    //     .unwrap()
    // );

    // W3

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[2];
    // accumulator_2 = v2.(u + 1).[W3]
    accumulator2 = proof.w3.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2bbe5273f3e00b8778a5d220b203333d990f32eba3a6eb99bf4bc1213d0f5f42"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "074b69333ef4a622781e86a55d34609a5c86cfcad53d37b6f1238d695cc24ec3"
    //     ))
    //     .unwrap()
    // );

    // W4

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[3];
    // accumulator_2 = v3.(u + 1).[W4]
    accumulator2 = proof.w4.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2052a9558ab82d8e4d7e7dab8acf9a8af96b3cde3f21f207df76285db45ce1ac"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "06aa831918f9a2e57f68120c1426aa831354a58caa52ee4e2a2b61d514e531c3"
    //     ))
    //     .unwrap()
    // );

    // S

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[4];
    // accumulator_2 = v4.(u + 1).[S]
    accumulator2 = proof.s.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0fe2a2044deadc57711f7ba6aaa6e65bd9550ffe111eba93b2d0a311afd2268f"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "21c703ee9e8948aa47c6bd9140086b20e4685085fc403f73c5a1e1ba50e3337a"
    //     ))
    //     .unwrap()
    // );

    // Z

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[5];
    // accumulator_2 = v5.(u + 1).[Z]
    accumulator2 = proof.z.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "26b9b255d47db2ca4abbe5e5947d1cc8b5d918feb8e5cd9b843b2cad30badb20"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "047d92ab6024dc768c651f4ed62e438a44b2cee621fd0ef12d40fdfce9ef6c9b"
    //     ))
    //     .unwrap()
    // );

    // Z_LOOKUP

    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[6];
    // accumulator_2 = v6.(u + 1).[Z_LOOKUP]
    accumulator2 = proof.z_lookup.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "07cb06d2db0167180ec5335a8e8fa07a33834f8eeb23ff1d05d71af7cbcb937b"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "1f2891cf3967bbc699204c04912ff4e2983555474580dc542d420fd871725905"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE Q1

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[7];
    // accumulator_2 = v7.[Q1]
    accumulator2 = vk.q_1.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "00ac9a9e7253699258aa0c55abf0da0630523c58abb1de3bf29267575a996f57"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2017643c767f8dda5b759922c7df0866aadbfaec224add5fee3da185f4015da3"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE Q2

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[8];
    // accumulator_2 = v8.[Q2]
    accumulator2 = vk.q_2.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "21038c60e59a9ab8eabfff291e168857eb859bfef41dd70dfc44757c0480471e"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0fd8c76678742ec47d14585946ec83d78263095824109feaa76de7dfea8d7b83"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE Q3

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[9];
    // accumulator_2 = v9.[Q3]
    accumulator2 = vk.q_3.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "282e71621a291ae234bdbbce64e470fecbb47f16390f91cd6c07f30459122e61"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0389094c8bca435a4a57572e6d12262c86e58450748b5641ebf4d89a2e7fcce4"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE Q4

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[10];
    // accumulator_2 = v10.[Q4]
    accumulator2 = vk.q_4.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "02385f45ca661913e3750927572ae5597e260e40c18c30d288a8e66152dc21a8"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "01883a8afaef0d6aa182adc8718d90e6732792558cde634a8853716fe8cf0d55"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE QM

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[11];
    // accumulator_2 = v11.[QM]
    accumulator2 = vk.q_m.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "1e62ad61fff8afb95c92cb2e9f1043dbb49ffe32c98aa9c0a4312dd2aba4ad5e"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "18fd968a0423a992b68c76a0885f4b6a63fbbe8970bd36389642a8f0778b5e1d"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE QC

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[12];
    // accumulator_2 = v12.[QC]
    accumulator2 = vk.q_c.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "1e27be987d5cd1d38ce6e38f2171da60d4be2185117f7350f309840016a34c8b"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "031b4b24e187a33373391fa7251eb5d10e99bfac81fb30998000336b2335c6ff"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE QARITH

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[13];
    // accumulator_2 = v13.[QARITH]
    accumulator2 = vk.q_arithmetic.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "28e40ef3b9d60fff4ff2eb1782cf784162f451bca8b0a9b2f4d7b7699199e9c0"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2ad8a608c51ae477fb786e554a14452907426a49fe3cd6568f662ffd0fddf326"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE QSORT

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[14];
    // accumulator_2 = v14.[QSORT]
    accumulator2 = vk.q_sort.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "28f936634c507351f270274a86f8a7fc41e32d5c39a7ec2de3caa3ee6d176738"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "190e279b9efecf262166ef8cb51b86d0497bec349d29482a7c0f78e94f930f5a"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE QELLIPTIC

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[15];
    // accumulator_2 = v15.[QELLIPTIC]
    accumulator2 = vk.q_elliptic.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "14127ba0b4a5719ed4049f8349351468d22fd40160a8557a4ab74fa5088257ec"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "19bca1dad32d9e93d5506fda91de86a7f0236a25437b0d6abcdd4c0c4db0aff9"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE QAUX

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[16];
    // accumulator_2 = v16.[QAUX]
    accumulator2 = vk.q_aux.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "109b5669329dee2e91fe657e900f77617b99331c111fc987534ae7fade0281f3"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "208937163af04438bdc122332075eb4e50c5f9047eedd902e4a4224a089181e6"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE SIGMA1

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[17];
    // accumulator_2 = v17.[sigma1]
    accumulator2 = vk.sigma_1.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "23e0e5345a50e2b73a8c57d3523d62a95519cfc66f95ccc550b89ba7b3552b12"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "03caf6c2b7a37eeb6c78b10df7ff773a535a8f42a7190b637872f6dc9aa2c048"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE SIGMA2

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[18];
    // accumulator_2 = v18.[sigma2]
    accumulator2 = vk.sigma_2.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "220a46a6bf3d46abe7318c0170c389ba167e64938faa1be9d37f87139df4a887"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "02954d9a29d4067400017fe5219d57a56db82c7fcf89976a61753d866c9a0476"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE SIGMA3

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[19];
    // accumulator_2 = v19.[sigma3]
    accumulator2 = vk.sigma_3.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "02d2d3dbf9c2261024a8011650e770ba8f4469f9f15ffa3ecc1549d2bcf19593"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2dd080661c2875eff3125526ea1b7f8ec68549542e440839e00f317e4c1fa9df"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE SIGMA4

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[20];
    // accumulator_2 = v20.[sigma4]
    accumulator2 = vk.sigma_4.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "12b4d71edb8b96df6a42bb60ecd70f8de06cc171147a25a536894142e19a47bd"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "20637bf1c32d7480c605597e3cadcfe0ed0ad4eab774435d2f9753be0f0986ac"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE TABLE1

    // Verification key fields verified to be on curve at contract deployment
    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[21];
    // accumulator_2 = (u+1).v21.[table1]
    accumulator2 = vk.table_1.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "248b937b8fec1798082b1e8e1101115588deed5d455850a45484e4c93c3e8663"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "09c3d27eec5bba9573981f8b061db452d5d7f193bef5898a53d5b9fe11cbb887"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE TABLE2

    // Verification key fields verified to be on curve at contract deployment
    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[22];
    // accumulator_2 = (u + 1).v22.[table2]
    accumulator2 = vk.table_2.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2dce3304102d7ff45307ee00099b96b635eb3e94bb6a4eb904c601d2179b4aae"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "069ff7a93ebdcc2977adcc7f974dec9553700941fc797d32a7b1355c59c56797"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE TABLE3

    // Verification key fields verified to be on curve at contract deployment
    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[23];
    // accumulator_2 = (u + 1).v23.[table3]
    accumulator2 = vk.table_3.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "118776455da086cabeb20110f42267f76d58e404c6797aa1a6a3499d6471eb25"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0f753e81e8641547ef1ac06bfd68e9e40e45ae99373c1a9f0dd26cbf0f7dd4e1"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE TABLE4

    // Verification key fields verified to be on curve at contract deployment
    scalar = (nu_challenges.c_u + Fr::one()) * nu_challenges.c_v[24];
    // accumulator_2 = (u + 1).v24.[table4]
    accumulator2 = vk.table_4.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "11127011895888e62971d3bfe0f69d4f7522a551c8c399c3bddd8cd2e4edc6ca"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "06fdda2ba420ecf6aad2d3ded58ec72486412b27cd59487bd6ab2cac4d71119c"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE TABLE_TYPE

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[25];
    // accumulator_2 = v25.[TableType]
    accumulator2 = vk.table_type.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "2ac1f4b92afecbaaf83a50099fd6515c62b66d36fc151b9076033fb8125233ab"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "00a1bf2e2319c4828e586b150aeed0b3d90ba1efa7f9521f7032ef64c90936b6"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE ID1

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[26];
    // accumulator_2 = v26.[ID1]
    accumulator2 = vk.id_1.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "028225874f74c6b89ba2ae62f3c67d25e0441abe7436eb95e770a99dbb3c6325"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "292c63dbe5a0fa3417373f185b50ab96e5865fe05e5b26c6472df54fad7008cf"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE ID2

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[27];
    // accumulator_2 = v27.[ID2]
    accumulator2 = vk.id_2.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "032c5c016a118b0cea2c4fabea0f3b7c5d51aae37cc07bbe281c0c716a50807d"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "061c4f9d40abd400e57cc695b71f6f68726ac6af568b7670e92509e17ac66767"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE ID3

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[28];
    // accumulator_2 = v28.[ID3]
    accumulator2 = vk.id_3.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "218388e274f4e27c0338e471f703d04b30b47b71d2d18a27847820720778a147"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0c7f450e07e3bcf57011d0033d800fc537d45bf71b8392bf1e21eaaad42901f0"
    //     ))
    //     .unwrap()
    // );

    // ACCUMULATE ID4

    // Verification key fields verified to be on curve at contract deployment
    scalar = nu_challenges.c_v[29];
    // accumulator_2 = v29.[ID4]
    accumulator2 = vk.id_4.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "212cf4d7f87d25690d58478b568c629b1e0c04043600335509f4b2bb86349323"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0359e3ba837aac9daca8277f3d3c2041a905e0925a28324ddb60b8bf13d4028c"
    //     ))
    //     .unwrap()
    // );

    // COMPUTE BATCH EVALUATION SCALAR MULTIPLIER
    let batch_evaluation =
        compute_batch_evaluation_scalar_multiplier::<H>(proof, nu_challenges, quotient_eval);
    let point = <<Config<H> as BnConfig>::G1Config as SWCurveConfig>::GENERATOR.into_group(); // G = (1, 2)

    // accumulator_2 = -[1].(batch_evaluation)
    accumulator2 = point * (-batch_evaluation);
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "1b6b8919246da75789501bd861783891d85f80b49056998bbfb642f23b089de0"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0da28eb34af2fd1d4b218aacbb329c97efdfee44954734494fa0da94eb4fa003"
    //     ))
    //     .unwrap()
    // );

    /*
     * PERFORM PAIRING PREAMBLE
     */
    let mut pairing_lhs;

    // u = nu_challenges.c_u
    // zeta = challenges.zeta

    // VALIDATE PI_Z

    scalar = challenges.zeta;
    // compute zeta.[PI_Z] and add into accumulator
    accumulator2 = proof.pi_z.into_group() * scalar;
    // accumulator = accumulator + accumulator_2
    accumulator += accumulator2;

    // assert_eq!(
    //     *accumulator.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "23e62155a196ef1e8e02d2ddc09c914fb9c9c9371ab6a8e503cda05abfebd082"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *accumulator.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0028ac25bd05abf0b6f2eb1b8bfedc658bdb06e5328a78e7efdb13f9304b7c7a"
    //     ))
    //     .unwrap()
    // );

    // VALIDATE PI_Z_OMEGA

    scalar = nu_challenges.c_u * challenges.zeta * vk.work_root;
    // accumulator_2 = u.zeta.omega.[PI_Z_OMEGA]
    accumulator2 = proof.pi_z_omega.into_group() * scalar;
    // PAIRING_RHS = accumulator + accumulator_2
    let pairing_rhs = accumulator + accumulator2;

    // assert_eq!(
    //     *pairing_rhs.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0f49ea18353cee38d7045f8d8fce93de9d43657a7443a238c732f5eddbddb93c"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *pairing_rhs.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "04ff64f4841dbd83d35b33298c797a563e100e731f0678c0f6f1e2c6eb7b74bf"
    //     ))
    //     .unwrap()
    // );

    scalar = nu_challenges.c_u;
    // accumulator_2 = u.[PI_Z_OMEGA]
    accumulator2 = proof.pi_z_omega.into_group() * scalar;
    // PAIRING_LHS = [PI_Z] + [PI_Z_OMEGA] * u
    pairing_lhs = proof.pi_z.into_group() + accumulator2;
    // negate lhs y-coordinate
    pairing_lhs.y = -pairing_lhs.y;

    // assert_eq!(
    //     *pairing_lhs.into_affine().x().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0938778e7f7309ca99231045c99ddc9f8fc94a841f66e18b9a3a9a66f7dfe9c1"
    //     ))
    //     .unwrap()
    // );
    // assert_eq!(
    //     *pairing_lhs.into_affine().y().unwrap(),
    //     read_fq(&hex_literal::hex!(
    //         "0c09427d83a79ca0faef46564c0788056d2f05adb76248f9cf87dd864f5c3865"
    //     ))
    //     .unwrap()
    // );

    if vk.contains_recursive_proof {
        // TODO: ADD CODE (LINES: 2682-2725)
    }

    /*
     * PERFORM PAIRING
     */

    // rhs paired with [1]_2
    // lhs paired with [x]_2

    // NOTE: Here, we need to convert to Affine. Hence, it probably
    // makes sense to keep the points in Affine in the first place
    // and only switch to Projective when computations are required.

    let g1_points = [
        G1Prepared::from(pairing_rhs.into_affine()),
        G1Prepared::from(pairing_lhs.into_affine()),
    ];

    let g2_points = [
        G2Prepared::from(G2::<H>::generator()),
        G2Prepared::from(read_g2::<H>(&SRS_G2).unwrap()),
    ];

    let product = Bn254::<H>::multi_pairing(g1_points, g2_points);

    // Product of pairings must equal 1
    product.0.is_one()
}

/*
 * COMPUTE BATCH EVALUATION SCALAR MULTIPLIER
 */
fn compute_batch_evaluation_scalar_multiplier<H: CurveHooks>(
    proof: &Proof<H>,
    nu_challenges: &NuChallenges,
    quotient_eval: &Fr,
) -> Fr {
    /*
     * batch_evaluation = v0 * (w_1_omega * u + w_1_eval)
     * batch_evaluation += v1 * (w_2_omega * u + w_2_eval)
     * batch_evaluation += v2 * (w_3_omega * u + w_3_eval)
     * batch_evaluation += v3 * (w_4_omega * u + w_4_eval)
     * batch_evaluation += v4 * (s_omega_eval * u + s_eval)
     * batch_evaluation += v5 * (z_omega_eval * u + z_eval)
     * batch_evaluation += v6 * (z_lookup_omega_eval * u + z_lookup_eval)
     */
    let mut batch_evaluation = nu_challenges.c_v[0]
        * (proof.w1_omega_eval.into_fr() * nu_challenges.c_u + proof.w1_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[1]
        * (proof.w2_omega_eval.into_fr() * nu_challenges.c_u + proof.w2_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[2]
        * (proof.w3_omega_eval.into_fr() * nu_challenges.c_u + proof.w3_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[3]
        * (proof.w4_omega_eval.into_fr() * nu_challenges.c_u + proof.w4_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[4]
        * (proof.s_omega_eval.into_fr() * nu_challenges.c_u + proof.s_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[5]
        * (proof.z_omega_eval.into_fr() * nu_challenges.c_u + proof.z_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[6]
        * (proof.z_lookup_omega_eval.into_fr() * nu_challenges.c_u + proof.z_lookup_eval.into_fr());

    /*
     * batch_evaluation += v7 * Q1_EVAL
     * batch_evaluation += v8 * Q2_EVAL
     * batch_evaluation += v9 * Q3_EVAL
     * batch_evaluation += v10 * Q4_EVAL
     * batch_evaluation += v11 * QM_EVAL
     * batch_evaluation += v12 * QC_EVAL
     * batch_evaluation += v13 * QARITH_EVAL
     * batch_evaluation += v14 * QSORT_EVAL_LOC
     * batch_evaluation += v15 * QELLIPTIC_EVAL_LOC
     * batch_evaluation += v16 * QAUX_EVAL_LOC
     * batch_evaluation += v17 * SIGMA1_EVAL_LOC
     * batch_evaluation += v18 * SIGMA2_EVAL_LOC
     * batch_evaluation += v19 * SIGMA3_EVAL_LOC
     * batch_evaluation += v20 * SIGMA4_EVAL_LOC
     */

    batch_evaluation += nu_challenges.c_v[7] * proof.q1_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[8] * proof.q2_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[9] * proof.q3_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[10] * proof.q4_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[11] * proof.qm_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[12] * proof.qc_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[13] * proof.q_arith_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[14] * proof.q_sort_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[15] * proof.q_elliptic_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[16] * proof.q_aux_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[17] * proof.sigma1_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[18] * proof.sigma2_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[19] * proof.sigma3_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[20] * proof.sigma4_eval.into_fr();

    /*
     * batch_evaluation += v21 * (table1(zw) * u + table1(z))
     * batch_evaluation += v22 * (table2(zw) * u + table2(z))
     * batch_evaluation += v23 * (table3(zw) * u + table3(z))
     * batch_evaluation += v24 * (table4(zw) * u + table4(z))
     * batch_evaluation += v25 * table_type_eval
     * batch_evaluation += v26 * id1_eval
     * batch_evaluation += v27 * id2_eval
     * batch_evaluation += v28 * id3_eval
     * batch_evaluation += v29 * id4_eval
     * batch_evaluation += quotient_eval
     */

    batch_evaluation += nu_challenges.c_v[21]
        * (proof.table1_omega_eval.into_fr() * nu_challenges.c_u + proof.table1_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[22]
        * (proof.table2_omega_eval.into_fr() * nu_challenges.c_u + proof.table2_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[23]
        * (proof.table3_omega_eval.into_fr() * nu_challenges.c_u + proof.table3_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[24]
        * (proof.table4_omega_eval.into_fr() * nu_challenges.c_u + proof.table4_eval.into_fr());

    batch_evaluation += nu_challenges.c_v[25] * proof.table_type_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[26] * proof.id1_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[27] * proof.id2_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[28] * proof.id3_eval.into_fr();
    batch_evaluation += nu_challenges.c_v[29] * proof.id4_eval.into_fr();
    batch_evaluation += quotient_eval;

    batch_evaluation
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::macros::u256;
    use crate::resources::VALID_VK;

    #[test]
    fn test_parse_proof() {
        let proof = resources::VALID_PROOF;
        println!("{:?}", proof);
    }

    #[test]
    fn test_foo() {
        println!(
            "{:?}",
            u256!("0000001000000000000000000000000000000000000000000000000000000000") //.into_bytes()
        );
        println!(
            "{:?}",
            u256!("0000000100000000000000000000000000000000000000000000000000000000")
        );

        println!(
            "{:?}",
            u256!("0000001000000001000000000000000000000000000000000000000000000000") // value that gets hashed
        );
        //         00000010 00000001 00000000 00000000 00000000 00000000 00000000 00000000
        //         <------4th------> <------3rd------> <------2nd------> <------1st------>
        //         0 0 0 16  0 0 0 1  0 0 0 0  0 0 0 0 0 0 0 0  0 0 0 0  0 0 0 0  0 0 0 0

        println!(
            "{:?}",
            u256!("0000001000000000000000000000000000000000000000000000000000000000").into_bytes()
        );
        println!(
            "{:?}",
            u256!("0000000100000000000000000000000000000000000000000000000000000000").into_bytes()
        );
        println!(
            "{:?}",
            u256!("0000001000000001000000000000000000000000000000000000000000000000").into_bytes()
        );
    }

    #[test]
    fn test_verify() {
        use testhooks::TestHooks;
        let raw_proof = resources::VALID_PROOF;
        let raw_vk = VALID_VK.as_ref();
        let pi_1 = 10_u32.into_u256().into_bytes();
        let pubs: &[[u8; 32]] = &[pi_1];

        // x = "5"  (witness)
        // y = "10" (public input)
        assert_eq!(verify::<TestHooks>(&raw_vk, &raw_proof, pubs).unwrap(), ());
    }
}
