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

pub const PROOF_SIZE: usize = 2144; // = 67 * 32
pub const PUBS_SIZE: usize = 32;
pub const VK_SIZE: usize = 1714; // TODO: Revise if necessary once recursive proofs are supported

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
        let mut c_v: [Fr; 31] = [Fr::ONE; 31];

        hasher.update(buffer);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize_reset());
        let mut challenge = hash;

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

pub fn validate_vk<H: CurveHooks>(raw_vk: &[u8; VK_SIZE]) -> Result<(), VerifyError> {
    let _vk = VerificationKey::<H>::try_from(&raw_vk[..]).map_err(|e| {
        // log::debug!("Cannot parse verification key: {:?}", e);
        VerifyError::InvalidVerificationKey
    })?;
    Ok(())
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

    // Eta Challenge
    challenge = generate_eta_challenge::<H>(&proof, public_inputs, &challenge);

    let eta = challenge.into_fr();

    // Beta challenge
    challenge = generate_beta_challenge::<H>(&proof, &challenge);

    let beta = challenge.into_fr();

    // Gamma challenge
    challenge = generate_gamma_challenge(&challenge);

    let gamma = challenge.into_fr();

    // Alpha challenge
    challenge = generate_alpha_challenge::<H>(&proof, &challenge);

    let alpha = challenge.into_fr();

    // Zeta challenge
    challenge = generate_zeta_challenge::<H>(&proof, &challenge);
    let zeta = challenge.into_fr();

    let c_current = challenge;

    let mut challenges = Challenges::new(alpha, beta, gamma, zeta, eta, vk.circuit_size);

    /*
     *   EVALUATE FIELD OPERATIONS
     */

    /*
     *   COMPUTE PUBLIC INPUT DELTA
     *   ΔPI = ∏ᵢ∈ℓ(wᵢ + β σ(i) + γ) / ∏ᵢ∈ℓ(wᵢ + β σ'(i) + γ)
     */
    let (delta_numerator, delta_denominator) =
        compute_public_input_delta(public_inputs, &vk.work_root, &mut challenges);

    /*
     *  Compute Plookup delta factor [γ(1 + β)]^{n-k}
     *  k = num roots cut out of Z_H = 4
     */
    let (plookup_delta_numerator, plookup_delta_denominator) =
        compute_plookup_delta_factor(vk.circuit_size, &challenges);

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

    /*
     * COMPUTE ARITHMETIC WIDGET EVALUATION
     */
    let arithmetic_identity = compute_arithmetic_widget_evaluation::<H>(&proof, &mut challenges);

    /*
     * COMPUTE GENPERMSORT WIDGET EVALUATION
     */
    let sort_identity = compute_genpermsort_widget_evaluation::<H>(&proof, &mut challenges);

    /*
     * COMPUTE ELLIPTIC WIDGET EVALUATION
     */
    let elliptic_identity = compute_elliptic_widget_evaluation::<H>(&proof, &mut challenges);

    /*
     * COMPUTE AUXILIARY WIDGET EVALUATION
     */
    let aux_identity = compute_auxiliary_widget_evaluation::<H>(&proof, &mut challenges);

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

    /*
     * GENERATE NU AND SEPARATOR CHALLENGES
     */
    let nu_challenges = NuChallenges::new(&proof, &c_current, &quotient_eval).unwrap();

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
    let mut buffer = Vec::new();

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
        .chain_update(proof.w4.y.into_bytes())
        .chain_update(proof.w4.x.into_bytes())
        .chain_update(proof.s.y.into_bytes())
        .chain_update(proof.s.x.into_bytes())
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
    let mut numerator_value = Fr::ONE;
    let mut denominator_value = Fr::ONE;
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

    if !valid_inputs {
        panic!("Invalid inputs provided!"); // Q: Is this the desired handling approach?

        // mstore(0x00, PUBLIC_INPUT_GE_P_SELECTOR)
        // revert(0x00, 0x04)
    }

    (numerator_value, denominator_value)
}

fn compute_plookup_delta_factor(circuit_size: u32, challenges: &Challenges) -> (Fr, Fr) {
    let delta_base = challenges.gamma * (challenges.beta + Fr::ONE);
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

    vanishing_numerator -= Fr::ONE;

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
    let l_start_denominator = challenges.zeta - Fr::ONE;

    let accumulating_root = work_root.square();

    let l_end_denominator = accumulating_root.square() * work_root * challenges.zeta - Fr::ONE;

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
        expon.0[0] -= 2u64;
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
    let permutation_identity = result + challenges.alpha_base * l_start * (z_eval - Fr::ONE);
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

    let gamma_beta_constant = challenges.gamma * (challenges.beta + Fr::ONE);
    let mut numerator = f * proof.table_type_eval.into_fr() + challenges.gamma;
    let temp0 = t + t_omega * challenges.beta + gamma_beta_constant;
    numerator *= temp0;
    numerator *= challenges.beta + Fr::ONE;
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
            + (proof.q_arith_eval.into_fr() - Fr::ONE)
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

    let d1 = proof.w2_eval.into_fr() - proof.w1_eval.into_fr();
    let d2 = proof.w3_eval.into_fr() - proof.w2_eval.into_fr();
    let d3 = proof.w4_eval.into_fr() - proof.w3_eval.into_fr();
    let d4 = proof.w1_omega_eval.into_fr() - proof.w4_eval.into_fr();

    let mut range_accumulator =
        d1 * (d1 - Fr::ONE) * (d1 - Fr::from(2)) * (d1 - Fr::from(3)) * challenges.alpha_base;
    range_accumulator += d2
        * (d2 - Fr::ONE)
        * (d2 - Fr::from(2))
        * (d2 - Fr::from(3))
        * challenges.alpha_base
        * challenges.alpha;
    range_accumulator += d3
        * (d3 - Fr::ONE)
        * (d3 - Fr::from(2))
        * (d3 - Fr::from(3))
        * challenges.alpha_base
        * challenges.alpha_sqr;
    range_accumulator += d4
        * (d4 - Fr::ONE)
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
    x_add_identity = x_add_identity * (Fr::ONE - proof.qm_eval.into_fr()) * challenges.alpha_base;

    // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
    let y1_plus_y3 = y1_eval.into_fr() + y3_eval.into_fr();
    let y_diff = y2_eval.into_fr() * qsign.into_fr() - y1_eval.into_fr();
    let mut y_add_identity =
        y1_plus_y3 * x_diff + ((x3_eval.into_fr() - x1_eval.into_fr()) * y_diff);
    y_add_identity *=
        (Fr::ONE - proof.qm_eval.into_fr()) * challenges.alpha_base * challenges.alpha;

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

    // compute non_native_field_identity
    (non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3)
        * proof.q2_eval.into_fr()
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
        (Fr::ONE - index_delta) * value_delta * (Fr::ONE - next_gate_access_type);

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

    let access_check = access_type * (access_type - Fr::ONE);

    let next_gate_access_type_is_boolean =
        next_gate_access_type * (next_gate_access_type - Fr::ONE);

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
        (Fr::ONE - index_delta) * timestamp_delta - proof.w3_eval.into_fr();

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

    // index_delta = w_1_omega - w_1
    let index_delta = proof.w1_omega_eval.into_fr() - proof.w1_eval.into_fr();
    // record_delta = w_4_omega - w_4
    let record_delta = proof.w4_omega_eval.into_fr() - proof.w4_eval.into_fr();
    // index_is_monotonically_increasing = index_delta * (index_delta - 1)
    let index_is_monotonically_increasing = index_delta * (index_delta - Fr::ONE);

    // adjacent_values_match_if_adjacent_indices_match = record_delta * (1 - index_delta)
    let adjacent_values_match_if_adjacent_indices_match = record_delta * (Fr::ONE - index_delta);

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

    // Note: Validations already took place back when we parsed the proof.
    let u_plus_one = nu_challenges.c_u + Fr::ONE;
    let zeta_pow_2n = challenges.zeta_pow_n.square();
    let zeta_pow_3n = zeta_pow_2n * challenges.zeta_pow_n;
    // COMPUTE BATCH EVALUATION SCALAR MULTIPLIER
    let batch_evaluation =
        compute_batch_evaluation_scalar_multiplier::<H>(proof, nu_challenges, quotient_eval);

    // TODO: Update bases and scalars once support for recursive proofs is added.
    let bases = [
        proof.t1,
        proof.t2,
        proof.t3,
        proof.t4,
        proof.w1,
        proof.w2,
        proof.w3,
        proof.w4,
        proof.s,
        proof.z,
        proof.z_lookup,
        vk.q_1,
        vk.q_2,
        vk.q_3,
        vk.q_4,
        vk.q_m,
        vk.q_c,
        vk.q_arithmetic,
        vk.q_sort,
        vk.q_elliptic,
        vk.q_aux,
        vk.sigma_1,
        vk.sigma_2,
        vk.sigma_3,
        vk.sigma_4,
        vk.table_1,
        vk.table_2,
        vk.table_3,
        vk.table_4,
        vk.table_type,
        vk.id_1,
        vk.id_2,
        vk.id_3,
        vk.id_4,
        <<Config<H> as BnConfig>::G1Config as SWCurveConfig>::GENERATOR,
        proof.pi_z,
        proof.pi_z_omega,
    ];

    let scalars = [
        Fr::ONE,
        challenges.zeta_pow_n,
        zeta_pow_2n,
        zeta_pow_3n,
        nu_challenges.c_v[0] * u_plus_one,
        nu_challenges.c_v[1] * u_plus_one,
        nu_challenges.c_v[2] * u_plus_one,
        nu_challenges.c_v[3] * u_plus_one,
        nu_challenges.c_v[4] * u_plus_one,
        nu_challenges.c_v[5] * u_plus_one,
        nu_challenges.c_v[6] * u_plus_one,
        nu_challenges.c_v[7],
        nu_challenges.c_v[8],
        nu_challenges.c_v[9],
        nu_challenges.c_v[10],
        nu_challenges.c_v[11],
        nu_challenges.c_v[12],
        nu_challenges.c_v[13],
        nu_challenges.c_v[14],
        nu_challenges.c_v[15],
        nu_challenges.c_v[16],
        nu_challenges.c_v[17],
        nu_challenges.c_v[18],
        nu_challenges.c_v[19],
        nu_challenges.c_v[20],
        nu_challenges.c_v[21] * u_plus_one,
        nu_challenges.c_v[22] * u_plus_one,
        nu_challenges.c_v[23] * u_plus_one,
        nu_challenges.c_v[24] * u_plus_one,
        nu_challenges.c_v[25],
        nu_challenges.c_v[26],
        nu_challenges.c_v[27],
        nu_challenges.c_v[28],
        nu_challenges.c_v[29],
        -batch_evaluation,
        challenges.zeta,
        challenges.zeta * nu_challenges.c_u * vk.work_root,
    ];

    let pairing_rhs = H::bn254_msm_g1(&bases, &scalars).unwrap();

    // PAIRING_LHS = [PI_Z] + [PI_Z_OMEGA] * u
    let bases = [proof.pi_z_omega, proof.pi_z];
    let scalars = [nu_challenges.c_u, Fr::ONE];
    let mut pairing_lhs = H::bn254_msm_g1(&bases, &scalars).unwrap();
    // negate lhs y-coordinate
    pairing_lhs.y = -pairing_lhs.y;

    /*
     * PERFORM PAIRING
     */

    // rhs paired with [1]_2
    // lhs paired with [x]_2

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
