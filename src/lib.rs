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
pub mod key;
pub mod proof;
mod resources;
mod srs;
pub mod testhooks;
mod types;
mod utils;

use crate::{
    key::{read_g2, VerificationKey},
    proof::Proof,
    srs::SRS_G2,
};
use ark_bn254_ext::{Config, CurveHooks};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{Field, MontConfig, MontFp, One};
use ark_models_ext::bn::{BnConfig, G1Prepared, G2Prepared};
use errors::VerifyError;
use sha3::{Digest, Keccak256};
use utils::{IntoBytes, IntoFr, IntoU256};

pub use types::*;

extern crate alloc;
extern crate core;
use alloc::vec::Vec;

pub const PROOF_SIZE: usize = 2144; // = 67 * 32
pub const PUBS_SIZE: usize = 32;
pub const VK_SIZE: usize = 1779;

const NEGATIVE_INVERSE_OF_2_MODULO_R: Fr =
    MontFp!("10944121435919637611123202872628637544274182200208017171849102093287904247808");
const LIMB_SIZE: Fr = MontFp!("295147905179352825856"); // = 2 << 68
const SUBLIMB_SHIFT: Fr = MontFp!("16384"); // 1 << 14 = 0x4000 = 16384

/// The public input.
pub type PublicInput = [u8; PUBS_SIZE];

#[derive(Debug)]
pub struct Challenges {
    alpha: Fr,
    alpha_sqr: Fr,
    alpha_cube: Fr,
    alpha_quad: Fr,
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
    c_v: [Fr; 30],
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
        let challenge: [u8; 32] = Keccak256::new()
            .chain_update(c_current)
            .chain_update(quotient_eval.into_bytes())
            .chain_update(proof.w1_eval.into_bytes())
            .chain_update(proof.w2_eval.into_bytes())
            .chain_update(proof.w3_eval.into_bytes())
            .chain_update(proof.w4_eval.into_bytes())
            .chain_update(proof.s_eval.into_bytes())
            .chain_update(proof.z_eval.into_bytes())
            .chain_update(proof.z_lookup_eval.into_bytes())
            .chain_update(proof.q1_eval.into_bytes())
            .chain_update(proof.q2_eval.into_bytes())
            .chain_update(proof.q3_eval.into_bytes())
            .chain_update(proof.q4_eval.into_bytes())
            .chain_update(proof.qm_eval.into_bytes())
            .chain_update(proof.qc_eval.into_bytes())
            .chain_update(proof.q_arith_eval.into_bytes())
            .chain_update(proof.q_sort_eval.into_bytes())
            .chain_update(proof.q_elliptic_eval.into_bytes())
            .chain_update(proof.q_aux_eval.into_bytes())
            .chain_update(proof.sigma1_eval.into_bytes())
            .chain_update(proof.sigma2_eval.into_bytes())
            .chain_update(proof.sigma3_eval.into_bytes())
            .chain_update(proof.sigma4_eval.into_bytes())
            .chain_update(proof.table1_eval.into_bytes())
            .chain_update(proof.table2_eval.into_bytes())
            .chain_update(proof.table3_eval.into_bytes())
            .chain_update(proof.table4_eval.into_bytes())
            .chain_update(proof.table_type_eval.into_bytes())
            .chain_update(proof.id1_eval.into_bytes())
            .chain_update(proof.id2_eval.into_bytes())
            .chain_update(proof.id3_eval.into_bytes())
            .chain_update(proof.id4_eval.into_bytes())
            .chain_update(proof.w1_omega_eval.into_bytes())
            .chain_update(proof.w2_omega_eval.into_bytes())
            .chain_update(proof.w3_omega_eval.into_bytes())
            .chain_update(proof.w4_omega_eval.into_bytes())
            .chain_update(proof.s_omega_eval.into_bytes())
            .chain_update(proof.z_omega_eval.into_bytes())
            .chain_update(proof.z_lookup_omega_eval.into_bytes())
            .chain_update(proof.table1_omega_eval.into_bytes())
            .chain_update(proof.table2_omega_eval.into_bytes())
            .chain_update(proof.table3_omega_eval.into_bytes())
            .chain_update(proof.table4_omega_eval.into_bytes())
            .finalize()
            .into();

        let c_v: [Fr; 30] = core::array::from_fn(|i| {
            if i == 0 {
                challenge.into_fr()
            } else {
                let hash: [u8; 32] = Keccak256::new()
                    .chain_update(challenge)
                    .chain_update([i as u8])
                    .finalize()
                    .into();
                hash.into_fr()
            }
        });

        let hash: [u8; 32] = Keccak256::new()
            .chain_update(challenge)
            .chain_update(proof.pi_z.y.into_bytes())
            .chain_update(proof.pi_z.x.into_bytes())
            .chain_update(proof.pi_z_omega.y.into_bytes())
            .chain_update(proof.pi_z_omega.x.into_bytes())
            .finalize()
            .into();
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
    pubs: &[PublicInput],
) -> Result<(), VerifyError> {
    let vk =
        VerificationKey::<H>::try_from(raw_vk).map_err(|_| VerifyError::InvalidVerificationKey)?;
    let proof = Proof::<H>::try_from(raw_proof).map_err(|_| VerifyError::InvalidProofData)?;

    // TODO: PARSE RECURSIVE PROOF

    let public_inputs = &pubs
        .iter()
        .map(|pi_bytes| pi_bytes.into_u256())
        .collect::<Vec<U256>>();

    // Generate Challenges
    let mut challenge = generate_initial_challenge(vk.circuit_size, vk.num_public_inputs);
    challenge = generate_eta_challenge::<H>(&proof, public_inputs, &challenge);
    let eta = challenge.into_fr();
    challenge = generate_beta_challenge::<H>(&proof, &challenge);
    let beta = challenge.into_fr();
    challenge = generate_gamma_challenge(&challenge);
    let gamma = challenge.into_fr();
    challenge = generate_alpha_challenge::<H>(&proof, &challenge);
    let alpha = challenge.into_fr();
    let alpha_base = alpha;
    challenge = generate_zeta_challenge::<H>(&proof, &challenge);
    let zeta = challenge.into_fr();
    let c_current = challenge;
    let challenges = Challenges::new(alpha, beta, gamma, zeta, eta, vk.circuit_size);

    // Evaluate Field Operations

    /*
     *   COMPUTE PUBLIC INPUT DELTA
     *   ΔPI = ∏ᵢ∈ℓ(wᵢ + β σ(i) + γ) / ∏ᵢ∈ℓ(wᵢ + β σ'(i) + γ)
     */
    let (delta_numerator, delta_denominator) =
        compute_public_input_delta(public_inputs, &vk.work_root, &challenges)
            .map_err(|_| VerifyError::InvalidInput)?;

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
            &delta_numerator,
            &delta_denominator,
            &plookup_delta_numerator,
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
    let (permutation_identity, alpha_base) = compute_permutation_widget_evaluation::<H>(
        &proof,
        &challenges,
        alpha_base,
        &l_start,
        &l_end,
        &public_input_delta,
    );

    /*
     * COMPUTE PLOOKUP WIDGET EVALUATION
     */
    let (plookup_identity, alpha_base) = compute_plookup_widget_evaluation::<H>(
        &proof,
        &challenges,
        alpha_base,
        &l_start,
        &l_end,
        &plookup_delta,
    );

    /*
     * COMPUTE ARITHMETIC WIDGET EVALUATION
     */
    let (arithmetic_identity, alpha_base) =
        compute_arithmetic_widget_evaluation::<H>(&proof, &challenges, alpha_base);

    /*
     * COMPUTE GENPERMSORT WIDGET EVALUATION
     */
    let (sort_identity, alpha_base) =
        compute_genpermsort_widget_evaluation::<H>(&proof, &challenges, alpha_base);

    /*
     * COMPUTE ELLIPTIC WIDGET EVALUATION
     */
    let (elliptic_identity, alpha_base) =
        compute_elliptic_widget_evaluation::<H>(&proof, &challenges, alpha_base);

    /*
     * COMPUTE AUXILIARY WIDGET EVALUATION
     */
    let (aux_identity, _alpha_base) =
        compute_auxiliary_widget_evaluation::<H>(&proof, &challenges, alpha_base);

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
    let nu_challenges = NuChallenges::new(&proof, &c_current, &quotient_eval)
        .map_err(|_| VerifyError::OtherError)?;

    /*
     * PERFORM FINAL CHECKS
     */

    if perform_final_checks::<H>(&proof, &vk, &challenges, &nu_challenges, &quotient_eval) {
        Ok(())
    } else {
        Err(VerifyError::VerificationError)
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
    let mut hasher = Keccak256::new();

    hasher.update(initial_challenge);
    for input in public_inputs {
        hasher.update(input.into_bytes());
    }
    hasher.update(proof.w1.y.into_bytes());
    hasher.update(proof.w1.x.into_bytes());
    hasher.update(proof.w2.y.into_bytes());
    hasher.update(proof.w2.x.into_bytes());
    hasher.update(proof.w3.y.into_bytes());
    hasher.update(proof.w3.x.into_bytes());

    hasher.finalize().into()
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
    Keccak256::new()
        .chain_update(challenge)
        .chain_update([1u8])
        .finalize()
        .into()
}

/**
 * Generate alpha challenge
 */
fn generate_alpha_challenge<H: CurveHooks>(proof: &Proof<H>, challenge: &[u8; 32]) -> [u8; 32] {
    Keccak256::new()
        .chain_update(challenge)
        .chain_update(proof.z.y.into_bytes())
        .chain_update(proof.z.x.into_bytes())
        .chain_update(proof.z_lookup.y.into_bytes())
        .chain_update(proof.z_lookup.x.into_bytes())
        .finalize()
        .into()
}

/**
 * Generate zeta challenge
 */
fn generate_zeta_challenge<H: CurveHooks>(proof: &Proof<H>, challenge: &[u8; 32]) -> [u8; 32] {
    Keccak256::new()
        .chain_update(challenge)
        .chain_update(proof.t1.y.into_bytes())
        .chain_update(proof.t1.x.into_bytes())
        .chain_update(proof.t2.y.into_bytes())
        .chain_update(proof.t2.x.into_bytes())
        .chain_update(proof.t3.y.into_bytes())
        .chain_update(proof.t3.x.into_bytes())
        .chain_update(proof.t4.y.into_bytes())
        .chain_update(proof.t4.x.into_bytes())
        .finalize()
        .into()
}

fn compute_public_input_delta(
    public_inputs: &[U256],
    work_root: &Fr,
    challenges: &Challenges,
) -> Result<(Fr, Fr), VerifyError> {
    let mut numerator_value = Fr::ONE;
    let mut denominator_value = Fr::ONE;
    let mut valid_inputs = true;

    // root_1 = β * 0x05
    let mut root_1 = challenges.beta * MontFp!("5"); // k1.β

    // root_2 = β * 0x0c
    let mut root_2 = challenges.beta * MontFp!("12");

    for &input in public_inputs {
        valid_inputs &= input < FrConfig::MODULUS;
        let temp = input.into_fr() + challenges.gamma;
        numerator_value *= root_1 + temp;
        denominator_value *= root_2 + temp;

        root_1 *= work_root;
        root_2 *= work_root;
    }

    if !valid_inputs {
        return Err(VerifyError::InvalidInput);
    }

    Ok((numerator_value, denominator_value))
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

    let mut inverses = [
        *delta_denominator,
        vanishing_denominator,
        vanishing_numerator,
        l_start_denominator,
        *plookup_delta_denominator,
        l_end_denominator,
    ];

    ark_ff::fields::batch_inversion(&mut inverses);

    let public_input_delta = *delta_numerator * inverses[0];
    let zero_poly = vanishing_numerator * inverses[1];
    let zero_poly_inverse = vanishing_denominator * inverses[2];
    let l_start = lagrange_numerator * inverses[3];
    let plookup_delta = *plookup_delta_numerator * inverses[4];
    let l_end = lagrange_numerator * inverses[5];

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
    challenges: &Challenges,
    mut alpha_base: Fr,
    l_start: &Fr,
    l_end: &Fr,
    public_input_delta: &Fr,
) -> (Fr, Fr) {
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

    let mut result = alpha_base * z_eval * t1 * t2;

    t1 = (w1_eval + challenges.gamma + challenges.beta * proof.sigma1_eval.into_fr())
        * (w2_eval + challenges.gamma + challenges.beta * proof.sigma2_eval.into_fr());

    t2 = (w3_eval + challenges.gamma + challenges.beta * proof.sigma3_eval.into_fr())
        * (w4_eval + challenges.gamma + challenges.beta * proof.sigma4_eval.into_fr());

    result -= alpha_base * z_omega_eval * t1 * t2;

    alpha_base *= challenges.alpha;
    result += alpha_base * l_end * (z_omega_eval - public_input_delta);
    alpha_base *= challenges.alpha;
    let permutation_identity = result + alpha_base * l_start * (z_eval - Fr::ONE);
    alpha_base *= challenges.alpha;

    (permutation_identity, alpha_base)
}

fn compute_plookup_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &Challenges,
    mut alpha_base: Fr,
    l_start: &Fr,
    l_end: &Fr,
    plookup_delta: &Fr,
) -> (Fr, Fr) {
    let mut f = challenges.eta * proof.q3_eval.into_fr();
    f += proof.w3_eval.into_fr() + proof.qc_eval.into_fr() * proof.w3_omega_eval.into_fr();
    f *= challenges.eta;
    f += proof.w2_eval.into_fr() + proof.qm_eval.into_fr() * proof.w2_omega_eval.into_fr();
    f *= challenges.eta;
    f += proof.w1_eval.into_fr() + proof.q2_eval.into_fr() * proof.w1_omega_eval.into_fr();

    let t = proof.table4_eval.into_fr() * challenges.eta_cube
        + proof.table3_eval.into_fr() * challenges.eta_sqr
        + proof.table2_eval.into_fr() * challenges.eta
        + proof.table1_eval.into_fr();

    let t_omega = proof.table4_omega_eval.into_fr() * challenges.eta_cube
        + proof.table3_omega_eval.into_fr() * challenges.eta_sqr
        + proof.table2_omega_eval.into_fr() * challenges.eta
        + proof.table1_omega_eval.into_fr();

    let gamma_beta_constant = challenges.gamma * (challenges.beta + Fr::ONE);
    let mut numerator = f * proof.table_type_eval.into_fr() + challenges.gamma;
    let temp0 = t + t_omega * challenges.beta + gamma_beta_constant;
    numerator *= temp0;
    numerator *= challenges.beta + Fr::ONE;
    let temp0 = challenges.alpha * l_start;
    numerator += temp0;
    numerator *= proof.z_lookup_eval.into_fr();
    numerator -= temp0;

    let mut denominator = proof.s_eval.into_fr()
        + proof.s_omega_eval.into_fr() * challenges.beta
        + gamma_beta_constant;
    let temp1 = challenges.alpha_sqr * l_end;
    denominator -= temp1;
    denominator *= proof.z_lookup_omega_eval.into_fr();
    denominator += temp1 * plookup_delta;

    let plookup_identity = (numerator - denominator) * alpha_base;

    // update alpha
    alpha_base *= challenges.alpha_cube;

    (plookup_identity, alpha_base)
}

fn compute_arithmetic_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &Challenges,
    mut alpha_base: Fr,
) -> (Fr, Fr) {
    let w1q1 = proof.w1_eval.into_fr() * proof.q1_eval.into_fr();
    let w2q2 = proof.w2_eval.into_fr() * proof.q2_eval.into_fr();
    let w3q3 = proof.w3_eval.into_fr() * proof.q3_eval.into_fr();
    let w4q4 = proof.w4_eval.into_fr() * proof.q4_eval.into_fr();

    let w1w2qm = proof.w1_eval.into_fr()
        * proof.w2_eval.into_fr()
        * proof.qm_eval.into_fr()
        * (proof.q_arith_eval.into_fr() - MontFp!("3"))
        * NEGATIVE_INVERSE_OF_2_MODULO_R;

    let identity = w1w2qm + w1q1 + w2q2 + w3q3 + w4q4 + proof.qc_eval.into_fr();

    let extra_small_addition_gate_identity = challenges.alpha
        * (proof.q_arith_eval.into_fr() - MontFp!("2"))
        * (proof.w1_eval.into_fr() + proof.w4_eval.into_fr() - proof.w1_omega_eval.into_fr()
            + proof.qm_eval.into_fr());

    let arithmetic_identity = alpha_base
        * proof.q_arith_eval.into_fr()
        * (identity
            + (proof.q_arith_eval.into_fr() - Fr::ONE)
                * (proof.w4_omega_eval.into_fr() + extra_small_addition_gate_identity));

    // update alpha
    alpha_base *= challenges.alpha_sqr;

    (arithmetic_identity, alpha_base)
}

fn compute_genpermsort_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &Challenges,
    mut alpha_base: Fr,
) -> (Fr, Fr) {
    let d1 = proof.w2_eval.into_fr() - proof.w1_eval.into_fr();
    let d2 = proof.w3_eval.into_fr() - proof.w2_eval.into_fr();
    let d3 = proof.w4_eval.into_fr() - proof.w3_eval.into_fr();
    let d4 = proof.w1_omega_eval.into_fr() - proof.w4_eval.into_fr();

    let mut range_accumulator =
        d1 * (d1 - Fr::ONE) * (d1 - MontFp!("2")) * (d1 - MontFp!("3")) * alpha_base;
    range_accumulator += d2
        * (d2 - Fr::ONE)
        * (d2 - MontFp!("2"))
        * (d2 - MontFp!("3"))
        * alpha_base
        * challenges.alpha;
    range_accumulator += d3
        * (d3 - Fr::ONE)
        * (d3 - MontFp!("2"))
        * (d3 - MontFp!("3"))
        * alpha_base
        * challenges.alpha_sqr;
    range_accumulator += d4
        * (d4 - Fr::ONE)
        * (d4 - MontFp!("2"))
        * (d4 - MontFp!("3"))
        * alpha_base
        * challenges.alpha_cube;
    range_accumulator *= proof.q_sort_eval.into_fr();

    let sort_identity = range_accumulator;

    // update alpha
    alpha_base *= challenges.alpha_quad;

    (sort_identity, alpha_base)
}

fn compute_elliptic_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &Challenges,
    mut alpha_base: Fr,
) -> (Fr, Fr) {
    // Aliases:
    let x1_eval = &proof.w2_eval;
    let x2_eval = &proof.w1_omega_eval;
    let x3_eval = &proof.w2_omega_eval;
    let y1_eval = &proof.w3_eval;
    let y2_eval = &proof.w4_omega_eval;
    let y3_eval = &proof.w3_omega_eval;
    let qsign = &proof.q1_eval;

    let x_diff = x2_eval.into_fr() - x1_eval.into_fr();
    let y2_sqr = y2_eval.into_fr().square();
    let y1_sqr = y1_eval.into_fr().square();
    let y1y2 = y1_eval.into_fr() * y2_eval.into_fr() * qsign.into_fr();

    let mut x_add_identity = (x3_eval.into_fr() + x2_eval.into_fr() + x1_eval.into_fr())
        * x_diff.square()
        + y1y2.double()
        - (y1_sqr + y2_sqr);
    x_add_identity = x_add_identity * (Fr::ONE - proof.qm_eval.into_fr()) * alpha_base;

    let y1_plus_y3 = y1_eval.into_fr() + y3_eval.into_fr();
    let y_diff = y2_eval.into_fr() * qsign.into_fr() - y1_eval.into_fr();
    let mut y_add_identity =
        y1_plus_y3 * x_diff + ((x3_eval.into_fr() - x1_eval.into_fr()) * y_diff);
    y_add_identity *= (Fr::ONE - proof.qm_eval.into_fr()) * alpha_base * challenges.alpha;

    let mut elliptic_identity = (x_add_identity + y_add_identity) * proof.q_elliptic_eval.into_fr();

    // y^2 = x^3 + ax + b
    // for Grumpkin, a = 0 and b = -17. We use b in a custom gate relation that evaluates elliptic curve arithmetic
    let grumpkin_curve_b_parameter_negated = MontFp!("17");

    let x1_sqr = x1_eval.into_fr().square();
    let x_pow_4 = (y1_sqr + grumpkin_curve_b_parameter_negated) * x1_eval.into_fr();
    let y1_sqr_mul_4 = y1_sqr * MontFp!("4");
    let x1_pow_4_mul_9 = x_pow_4 * MontFp!("9");
    let x1_sqr_mul_3 = x1_sqr * MontFp!("3");
    let mut x_double_identity =
        (x3_eval.into_fr() + x1_eval.into_fr().double()) * y1_sqr_mul_4 - x1_pow_4_mul_9;

    let mut y_double_identity = x1_sqr_mul_3 * (x1_eval.into_fr() - x3_eval.into_fr())
        - y1_eval.into_fr().double() * (y1_eval.into_fr() + y3_eval.into_fr());

    x_double_identity *= alpha_base;
    y_double_identity *= alpha_base * challenges.alpha;
    x_double_identity *= proof.qm_eval.into_fr();
    y_double_identity *= proof.qm_eval.into_fr();

    elliptic_identity += (x_double_identity + y_double_identity) * proof.q_elliptic_eval.into_fr();

    // update alpha
    alpha_base *= challenges.alpha_quad;

    (elliptic_identity, alpha_base)
}

fn compute_aux_non_native_field_evaluation<H: CurveHooks>(proof: &Proof<H>) -> Fr {
    let mut limb_subproduct = proof.w1_eval.into_fr() * proof.w2_omega_eval.into_fr()
        + proof.w1_omega_eval.into_fr() * proof.w2_eval.into_fr();

    let mut non_native_field_gate_2 = proof.w1_eval.into_fr() * proof.w4_eval.into_fr()
        + proof.w2_eval.into_fr() * proof.w3_eval.into_fr()
        - proof.w3_omega_eval.into_fr();

    non_native_field_gate_2 *= LIMB_SIZE;
    non_native_field_gate_2 -= proof.w4_omega_eval.into_fr();
    non_native_field_gate_2 += limb_subproduct;
    non_native_field_gate_2 *= proof.q4_eval.into_fr();
    limb_subproduct *= LIMB_SIZE;
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
    let mut limb_accumulator_1 = proof.w2_omega_eval.into_fr() * SUBLIMB_SHIFT;
    limb_accumulator_1 += proof.w1_omega_eval.into_fr();
    limb_accumulator_1 *= SUBLIMB_SHIFT;
    limb_accumulator_1 += proof.w3_eval.into_fr();
    limb_accumulator_1 *= SUBLIMB_SHIFT;
    limb_accumulator_1 += proof.w2_eval.into_fr();
    limb_accumulator_1 *= SUBLIMB_SHIFT;
    limb_accumulator_1 += proof.w1_eval.into_fr();
    limb_accumulator_1 += -proof.w4_eval.into_fr();
    limb_accumulator_1 *= proof.q4_eval.into_fr();

    let mut limb_accumulator_2 = proof.w3_omega_eval.into_fr() * SUBLIMB_SHIFT;
    limb_accumulator_2 += proof.w2_omega_eval.into_fr();
    limb_accumulator_2 *= SUBLIMB_SHIFT;
    limb_accumulator_2 += proof.w1_omega_eval.into_fr();
    limb_accumulator_2 *= SUBLIMB_SHIFT;
    limb_accumulator_2 += proof.w4_eval.into_fr();
    limb_accumulator_2 *= SUBLIMB_SHIFT;
    limb_accumulator_2 += proof.w3_eval.into_fr();
    limb_accumulator_2 += -proof.w4_omega_eval.into_fr();
    limb_accumulator_2 *= proof.qm_eval.into_fr();

    (limb_accumulator_1 + limb_accumulator_2) * proof.q3_eval.into_fr()
}

fn compute_aux_ram_consistency_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &Challenges,
    index_delta: &Fr,
    partial_record_check: &Fr,
    index_is_monotonically_increasing: &Fr,
) -> Fr {
    let mut next_gate_access_type = proof.w3_omega_eval.into_fr() * challenges.eta;
    next_gate_access_type += proof.w2_omega_eval.into_fr();
    next_gate_access_type *= challenges.eta;
    next_gate_access_type += proof.w1_omega_eval.into_fr();
    next_gate_access_type *= challenges.eta;
    next_gate_access_type = proof.w4_omega_eval.into_fr() - next_gate_access_type;

    let value_delta = proof.w3_omega_eval.into_fr() - proof.w3_eval.into_fr();

    let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
        (Fr::ONE - index_delta) * value_delta * (Fr::ONE - next_gate_access_type);

    // AUX_RAM_CONSISTENCY_EVALUATION

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
    challenges: &Challenges,
    mut alpha_base: Fr,
    index_delta: &Fr,
    aux_evaluations: &AuxiliaryEvaluations,
) -> (Fr, Fr) {
    let timestamp_delta = proof.w2_omega_eval.into_fr() - proof.w2_eval.into_fr();

    let ram_timestamp_check_identity =
        (Fr::ONE - index_delta) * timestamp_delta - proof.w3_eval.into_fr();

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

    auxiliary_identity *= alpha_base;

    // update alpha
    alpha_base *= challenges.alpha_cube;

    (auxiliary_identity, alpha_base)
}

fn compute_auxiliary_widget_evaluation<H: CurveHooks>(
    proof: &Proof<H>,
    challenges: &Challenges,
    alpha_base: Fr,
) -> (Fr, Fr) {
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

    let index_delta = proof.w1_omega_eval.into_fr() - proof.w1_eval.into_fr();
    let record_delta = proof.w4_omega_eval.into_fr() - proof.w4_eval.into_fr();
    let index_is_monotonically_increasing = index_delta * (index_delta - Fr::ONE);

    let adjacent_values_match_if_adjacent_indices_match = record_delta * (Fr::ONE - index_delta);

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

    compute_auxiliary_identity::<H>(
        proof,
        challenges,
        alpha_base,
        &index_delta,
        &aux_evaluations,
    )
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
    let batch_evaluation =
        compute_batch_evaluation_scalar_multiplier::<H>(proof, nu_challenges, quotient_eval);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{VALID_PI, VALID_PROOF, VALID_VK};
    use testhooks::TestHooks;

    #[test]
    fn test_verify() {
        let raw_proof = resources::VALID_PROOF;
        let raw_vk = VALID_VK.as_ref();
        let pubs = resources::VALID_PI;

        assert_eq!(verify::<TestHooks>(&raw_vk, &raw_proof, &pubs).unwrap(), ());
    }

    #[test]
    fn test_verify_invalid_vk() {
        let raw_proof = VALID_PROOF;
        let pubs = VALID_PI;
        let invalid_vk = [0u8; VK_SIZE];

        assert_eq!(
            verify::<TestHooks>(&invalid_vk, &raw_proof, &pubs),
            Err(VerifyError::InvalidVerificationKey)
        );
    }

    #[test]
    fn test_verify_invalid_proof() {
        let invalid_proof = [0u8; PROOF_SIZE];
        let raw_vk = VALID_VK.as_ref();
        let pubs = VALID_PI;

        assert_eq!(
            verify::<TestHooks>(&raw_vk, &invalid_proof, &pubs),
            Err(VerifyError::InvalidProofData)
        );
    }

    #[test]
    fn test_verify_invalid_pub_input() {
        let raw_proof = resources::VALID_PROOF;
        let raw_vk = VALID_VK.as_ref();
        let invalid_pubs = [hex_literal::hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )];

        assert_eq!(
            verify::<TestHooks>(&raw_vk, &raw_proof, &invalid_pubs),
            Err(VerifyError::InvalidInput)
        );
    }

    #[test]
    fn test_verify_invalid_pub_input_length() {
        let raw_proof = resources::VALID_PROOF;
        let raw_vk = VALID_VK.as_ref();
        let invalid_pubs = [
            hex_literal::hex!("000000000000000000000000000000000000000000000000000000000000000a"),
            hex_literal::hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ];

        assert_eq!(
            verify::<TestHooks>(&raw_vk, &raw_proof, &invalid_pubs),
            Err(VerifyError::InvalidInput)
        );
    }
}
