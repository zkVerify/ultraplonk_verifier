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

use crate::{
    errors::{FieldError, GroupError},
    utils::{read_fq_util, read_g1_util},
    Fq, G1, PROOF_SIZE,
};
use ark_bn254_ext::CurveHooks;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum ProofError {
    #[snafu(display("Buffer size is incorrect"))]
    IncorrectBufferSize,

    #[snafu(display("Point for field is not on curve"))]
    PointNotOnCurve,

    #[snafu(display("Point is not in the correct subgroup"))]
    PointNotInCorrectSubgroup,

    #[snafu(display("Value is not a member of Fq"))]
    NotMember,

    #[snafu(display("Other error"))]
    OtherError,
}

#[derive(Debug)]
pub struct Proof<H: CurveHooks> {
    pub w1: G1<H>,
    pub w2: G1<H>,
    pub w3: G1<H>,
    pub w4: G1<H>,
    pub s: G1<H>,
    pub z: G1<H>,
    pub z_lookup: G1<H>,
    pub t1: G1<H>,
    pub t2: G1<H>,
    pub t3: G1<H>,
    pub t4: G1<H>,
    pub w1_eval: Fq,
    pub w2_eval: Fq,
    pub w3_eval: Fq,
    pub w4_eval: Fq,
    pub s_eval: Fq,
    pub z_eval: Fq,
    pub z_lookup_eval: Fq,
    pub q1_eval: Fq,
    pub q2_eval: Fq,
    pub q3_eval: Fq,
    pub q4_eval: Fq,
    pub qm_eval: Fq,
    pub qc_eval: Fq,
    pub q_arith_eval: Fq,
    pub q_sort_eval: Fq,
    pub q_elliptic_eval: Fq,
    pub q_aux_eval: Fq,
    pub sigma1_eval: Fq,
    pub sigma2_eval: Fq,
    pub sigma3_eval: Fq,
    pub sigma4_eval: Fq,
    pub table1_eval: Fq,
    pub table2_eval: Fq,
    pub table3_eval: Fq,
    pub table4_eval: Fq,
    pub table_type_eval: Fq,
    pub id1_eval: Fq,
    pub id2_eval: Fq,
    pub id3_eval: Fq,
    pub id4_eval: Fq,
    pub w1_omega_eval: Fq,
    pub w2_omega_eval: Fq,
    pub w3_omega_eval: Fq,
    pub w4_omega_eval: Fq,
    pub s_omega_eval: Fq,
    pub z_omega_eval: Fq,
    pub z_lookup_omega_eval: Fq,
    pub table1_omega_eval: Fq,
    pub table2_omega_eval: Fq,
    pub table3_omega_eval: Fq,
    pub table4_omega_eval: Fq,
    pub pi_z: G1<H>,
    pub pi_z_omega: G1<H>,
}

fn read_proof_g1<H: CurveHooks>(data: &[u8], offset: &mut usize) -> Result<G1<H>, ProofError> {
    read_g1_util::<H>(&data[*offset..*offset + 64], true)
        .map_err(|e| match e {
            GroupError::NotOnCurve => ProofError::PointNotOnCurve,
            GroupError::NotInSubgroup => ProofError::PointNotInCorrectSubgroup,
            GroupError::InvalidSliceLength => ProofError::IncorrectBufferSize,
        })
        .inspect(|_| {
            *offset += 64;
        })
}

fn read_proof_fq(data: &[u8], offset: &mut usize) -> Result<Fq, ProofError> {
    read_fq_util(&data[*offset..*offset + 32])
        .map_err(|e| match e {
            FieldError::NotMember => ProofError::NotMember,
            FieldError::InvalidSliceLength => ProofError::IncorrectBufferSize,
            _ => ProofError::OtherError,
        })
        .inspect(|_| {
            *offset += 32;
        })
}

impl<H: CurveHooks> TryFrom<&[u8]> for Proof<H> {
    type Error = ProofError;

    fn try_from(proof: &[u8]) -> Result<Self, ProofError> {
        if proof.len() != PROOF_SIZE {
            return Err(ProofError::IncorrectBufferSize);
        }

        let mut offset = 0;

        let w1 = read_proof_g1::<H>(proof, &mut offset)?;
        let w2 = read_proof_g1::<H>(proof, &mut offset)?;
        let w3 = read_proof_g1::<H>(proof, &mut offset)?;
        let w4 = read_proof_g1::<H>(proof, &mut offset)?;

        let s = read_proof_g1::<H>(proof, &mut offset)?;
        let z = read_proof_g1::<H>(proof, &mut offset)?;
        let z_lookup = read_proof_g1::<H>(proof, &mut offset)?;

        let t1 = read_proof_g1::<H>(proof, &mut offset)?;
        let t2 = read_proof_g1::<H>(proof, &mut offset)?;
        let t3 = read_proof_g1::<H>(proof, &mut offset)?;
        let t4 = read_proof_g1::<H>(proof, &mut offset)?;

        let w1_eval = read_proof_fq(proof, &mut offset)?;
        let w2_eval = read_proof_fq(proof, &mut offset)?;
        let w3_eval = read_proof_fq(proof, &mut offset)?;
        let w4_eval = read_proof_fq(proof, &mut offset)?;

        let s_eval = read_proof_fq(proof, &mut offset)?;
        let z_eval = read_proof_fq(proof, &mut offset)?;
        let z_lookup_eval = read_proof_fq(proof, &mut offset)?;

        let q1_eval = read_proof_fq(proof, &mut offset)?;
        let q2_eval = read_proof_fq(proof, &mut offset)?;
        let q3_eval = read_proof_fq(proof, &mut offset)?;
        let q4_eval = read_proof_fq(proof, &mut offset)?;
        let qm_eval = read_proof_fq(proof, &mut offset)?;
        let qc_eval = read_proof_fq(proof, &mut offset)?;
        let q_arith_eval = read_proof_fq(proof, &mut offset)?;
        let q_sort_eval = read_proof_fq(proof, &mut offset)?;
        let q_elliptic_eval = read_proof_fq(proof, &mut offset)?;
        let q_aux_eval = read_proof_fq(proof, &mut offset)?;

        let sigma1_eval = read_proof_fq(proof, &mut offset)?;
        let sigma2_eval = read_proof_fq(proof, &mut offset)?;
        let sigma3_eval = read_proof_fq(proof, &mut offset)?;
        let sigma4_eval = read_proof_fq(proof, &mut offset)?;

        let table1_eval = read_proof_fq(proof, &mut offset)?;
        let table2_eval = read_proof_fq(proof, &mut offset)?;
        let table3_eval = read_proof_fq(proof, &mut offset)?;
        let table4_eval = read_proof_fq(proof, &mut offset)?;
        let table_type_eval = read_proof_fq(proof, &mut offset)?;

        let id1_eval = read_proof_fq(proof, &mut offset)?;
        let id2_eval = read_proof_fq(proof, &mut offset)?;
        let id3_eval = read_proof_fq(proof, &mut offset)?;
        let id4_eval = read_proof_fq(proof, &mut offset)?;

        let w1_omega_eval = read_proof_fq(proof, &mut offset)?;
        let w2_omega_eval = read_proof_fq(proof, &mut offset)?;
        let w3_omega_eval = read_proof_fq(proof, &mut offset)?;
        let w4_omega_eval = read_proof_fq(proof, &mut offset)?;

        let s_omega_eval = read_proof_fq(proof, &mut offset)?;
        let z_omega_eval = read_proof_fq(proof, &mut offset)?;
        let z_lookup_omega_eval = read_proof_fq(proof, &mut offset)?;

        let table1_omega_eval = read_proof_fq(proof, &mut offset)?;
        let table2_omega_eval = read_proof_fq(proof, &mut offset)?;
        let table3_omega_eval = read_proof_fq(proof, &mut offset)?;
        let table4_omega_eval = read_proof_fq(proof, &mut offset)?;

        let pi_z = read_proof_g1::<H>(proof, &mut offset)?;
        let pi_z_omega = read_proof_g1::<H>(proof, &mut offset)?;

        Ok(Proof::<H> {
            w1,
            w2,
            w3,
            w4,
            s,
            z,
            z_lookup,
            t1,
            t2,
            t3,
            t4,
            w1_eval,
            w2_eval,
            w3_eval,
            w4_eval,
            s_eval,
            z_eval,
            z_lookup_eval,
            q1_eval,
            q2_eval,
            q3_eval,
            q4_eval,
            qm_eval,
            qc_eval,
            q_arith_eval,
            q_sort_eval,
            q_elliptic_eval,
            q_aux_eval,
            sigma1_eval,
            sigma2_eval,
            sigma3_eval,
            sigma4_eval,
            table1_eval,
            table2_eval,
            table3_eval,
            table4_eval,
            table_type_eval,
            id1_eval,
            id2_eval,
            id3_eval,
            id4_eval,
            w1_omega_eval,
            w2_omega_eval,
            w3_omega_eval,
            w4_omega_eval,
            s_omega_eval,
            z_omega_eval,
            z_lookup_omega_eval,
            table1_omega_eval,
            table2_omega_eval,
            table3_omega_eval,
            table4_omega_eval,
            pi_z,
            pi_z_omega,
        })
    }
}
