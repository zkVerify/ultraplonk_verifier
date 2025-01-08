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

use crate::errors::VerifyError;
use crate::utils::{IntoFq, IntoFr};
use crate::{Fq, Fq2, VK_SIZE};
use crate::{Fr, G1, G2, U256};
use ark_bn254_ext::CurveHooks;
use core::convert::TryFrom;
use core::convert::TryInto;

use core::result::Result;
use core::result::Result::Err;
use core::result::Result::Ok;

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    // pub circuit_type: u32, // Q: What is this for?
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub work_root: Fr,
    pub work_root_inverse: Fr, // TODO: Must somehow enforce that work_root_inverse * work_root == 1 (mod r)
    pub domain_inverse: Fr,
    pub q_1: G1<H>,
    pub q_2: G1<H>,
    pub q_3: G1<H>,
    pub q_4: G1<H>,
    pub q_m: G1<H>,
    pub q_c: G1<H>,
    pub q_arith: G1<H>,
    pub q_aux: G1<H>,
    pub q_elliptic: G1<H>,
    pub q_sort: G1<H>,
    pub sigma_1: G1<H>,
    pub sigma_2: G1<H>,
    pub sigma_3: G1<H>,
    pub sigma_4: G1<H>,
    pub table_1: G1<H>,
    pub table_2: G1<H>,
    pub table_3: G1<H>,
    pub table_4: G1<H>,
    pub table_type: G1<H>,
    pub id_1: G1<H>,
    pub id_2: G1<H>,
    pub id_3: G1<H>,
    pub id_4: G1<H>,
    pub contains_recursive_proof: bool,
    /*
    pub recursive_proof_public_inputs_size: u32,
    pub is_recursive_circuit: bool,
    */
}

impl<H: CurveHooks> TryFrom<&[u8]> for VerificationKey<H> {
    type Error = VerifyError; // &'static str;

    fn try_from(vk_bytes: &[u8]) -> Result<Self, Self::Error> {
        if vk_bytes.len() != VK_SIZE {
            // return Err("Incorrect vk size");
            return Err(VerifyError::InvalidVerificationKey);
        }

        // TODO: DOUBLE CHECK AGAIN REGARDING THE DESIRED STRUCTURE OF VerificationKeys!!!
        let circuit_size = u32::from_be_bytes(vk_bytes[..4].try_into().unwrap()); // Needs to be a power of 2
        let num_public_inputs = u32::from_be_bytes(vk_bytes[4..8].try_into().unwrap());

        let work_root =
            read_fr(&vk_bytes[8..40]).map_err(|_| VerifyError::InvalidVerificationKey)?;
        let domain_inverse =
            read_fr(&vk_bytes[40..72]).map_err(|_| VerifyError::InvalidVerificationKey)?;

        let q_1 = read_g1::<H>(&vk_bytes[72..136], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_2 = read_g1::<H>(&vk_bytes[136..200], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_3 = read_g1::<H>(&vk_bytes[200..264], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_4 = read_g1::<H>(&vk_bytes[264..328], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_m = read_g1::<H>(&vk_bytes[328..392], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_c = read_g1::<H>(&vk_bytes[392..456], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_arith = read_g1::<H>(&vk_bytes[456..520], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_aux = read_g1::<H>(&vk_bytes[520..584], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_elliptic = read_g1::<H>(&vk_bytes[584..648], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let q_sort = read_g1::<H>(&vk_bytes[648..712], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let sigma_1 = read_g1::<H>(&vk_bytes[712..776], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let sigma_2 = read_g1::<H>(&vk_bytes[776..840], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let sigma_3 = read_g1::<H>(&vk_bytes[840..904], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let sigma_4 = read_g1::<H>(&vk_bytes[904..968], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let table_1 = read_g1::<H>(&vk_bytes[968..1032], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let table_2 = read_g1::<H>(&vk_bytes[1032..1096], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let table_3 = read_g1::<H>(&vk_bytes[1096..1160], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let table_4 = read_g1::<H>(&vk_bytes[1160..1224], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let table_type = read_g1::<H>(&vk_bytes[1224..1288], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let id_1 = read_g1::<H>(&vk_bytes[1288..1352], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let id_2 = read_g1::<H>(&vk_bytes[1352..1416], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let id_3 = read_g1::<H>(&vk_bytes[1416..1480], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let id_4 = read_g1::<H>(&vk_bytes[1480..1544], false)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;

        let work_root_inverse =
            read_fr(&vk_bytes[1544..1576]).map_err(|_| VerifyError::InvalidVerificationKey)?;

        // TODO: Check if work_root and work_root inverse are indeed inverses.

        let contains_recursive_proof = vk_bytes[1576] > 0;

        Ok(VerificationKey::<H> {
            circuit_size,
            num_public_inputs,
            work_root,
            work_root_inverse,
            domain_inverse,
            q_1,
            q_2,
            q_3,
            q_4,
            q_m,
            q_c,
            q_arith,
            q_aux,
            q_elliptic,
            q_sort,
            sigma_1,
            sigma_2,
            sigma_3,
            sigma_4,
            table_1,
            table_2,
            table_3,
            table_4,
            table_type,
            id_1,
            id_2,
            id_3,
            id_4,
            contains_recursive_proof,
        })
    }
}

// Parse point on G1
pub(crate) fn read_g1<H: CurveHooks>(data: &[u8], reverse: bool) -> Result<G1<H>, ()> {
    // VerificationKeyError
    if data.len() != 64 {
        return Err(());
    }

    let x: Fq;
    let y: Fq;

    if reverse {
        y = read_fq(&data[0..32]).unwrap();
        x = read_fq(&data[32..64]).unwrap();
    } else {
        x = read_fq(&data[0..32]).unwrap();
        y = read_fq(&data[32..64]).unwrap();
    }

    Ok(G1::<H>::new(x, y))
}

// Parse point on G2
pub(crate) fn read_g2<H: CurveHooks>(data: &[u8]) -> Result<G2<H>, ()> {
    // VerificationKeyError
    if data.len() != 128 {
        return Err(());
    }

    let x_c0 = read_fq(&data[0..32]).unwrap();
    let x_c1 = read_fq(&data[32..64]).unwrap();
    let y_c0 = read_fq(&data[64..96]).unwrap();
    let y_c1 = read_fq(&data[96..128]).unwrap();

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2::<H>::new(x, y))
}

pub(crate) fn read_fq(data: &[u8]) -> Result<Fq, ()> {
    // VerificationKeyError
    if data.len() != 32 {
        return Err(());
    }

    // Convert bytes to limbs manually
    let mut limbs = [0u64; 4];
    for (i, chunk) in data.chunks(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    // Create a U256
    let bigint = U256::new(limbs);

    // Try to construct an Fq element
    Ok(bigint.into_fq())
}

pub(crate) fn read_fr(data: &[u8]) -> Result<Fr, ()> {
    // VerificationKeyError
    if data.len() != 32 {
        return Err(());
    }

    // Convert bytes to limbs manually
    let mut limbs = [0u64; 4];
    for (i, chunk) in data.chunks(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    // Create a U256
    let bigint = U256::new(limbs);

    // Try to construct an Fr element
    Ok(bigint.into_fr())
}
