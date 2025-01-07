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

use crate::utils::{IntoFq, IntoFr};
use crate::{Fr, G1, G2, U256};
use ark_bn254::{Fq, Fq2};
use core::convert::TryInto;

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey {
    // pub circuit_type: u32, // Q: What is this for?
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub work_root: Fr,
    pub work_root_inverse: Fr, // TODO: Must somehow enforce that work_root_inverse * work_root == 1 (mod r)
    pub domain_inverse: Fr,
    pub q_1: G1,
    pub q_2: G1,
    pub q_3: G1,
    pub q_4: G1,
    pub q_m: G1,
    pub q_c: G1,
    pub q_arith: G1,
    pub q_aux: G1,
    pub q_elliptic: G1,
    pub q_sort: G1,
    pub sigma_1: G1,
    pub sigma_2: G1,
    pub sigma_3: G1,
    pub sigma_4: G1,
    pub table_1: G1,
    pub table_2: G1,
    pub table_3: G1,
    pub table_4: G1,
    pub table_type: G1,
    pub id_1: G1,
    pub id_2: G1,
    pub id_3: G1,
    pub id_4: G1,
    pub contains_recursive_proof: bool,
    /*
    pub recursive_proof_public_inputs_size: u32,
    pub is_recursive_circuit: bool,
    */
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = &'static str;

    fn try_from(vk_bytes: &[u8]) -> Result<Self, Self::Error> {
        if vk_bytes.len() != 1577 {
            // = 2 * 4 + 49 * 32 + 1
            // TODO: Define a constant
            return Err("Incorrect vk size");
        }

        // TODO: DOUBLE CHECK AGAIN REGARDING THE DESIRED STRUCTURE OF VerificationKeys!!!
        let circuit_size = u32::from_be_bytes(vk_bytes[..4].try_into().unwrap()); // Needs to be a power of 2
        let num_public_inputs = u32::from_be_bytes(vk_bytes[4..8].try_into().unwrap());

        let work_root = read_fr(&vk_bytes[8..40]).unwrap();
        let domain_inverse = read_fr(&vk_bytes[40..72]).unwrap();

        let q_1 = read_g1(&vk_bytes[72..136], false).unwrap();
        let q_2 = read_g1(&vk_bytes[136..200], false).unwrap();
        let q_3 = read_g1(&vk_bytes[200..264], false).unwrap();
        let q_4 = read_g1(&vk_bytes[264..328], false).unwrap();
        let q_m = read_g1(&vk_bytes[328..392], false).unwrap();
        let q_c = read_g1(&vk_bytes[392..456], false).unwrap();
        let q_arith = read_g1(&vk_bytes[456..520], false).unwrap();
        let q_aux = read_g1(&vk_bytes[520..584], false).unwrap();
        let q_elliptic = read_g1(&vk_bytes[584..648], false).unwrap();
        let q_sort = read_g1(&vk_bytes[648..712], false).unwrap();
        let sigma_1 = read_g1(&vk_bytes[712..776], false).unwrap();
        let sigma_2 = read_g1(&vk_bytes[776..840], false).unwrap();
        let sigma_3 = read_g1(&vk_bytes[840..904], false).unwrap();
        let sigma_4 = read_g1(&vk_bytes[904..968], false).unwrap();
        let table_1 = read_g1(&vk_bytes[968..1032], false).unwrap();
        let table_2 = read_g1(&vk_bytes[1032..1096], false).unwrap();
        let table_3 = read_g1(&vk_bytes[1096..1160], false).unwrap();
        let table_4 = read_g1(&vk_bytes[1160..1224], false).unwrap();
        let table_type = read_g1(&vk_bytes[1224..1288], false).unwrap();
        let id_1 = read_g1(&vk_bytes[1288..1352], false).unwrap();
        let id_2 = read_g1(&vk_bytes[1352..1416], false).unwrap();
        let id_3 = read_g1(&vk_bytes[1416..1480], false).unwrap();
        let id_4 = read_g1(&vk_bytes[1480..1544], false).unwrap();

        let work_root_inverse = read_fr(&vk_bytes[1544..1576]).unwrap();

        // TODO: Check if work_root and work_root inverse are indeed inverses.

        let contains_recursive_proof = vk_bytes[1576] > 0; // 0000000000000000000000000000000000000000000000000000000000000000

        Ok(VerificationKey {
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
pub(crate) fn read_g1(data: &[u8], reverse: bool) -> Result<G1, String> {
    // VerificationKeyError
    if data.len() != 64 {
        return Err("Input slice must be exactly 64 bytes.".to_string());
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

    Ok(G1::new(x, y))
}

// Parse point on G2
pub(crate) fn read_g2(data: &[u8]) -> Result<G2, String> {
    // VerificationKeyError
    if data.len() != 128 {
        return Err("Input slice must be exactly 128 bytes.".to_string());
    }

    let x_c0 = read_fq(&data[0..32]).unwrap();
    let x_c1 = read_fq(&data[32..64]).unwrap();
    let y_c0 = read_fq(&data[64..96]).unwrap();
    let y_c1 = read_fq(&data[96..128]).unwrap();

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2::new(x, y))
}

pub(crate) fn read_fq(data: &[u8]) -> Result<Fq, String> {
    // VerificationKeyError
    if data.len() != 32 {
        return Err("Input slice must be exactly 32 bytes.".to_string());
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

pub(crate) fn read_fr(data: &[u8]) -> Result<Fr, String> {
    // VerificationKeyError
    if data.len() != 32 {
        return Err("Input slice must be exactly 32 bytes.".to_string());
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
