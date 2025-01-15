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

#![allow(non_camel_case_types)]

use crate::{
    errors::{FieldError, GroupError},
    utils::{read_fq_util, read_g1_util, IntoBytes},
    Fq2, Fr, G1, G2, VK_SIZE,
};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use ark_bn254_ext::CurveHooks;
use ark_ff::{FftField, Field};
use snafu::Snafu;

#[allow(unused)]
#[derive(Debug, Snafu)]
pub enum VerificationKeyError {
    #[snafu(display("Buffer too short"))]
    BufferTooShort,

    #[snafu(display("Buffer size is incorrect"))]
    IncorrectBufferSize,

    #[snafu(display("Invalid field '{}': {:?}", field, error))]
    InvalidField {
        field: &'static str,
        error: FieldError,
    },

    #[snafu(display("Point for field '{}' is not on curve", field))]
    PointNotOnCurve { field: &'static str },

    #[snafu(display("Point for field '{}' is not in the correct subgroup", field))]
    PointNotInCorrectSubgroup { field: &'static str },

    #[snafu(display("Invalid value '{}'", value))]
    InvalidValue { value: String },

    #[snafu(display("Non-invertible element {}", value))]
    NonInvertibleElement { value: String },

    #[snafu(display("No roots of unity for {}", value))]
    NoRootsOfUnity { value: String },

    #[snafu(display("Invalid circuit type, expected 2"))]
    InvalidCircuitType,

    #[snafu(display("Invalid commitment field: {:?}", value))]
    InvalidCommitmentField { value: String },

    #[snafu(display("Invalid commitments number, expected 23"))]
    InvalidCommitmentsNumber,

    #[snafu(display("Invalid commitment key at offset {:?}", offset))]
    InvalidCommitmentKey { offset: usize },

    #[snafu(display("Unexpected commitment key: {:?}, expected {:?}", key, expected))]
    UnexpectedCommitmentKey { key: String, expected: String },

    #[snafu(display("Recursion is not supported"))]
    RecursionNotSupported,
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum CommitmentField {
    Q_1,
    Q_2,
    Q_3,
    Q_4,
    Q_M,
    Q_C,
    Q_ARITHMETIC,
    Q_SORT,
    Q_ELLIPTIC,
    Q_AUX,
    SIGMA_1,
    SIGMA_2,
    SIGMA_3,
    SIGMA_4,
    TABLE_1,
    TABLE_2,
    TABLE_3,
    TABLE_4,
    TABLE_TYPE,
    ID_1,
    ID_2,
    ID_3,
    ID_4,
}

#[allow(unused)]
impl CommitmentField {
    pub fn str(&self) -> &'static str {
        match self {
            CommitmentField::Q_1 => "Q_1",
            CommitmentField::Q_2 => "Q_2",
            CommitmentField::Q_3 => "Q_3",
            CommitmentField::Q_4 => "Q_4",
            CommitmentField::Q_M => "Q_M",
            CommitmentField::Q_C => "Q_C",
            CommitmentField::Q_ARITHMETIC => "Q_ARITHMETIC",
            CommitmentField::Q_SORT => "Q_SORT",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC",
            CommitmentField::Q_AUX => "Q_AUX",
            CommitmentField::SIGMA_1 => "SIGMA_1",
            CommitmentField::SIGMA_2 => "SIGMA_2",
            CommitmentField::SIGMA_3 => "SIGMA_3",
            CommitmentField::SIGMA_4 => "SIGMA_4",
            CommitmentField::TABLE_1 => "TABLE_1",
            CommitmentField::TABLE_2 => "TABLE_2",
            CommitmentField::TABLE_3 => "TABLE_3",
            CommitmentField::TABLE_4 => "TABLE_4",
            CommitmentField::TABLE_TYPE => "TABLE_TYPE",
            CommitmentField::ID_1 => "ID_1",
            CommitmentField::ID_2 => "ID_2",
            CommitmentField::ID_3 => "ID_3",
            CommitmentField::ID_4 => "ID_4",
        }
    }

    fn x_str(&self) -> &'static str {
        match self {
            CommitmentField::Q_1 => "Q_1.x",
            CommitmentField::Q_2 => "Q_2.x",
            CommitmentField::Q_3 => "Q_3.x",
            CommitmentField::Q_4 => "Q_4.x",
            CommitmentField::Q_M => "Q_M.x",
            CommitmentField::Q_C => "Q_C.x",
            CommitmentField::Q_ARITHMETIC => "Q_ARITHMETIC.x",
            CommitmentField::Q_SORT => "Q_SORT.x",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC.x",
            CommitmentField::Q_AUX => "Q_AUX.x",
            CommitmentField::SIGMA_1 => "SIGMA_1.x",
            CommitmentField::SIGMA_2 => "SIGMA_2.x",
            CommitmentField::SIGMA_3 => "SIGMA_3.x",
            CommitmentField::SIGMA_4 => "SIGMA_4.x",
            CommitmentField::TABLE_1 => "TABLE_1.x",
            CommitmentField::TABLE_2 => "TABLE_2.x",
            CommitmentField::TABLE_3 => "TABLE_3.x",
            CommitmentField::TABLE_4 => "TABLE_4.x",
            CommitmentField::TABLE_TYPE => "TABLE_TYPE.x",
            CommitmentField::ID_1 => "ID_1.x",
            CommitmentField::ID_2 => "ID_2.x",
            CommitmentField::ID_3 => "ID_3.x",
            CommitmentField::ID_4 => "ID_4.x",
        }
    }

    fn y_str(&self) -> &'static str {
        match self {
            CommitmentField::Q_1 => "Q_1.y",
            CommitmentField::Q_2 => "Q_2.y",
            CommitmentField::Q_3 => "Q_3.y",
            CommitmentField::Q_4 => "Q_4.y",
            CommitmentField::Q_M => "Q_M.y",
            CommitmentField::Q_C => "Q_C.y",
            CommitmentField::Q_ARITHMETIC => "Q_ARITHMETIC.y",
            CommitmentField::Q_SORT => "Q_SORT.y",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC.y",
            CommitmentField::Q_AUX => "Q_AUX.y",
            CommitmentField::SIGMA_1 => "SIGMA_1.y",
            CommitmentField::SIGMA_2 => "SIGMA_2.y",
            CommitmentField::SIGMA_3 => "SIGMA_3.y",
            CommitmentField::SIGMA_4 => "SIGMA_4.y",
            CommitmentField::TABLE_1 => "TABLE_1.y",
            CommitmentField::TABLE_2 => "TABLE_2.y",
            CommitmentField::TABLE_3 => "TABLE_3.y",
            CommitmentField::TABLE_4 => "TABLE_4.y",
            CommitmentField::TABLE_TYPE => "TABLE_TYPE.y",
            CommitmentField::ID_1 => "ID_1.y",
            CommitmentField::ID_2 => "ID_2.y",
            CommitmentField::ID_3 => "ID_3.y",
            CommitmentField::ID_4 => "ID_4.y",
        }
    }

    fn try_from(value: &str) -> Result<Self, String> {
        match value {
            "Q_1" => Ok(CommitmentField::Q_1),
            "Q_2" => Ok(CommitmentField::Q_2),
            "Q_3" => Ok(CommitmentField::Q_3),
            "Q_4" => Ok(CommitmentField::Q_4),
            "Q_M" => Ok(CommitmentField::Q_M),
            "Q_C" => Ok(CommitmentField::Q_C),
            "Q_ARITHMETIC" => Ok(CommitmentField::Q_ARITHMETIC),
            "Q_SORT" => Ok(CommitmentField::Q_SORT),
            "Q_ELLIPTIC" => Ok(CommitmentField::Q_ELLIPTIC),
            "Q_AUX" => Ok(CommitmentField::Q_AUX),
            "SIGMA_1" => Ok(CommitmentField::SIGMA_1),
            "SIGMA_2" => Ok(CommitmentField::SIGMA_2),
            "SIGMA_3" => Ok(CommitmentField::SIGMA_3),
            "SIGMA_4" => Ok(CommitmentField::SIGMA_4),
            "TABLE_1" => Ok(CommitmentField::TABLE_1),
            "TABLE_2" => Ok(CommitmentField::TABLE_2),
            "TABLE_3" => Ok(CommitmentField::TABLE_3),
            "TABLE_4" => Ok(CommitmentField::TABLE_4),
            "TABLE_TYPE" => Ok(CommitmentField::TABLE_TYPE),
            "ID_1" => Ok(CommitmentField::ID_1),
            "ID_2" => Ok(CommitmentField::ID_2),
            "ID_3" => Ok(CommitmentField::ID_3),
            "ID_4" => Ok(CommitmentField::ID_4),
            _ => Err(format!("Invalid commitment field '{}'", value)),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    pub circuit_type: u32,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub work_root: Fr,
    pub work_root_inverse: Fr,
    pub domain_inverse: Fr,
    pub q_1: G1<H>,
    pub q_2: G1<H>,
    pub q_3: G1<H>,
    pub q_4: G1<H>,
    pub q_m: G1<H>,
    pub q_c: G1<H>,
    pub q_arithmetic: G1<H>,
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
    pub recursive_proof_indices: u32,
}

#[allow(unused)]
impl<H: CurveHooks> VerificationKey<H> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&self.circuit_type.to_be_bytes());

        data.extend_from_slice(&self.circuit_size.to_be_bytes());
        data.extend_from_slice(&self.num_public_inputs.to_be_bytes());

        // Commitments size
        data.extend_from_slice(&23u32.to_be_bytes());

        write_g1(&CommitmentField::ID_1, self.id_1, &mut data);
        write_g1(&CommitmentField::ID_2, self.id_2, &mut data);
        write_g1(&CommitmentField::ID_3, self.id_3, &mut data);
        write_g1(&CommitmentField::ID_4, self.id_4, &mut data);
        write_g1(&CommitmentField::Q_1, self.q_1, &mut data);
        write_g1(&CommitmentField::Q_2, self.q_2, &mut data);
        write_g1(&CommitmentField::Q_3, self.q_3, &mut data);
        write_g1(&CommitmentField::Q_4, self.q_4, &mut data);
        write_g1(&CommitmentField::Q_ARITHMETIC, self.q_arithmetic, &mut data);
        write_g1(&CommitmentField::Q_AUX, self.q_aux, &mut data);
        write_g1(&CommitmentField::Q_C, self.q_c, &mut data);
        write_g1(&CommitmentField::Q_ELLIPTIC, self.q_elliptic, &mut data);
        write_g1(&CommitmentField::Q_M, self.q_m, &mut data);
        write_g1(&CommitmentField::Q_SORT, self.q_sort, &mut data);
        write_g1(&CommitmentField::SIGMA_1, self.sigma_1, &mut data);
        write_g1(&CommitmentField::SIGMA_2, self.sigma_2, &mut data);
        write_g1(&CommitmentField::SIGMA_3, self.sigma_3, &mut data);
        write_g1(&CommitmentField::SIGMA_4, self.sigma_4, &mut data);
        write_g1(&CommitmentField::TABLE_1, self.table_1, &mut data);
        write_g1(&CommitmentField::TABLE_2, self.table_2, &mut data);
        write_g1(&CommitmentField::TABLE_3, self.table_3, &mut data);
        write_g1(&CommitmentField::TABLE_4, self.table_4, &mut data);
        write_g1(&CommitmentField::TABLE_TYPE, self.table_type, &mut data);

        // Contains recursive proof
        data.push(if self.contains_recursive_proof { 1 } else { 0 });
        data.extend_from_slice(&0u32.to_be_bytes());

        data
    }
}

impl<H: CurveHooks> TryFrom<&[u8]> for VerificationKey<H> {
    type Error = VerificationKeyError;

    fn try_from(raw_vk: &[u8]) -> Result<Self, Self::Error> {
        if raw_vk.len() < VK_SIZE {
            return Err(VerificationKeyError::BufferTooShort);
        }

        let mut offset = 0;

        let circuit_type = read_u32_and_check(
            raw_vk,
            &mut offset,
            2,
            VerificationKeyError::InvalidCircuitType,
        )?;
        let circuit_size = read_u32(raw_vk, &mut offset); // Needs to be a power of 2
        let num_public_inputs = read_u32(raw_vk, &mut offset);

        read_u32_and_check(
            raw_vk,
            &mut offset,
            23,
            VerificationKeyError::InvalidCommitmentsNumber,
        )?;

        let id_1 = read_commitment(&CommitmentField::ID_1, raw_vk, &mut offset)?;
        let id_2 = read_commitment(&CommitmentField::ID_2, raw_vk, &mut offset)?;
        let id_3 = read_commitment(&CommitmentField::ID_3, raw_vk, &mut offset)?;
        let id_4 = read_commitment(&CommitmentField::ID_4, raw_vk, &mut offset)?;
        let q_1 = read_commitment(&CommitmentField::Q_1, raw_vk, &mut offset)?;
        let q_2 = read_commitment(&CommitmentField::Q_2, raw_vk, &mut offset)?;
        let q_3 = read_commitment(&CommitmentField::Q_3, raw_vk, &mut offset)?;
        let q_4 = read_commitment(&CommitmentField::Q_4, raw_vk, &mut offset)?;
        let q_arithmetic = read_commitment(&CommitmentField::Q_ARITHMETIC, raw_vk, &mut offset)?;
        let q_aux = read_commitment(&CommitmentField::Q_AUX, raw_vk, &mut offset)?;
        let q_c = read_commitment(&CommitmentField::Q_C, raw_vk, &mut offset)?;
        let q_elliptic = read_commitment(&CommitmentField::Q_ELLIPTIC, raw_vk, &mut offset)?;
        let q_m = read_commitment(&CommitmentField::Q_M, raw_vk, &mut offset)?;
        let q_sort = read_commitment(&CommitmentField::Q_SORT, raw_vk, &mut offset)?;
        let sigma_1 = read_commitment(&CommitmentField::SIGMA_1, raw_vk, &mut offset)?;
        let sigma_2 = read_commitment(&CommitmentField::SIGMA_2, raw_vk, &mut offset)?;
        let sigma_3 = read_commitment(&CommitmentField::SIGMA_3, raw_vk, &mut offset)?;
        let sigma_4 = read_commitment(&CommitmentField::SIGMA_4, raw_vk, &mut offset)?;
        let table_1 = read_commitment(&CommitmentField::TABLE_1, raw_vk, &mut offset)?;
        let table_2 = read_commitment(&CommitmentField::TABLE_2, raw_vk, &mut offset)?;
        let table_3 = read_commitment(&CommitmentField::TABLE_3, raw_vk, &mut offset)?;
        let table_4 = read_commitment(&CommitmentField::TABLE_4, raw_vk, &mut offset)?;
        let table_type = read_commitment(&CommitmentField::TABLE_TYPE, raw_vk, &mut offset)?;

        let contains_recursive_proof = read_bool_and_check(
            raw_vk,
            &mut offset,
            false,
            VerificationKeyError::RecursionNotSupported,
        )?;

        let recursive_proof_indices = read_u32_and_check(
            raw_vk,
            &mut offset,
            0,
            VerificationKeyError::RecursionNotSupported,
        )?;

        // NOTE: The following three fields can actually be computed just from the circuit_size (and r)
        // Hence, one optimization could be to create a lookup table for each value of 2^i, i = 0, 1, ...
        // This should prevent having to do inversions everytime we call verify().
        let domain_inverse = Fr::inverse(&Fr::from(circuit_size)).ok_or(
            VerificationKeyError::NonInvertibleElement {
                value: circuit_size.to_string(),
            },
        )?;
        let work_root = Fr::get_root_of_unity(circuit_size.into()).ok_or(
            VerificationKeyError::NoRootsOfUnity {
                value: circuit_size.to_string(),
            },
        )?;
        let work_root_inverse =
            Fr::inverse(&work_root).ok_or(VerificationKeyError::NonInvertibleElement {
                value: work_root.to_string(),
            })?;

        Ok(VerificationKey::<H> {
            circuit_type,
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
            q_arithmetic,
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
            recursive_proof_indices,
        })
    }
}

fn read_u32_and_check(
    data: &[u8],
    offset: &mut usize,
    val: u32,
    raise: VerificationKeyError,
) -> Result<u32, VerificationKeyError> {
    let value = read_u32(data, offset);
    if value != val {
        return Err(raise);
    }
    Ok(value)
}

fn read_u32(data: &[u8], offset: &mut usize) -> u32 {
    let value = u32::from_be_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    value
}

fn read_bool_and_check(
    data: &[u8],
    offset: &mut usize,
    val: bool,
    raise: VerificationKeyError,
) -> Result<bool, VerificationKeyError> {
    let value = read_bool(data, offset);
    if value != val {
        return Err(raise);
    }
    Ok(value)
}

fn read_bool(data: &[u8], offset: &mut usize) -> bool {
    let value = data[*offset] == 1;
    *offset += 1;
    value
}

fn read_commitment<H: CurveHooks>(
    field: &CommitmentField,
    data: &[u8],
    offset: &mut usize,
) -> Result<G1<H>, VerificationKeyError> {
    let expected = field.str();
    let key_size = read_u32(data, offset) as usize;

    if expected.len() != key_size {
        return Err(VerificationKeyError::InvalidCommitmentKey { offset: *offset });
    }

    let key = String::from_utf8(data[*offset..*offset + key_size].to_vec())
        .inspect(|_| {
            *offset += key_size;
        })
        .map_err(|_| VerificationKeyError::InvalidCommitmentKey { offset: *offset })?;

    let field = CommitmentField::try_from(&key)
        .map_err(|_| VerificationKeyError::InvalidCommitmentField { value: key.clone() })?;

    if key != expected {
        return Err(VerificationKeyError::UnexpectedCommitmentKey {
            key,
            expected: expected.to_string(),
        });
    }

    read_g1::<H>(&field, &data[*offset..*offset + 64]).inspect(|_| {
        *offset += 64;
    })
}

pub(crate) fn read_g1<H: CurveHooks>(
    field: &CommitmentField,
    data: &[u8],
) -> Result<G1<H>, VerificationKeyError> {
    read_g1_util::<H>(data, false).map_err(|e| match e {
        GroupError::NotOnCurve => VerificationKeyError::PointNotOnCurve { field: field.str() },
        GroupError::NotInSubgroup => {
            VerificationKeyError::PointNotInCorrectSubgroup { field: field.str() }
        }
        GroupError::InvalidSliceLength => VerificationKeyError::IncorrectBufferSize,
    })
}

#[allow(unused)]
fn write_g1<H: CurveHooks>(field: &CommitmentField, g1: G1<H>, data: &mut Vec<u8>) {
    // Helper to convert a field to bytes
    let field_to_bytes = |field: &CommitmentField| -> Vec<u8> {
        let mut bytes = Vec::new();
        let field_str = field.str();
        bytes.extend_from_slice(&(field_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field_str.as_bytes());
        bytes
    };

    // Helper to convert a G1 point to bytes
    let g1_to_bytes = |g1: G1<H>| -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&g1.x.into_bytes());
        bytes.extend_from_slice(&g1.y.into_bytes());
        bytes
    };

    // Use the helpers to append bytes to the data vector
    data.extend_from_slice(&field_to_bytes(field));
    data.extend_from_slice(&g1_to_bytes(g1));
}

// Parse point on G2
pub(crate) fn read_g2<H: CurveHooks>(data: &[u8]) -> Result<G2<H>, ()> {
    if data.len() != 128 {
        return Err(());
    }

    let x_c0 = read_fq_util(&data[0..32]).unwrap();
    let x_c1 = read_fq_util(&data[32..64]).unwrap();
    let y_c0 = read_fq_util(&data[64..96]).unwrap();
    let y_c1 = read_fq_util(&data[96..128]).unwrap();

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2::<H>::new(x, y))
}
