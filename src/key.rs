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

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    constants::{self, MAX_LOG2_CIRCUIT_SIZE},
    errors::GroupError,
    utils::{read_fq_util, read_g1_util, IntoBytes, IntoU256},
    Fq2, Fr, G1, G2, U256, VK_SIZE,
};
use ark_bn254::Fq;
use ark_bn254_ext::CurveHooks;
use ark_ff::BigInt;
use snafu::Snafu;

#[derive(Debug, PartialEq, Snafu)]
pub enum VerificationKeyError {
    #[snafu(display("Buffer too short"))]
    BufferTooShort,

    #[snafu(display(
        "Slice length is incorrect. Expected: {}, got: {}",
        expected_length,
        actual_length
    ))]
    InvalidSliceLength {
        expected_length: usize,
        actual_length: usize,
    },

    // #[snafu(display("Invalid field '{}': {:?}", field, error))]
    // InvalidField {
    //     field: &'static str,
    //     error: FieldError,
    // },
    #[snafu(display("Point for field '{}' is not on curve", field))]
    PointNotOnCurve { field: &'static str },

    #[snafu(display("Point for field '{}' is not in the correct subgroup", field))]
    PointNotInCorrectSubgroup { field: &'static str },

    // #[snafu(display("Invalid value '{}'", value))]
    // InvalidValue { value: String },
    #[snafu(display("Non-invertible element {}", value))]
    NonInvertibleElement { value: String },

    #[snafu(display("No roots of unity for {}", value))]
    NoRootsOfUnity { value: String },

    #[snafu(display("Invalid circuit type, expected 2"))]
    InvalidCircuitType,

    #[snafu(display("Invalid circuit size"))]
    InvalidCircuitSize,

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

#[derive(PartialEq, Eq, Debug, Default)]
pub struct VerificationKey<H: CurveHooks> {
    pub circuit_type: u32,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
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

impl<H: CurveHooks + Default> VerificationKey<H> {
    pub fn as_solidity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        const CIRCUIT_TYPE: U256 = BigInt!("2");
        out.extend(CIRCUIT_TYPE.into_bytes());
        out.extend(U256::from(self.circuit_size).into_bytes());
        out.extend(U256::from(self.num_public_inputs).into_bytes());
        out.extend(U256::from(self.id_1.x).into_bytes());
        out.extend(U256::from(self.id_1.y).into_bytes());
        out.extend(U256::from(self.id_2.x).into_bytes());
        out.extend(U256::from(self.id_2.y).into_bytes());
        out.extend(U256::from(self.id_3.x).into_bytes());
        out.extend(U256::from(self.id_3.y).into_bytes());
        out.extend(U256::from(self.id_4.x).into_bytes());
        out.extend(U256::from(self.id_4.y).into_bytes());
        out.extend(U256::from(self.q_1.x).into_bytes());
        out.extend(U256::from(self.q_1.y).into_bytes());
        out.extend(U256::from(self.q_2.x).into_bytes());
        out.extend(U256::from(self.q_2.y).into_bytes());
        out.extend(U256::from(self.q_3.x).into_bytes());
        out.extend(U256::from(self.q_3.y).into_bytes());
        out.extend(U256::from(self.q_4.x).into_bytes());
        out.extend(U256::from(self.q_4.y).into_bytes());
        out.extend(U256::from(self.q_arithmetic.x).into_bytes());
        out.extend(U256::from(self.q_arithmetic.y).into_bytes());
        out.extend(U256::from(self.q_aux.x).into_bytes());
        out.extend(U256::from(self.q_aux.y).into_bytes());
        out.extend(U256::from(self.q_c.x).into_bytes());
        out.extend(U256::from(self.q_c.y).into_bytes());
        out.extend(U256::from(self.q_elliptic.x).into_bytes());
        out.extend(U256::from(self.q_elliptic.y).into_bytes());
        out.extend(U256::from(self.q_m.x).into_bytes());
        out.extend(U256::from(self.q_m.y).into_bytes());
        out.extend(U256::from(self.q_sort.x).into_bytes());
        out.extend(U256::from(self.q_sort.y).into_bytes());
        out.extend(U256::from(self.sigma_1.x).into_bytes());
        out.extend(U256::from(self.sigma_1.y).into_bytes());
        out.extend(U256::from(self.sigma_2.x).into_bytes());
        out.extend(U256::from(self.sigma_2.y).into_bytes());
        out.extend(U256::from(self.sigma_3.x).into_bytes());
        out.extend(U256::from(self.sigma_3.y).into_bytes());
        out.extend(U256::from(self.sigma_4.x).into_bytes());
        out.extend(U256::from(self.sigma_4.y).into_bytes());
        out.extend(U256::from(self.table_1.x).into_bytes());
        out.extend(U256::from(self.table_1.y).into_bytes());
        out.extend(U256::from(self.table_2.x).into_bytes());
        out.extend(U256::from(self.table_2.y).into_bytes());
        out.extend(U256::from(self.table_3.x).into_bytes());
        out.extend(U256::from(self.table_3.y).into_bytes());
        out.extend(U256::from(self.table_4.x).into_bytes());
        out.extend(U256::from(self.table_4.y).into_bytes());
        out.extend(U256::from(self.table_type.x).into_bytes());
        out.extend(U256::from(self.table_type.y).into_bytes());
        out.extend(U256::from(self.contains_recursive_proof as u32).into_bytes());
        out.extend(U256::from(self.recursive_proof_indices).into_bytes());
        out
    }

    pub fn try_from_solidity_bytes(bytes: &[u8]) -> Result<Self, VerificationKeyError> {
        if bytes.len() != VK_SIZE {
            Err(VerificationKeyError::BufferTooShort)?;
        }
        let mut out = Self::default();
        let mut pos = 0;
        let indices = |p: usize| p * 32..(p + 1) * 32;
        let indices_point = |p: usize| p * 32..(p + 2) * 32;
        out.circuit_type = if get_u32(&bytes[indices(pos)])
            .or(Err(VerificationKeyError::InvalidCircuitType))?
            == 2
        {
            Ok(2)
        } else {
            Err(VerificationKeyError::InvalidCircuitType)
        }?;
        pos += 1;
        let circuit_size =
            get_u32(&bytes[indices(pos)]).or(Err(VerificationKeyError::InvalidCircuitSize))?;
        if !circuit_size.is_power_of_two() || circuit_size > 2u32.pow(MAX_LOG2_CIRCUIT_SIZE) {
            Err(VerificationKeyError::InvalidCircuitSize)?;
        }
        out.circuit_size = circuit_size;
        pos += 1;
        out.num_public_inputs =
            get_u32(&bytes[indices(pos)]).or(Err(VerificationKeyError::InvalidCircuitSize))?; // TODO
        pos += 1;
        out.id_1 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_1.str(),
            }))?;
        pos += 2;
        out.id_2 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_2.str(),
            }))?;
        pos += 2;
        out.id_3 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_3.str(),
            }))?;
        pos += 2;
        out.id_4 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_4.str(),
            }))?;
        pos += 2;
        out.q_1 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_1.str(),
            }))?;
        pos += 2;
        out.q_2 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_2.str(),
            }))?;
        pos += 2;
        out.q_3 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_3.str(),
            }))?;
        pos += 2;
        out.q_4 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_4.str(),
            }))?;
        pos += 2;
        out.q_arithmetic =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_ARITHMETIC.str(),
            }))?;
        pos += 2;
        out.q_aux =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_AUX.str(),
            }))?;
        pos += 2;
        out.q_c =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_C.str(),
            }))?;
        pos += 2;
        out.q_elliptic =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_ELLIPTIC.str(),
            }))?;
        pos += 2;
        out.q_m =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_M.str(),
            }))?;
        pos += 2;
        out.q_sort =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_SORT.str(),
            }))?;
        pos += 2;
        out.sigma_1 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::SIGMA_1.str(),
            }))?;
        pos += 2;
        out.sigma_2 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::SIGMA_2.str(),
            }))?;
        pos += 2;
        out.sigma_3 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::SIGMA_3.str(),
            }))?;
        pos += 2;
        out.sigma_4 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::SIGMA_4.str(),
            }))?;
        pos += 2;
        out.table_1 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::TABLE_1.str(),
            }))?;
        pos += 2;
        out.table_2 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::TABLE_2.str(),
            }))?;
        pos += 2;
        out.table_3 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::TABLE_3.str(),
            }))?;
        pos += 2;
        out.table_4 =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::TABLE_4.str(),
            }))?;
        pos += 2;
        out.table_type =
            get_g1(&bytes[indices_point(pos)]).or(Err(VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::TABLE_TYPE.str(),
            }))?;
        pos += 2;
        let contains_recursive_proof =
            get_bool(&bytes[indices(pos)]).or(Err(VerificationKeyError::RecursionNotSupported))?;
        pos += 1;
        if contains_recursive_proof {
            Err(VerificationKeyError::RecursionNotSupported)?
        }
        out.contains_recursive_proof = false;

        out.recursive_proof_indices =
            get_u32(&bytes[indices(pos)]).or(Err(VerificationKeyError::RecursionNotSupported))?;
        Ok(out)
    }
}

fn get_u256(bytes: &[u8]) -> Result<U256, ()> {
    <&[u8; 32]>::try_from(bytes)
        .map_err(|_| ())
        .map(IntoU256::into_u256)
}

fn get_u32(bytes: &[u8]) -> Result<u32, ()> {
    let out = get_u256(bytes)?;
    if out < U256::from(u32::MAX) {
        let mut data = [0u8; 4];
        data.copy_from_slice(&bytes[28..32]);
        Ok(u32::from_be_bytes(data))
    } else {
        Err(())
    }
}

fn get_bool(bytes: &[u8]) -> Result<bool, ()> {
    let out = get_u256(bytes)?;
    if out == U256::from(1u32) {
        Ok(true)
    } else if out == U256::from(0u32) {
        Ok(false)
    } else {
        Err(())
    }
}

fn get_g1<H: CurveHooks>(data: &[u8]) -> Result<G1<H>, ()> {
    if data.len() != 64 {
        return Err(());
    }
    use ark_ff::PrimeField;

    let x = Fq::from_bigint(get_u256(&data[0..32])?).ok_or(())?;
    let y = Fq::from_bigint(get_u256(&data[32..64])?).ok_or(())?;

    let point = G1::new_unchecked(x, y);

    // Validate point
    if !point.is_on_curve() {
        return Err(());
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(());
    }

    Ok(point)
}

impl<H: CurveHooks> From<&VerificationKey<H>> for PreparedVerificationKey<H> {
    fn from(vk: &VerificationKey<H>) -> Self {
        let log2_circuit_size = ark_std::log2(vk.circuit_size as usize);
        let work_root = constants::root_of_unity(log2_circuit_size).unwrap();
        let work_root_inverse = constants::inverse_root_of_unity(log2_circuit_size).unwrap();
        let domain_inverse = constants::domain_inverse(log2_circuit_size).unwrap();
        PreparedVerificationKey {
            circuit_type: vk.circuit_type,
            circuit_size: vk.circuit_size,
            num_public_inputs: vk.num_public_inputs,
            q_1: vk.q_1,
            q_2: vk.q_2,
            q_3: vk.q_3,
            q_4: vk.q_4,
            q_m: vk.q_m,
            q_c: vk.q_c,
            q_arithmetic: vk.q_arithmetic,
            q_aux: vk.q_aux,
            q_elliptic: vk.q_elliptic,
            q_sort: vk.q_sort,
            sigma_1: vk.sigma_1,
            sigma_2: vk.sigma_2,
            sigma_3: vk.sigma_3,
            sigma_4: vk.sigma_4,
            table_1: vk.table_1,
            table_2: vk.table_2,
            table_3: vk.table_3,
            table_4: vk.table_4,
            table_type: vk.table_type,
            id_1: vk.id_1,
            id_2: vk.id_2,
            id_3: vk.id_3,
            id_4: vk.id_4,
            contains_recursive_proof: vk.contains_recursive_proof,
            recursive_proof_indices: vk.recursive_proof_indices,
            work_root,
            work_root_inverse,
            domain_inverse,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct PreparedVerificationKey<H: CurveHooks> {
    pub circuit_type: u32,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
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
    pub work_root: Fr,
    pub work_root_inverse: Fr,
    pub domain_inverse: Fr,
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
        const OFFSET_AFTER_COMMITMENTS: usize = 1713;
        if raw_vk.len() < OFFSET_AFTER_COMMITMENTS + 2 {
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

        debug_assert_eq!(offset, OFFSET_AFTER_COMMITMENTS);

        let contains_recursive_proof = read_bool_and_check(
            raw_vk,
            &mut offset,
            false,
            VerificationKeyError::RecursionNotSupported,
        )?;

        let recursive_proof_indices = 0;

        offset = raw_vk.len() - 1;
        let _is_recursive_circuit = read_bool_and_check(
            raw_vk,
            &mut offset,
            false,
            VerificationKeyError::RecursionNotSupported,
        )?;

        Ok(VerificationKey::<H> {
            circuit_type,
            circuit_size,
            num_public_inputs,
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
        GroupError::InvalidSliceLength {
            expected_length,
            actual_length,
        } => VerificationKeyError::InvalidSliceLength {
            expected_length,
            actual_length,
        },
    })
}

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

    let x_c0 = read_fq_util(&data[0..32]).expect("Parsing the SRS should always succeed!");
    let x_c1 = read_fq_util(&data[32..64]).expect("Parsing the SRS should always succeed!");
    let y_c0 = read_fq_util(&data[64..96]).expect("Parsing the SRS should always succeed!");
    let y_c1 = read_fq_util(&data[96..128]).expect("Parsing the SRS should always succeed!");

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2::<H>::new(x, y))
}

#[cfg(test)]
mod should {
    use crate::testhooks::TestHooks;

    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_vk() -> [u8; VK_SIZE] {
        hex_literal::hex!(
            "
            0000000000000000000000000000000000000000000000000000000000000002
            0000000000000000000000000000000000000000000000000000000000000010
            0000000000000000000000000000000000000000000000000000000000000001
            068ae63477ca649fffc34e466c212c208b89ff7dfebff7831183169ea0cfd64d
            0d44dc459b23e94ce13c419e7feeb1d4bb61991ce667557d0ecc1ee6c29b3c3b
            093cf3ec6e1328ec2e9963bae3f0769bd8eb45e32cb91e2435d33daf3b336ea9
            29432aa4a2a667ca8a6781517f689f573e78164764701f7190e07eeb282d7752
            211045f9f4618ac7e73d1ba72682487e558f73d6737ff3645a9824352fb90e51
            012d9c85c11bcc8b2407f4764c4209c06e9027d21764554f5a20e9361d4d94ba
            2eea648c8732596b1314fe2a4d2f05363f0c994e91cecad25835338edee2294f
            0ab49886c2b94bd0bd3f6ed1dbbe2cb2671d2ae51d31c1210433c3972bb64578
            1a8732b002f568683304140deecc1ca5ce2553c9988950ea13c198f1afe44e13
            2c44ea8c14491b4acc57cc74ead43131d09e58937ae057f69f29b4af8ecc3441
            1eebbe1207643a8bd1669b999e82265d340a5ecb1a33c0b7055734ef91200c97
            2f08a6a07ed616c588bcf4e3555c006b27d5d1ffba12754d0718481e1a9a419a
            2a7e71e447b5645910a429e7f48f1a5deba7f7d446b95a5edd242b55f67993d3
            2b1ea7f7453a8c80a89a675245da0c33db05ba8e95ecea432ab85f6b2d6a1e86
            02d6fd9e84dbe74b7531e1801405a1c292117b1a17fefe9de0bfd9edf1a84bf9
            293c6ab3c06a0669af13393a82c60a459a3b2a0b768da45ac7af7f2aec40fc42
            18c3e78f81e83b52719158e4ac4c2f4b6c55389300451eb2a2deddf244129e7a
            0002e9c902fe5cd49b64563cadf3bb8d7beb75f905a5894e18d27c42c62fd797
            155a0f51fec78c33ffceb7364d69d7ac27e570ae50bc180509764eb3fef94815
            1c1c4720bed44a591d97cbc72b6e44b644999713a8d3c66e9054aa5726324c76
            117d457bfb28869ab380fd6e83133eeb5b6ab48e5df1ae9bc204b60817006655
            2a958a537a99428a1019fd2c8d6b97c48f3e74ad77f0e2c63c9dfb6dccf9a29c
            0ad34b5e8db72a5acf4427546c7294be6ed4f4d252a79059e505f9abc1bdf3ed
            1e5b26790a26eb340217dd9ad28dbf90a049f42a3852acd45e6f521f24b4900e
            0efe5ad29f99fce939416b6638dff26c845044cca9a2d9dbf94039a11d999aaa
            0a44bf49517a4b66ae6b51eee6ac68587f768022c11ac8e37cd9dce243d01ef2
            2cbce7beee3076b78dace04943d69d0d9e28aa6d00e046852781a5f20816645c
            2bc27ec2e1612ea284b08bcc55b6f2fd915d11bfedbdc0e59de09e5b28952080
            210fa88bc935d90241f733cc4f011893a7d349075a0de838001178895da2aa39
            1d270bb763cb26b2438b0760dfc7fb68fc98f87155867a2cf5c4b4ba06f637a6
            163a9c8b67447afccc64e9ccba9d9e826ba5b1d1ddd8d6bb960f01cd1321a169
            19256311d43dbc795f746c63b209667653a773088aba5c6b1337f435188d72c4
            1aa81f5a2a21e5f2ce127892122ad0d3c35ac30e8556f343a85b66bb0207b055
            2402d1ec00759182e950c3193c439370013802e6819544320a08b8682727f6c6
            2e6367e7e914347a3bb11215add814670b848a66aa5c015faedb4f2cef37454f
            17609c6252f021456896ab4c02adc333912c2f58020c8e55fb2e52096185a0bf
            02c397073c8abce6d4140c9b961209dd783bff1a1cfc999bb29859cfb16c46fc
            2b7bba2d1efffce0d033f596b4d030750599be670db593af86e1923fe8a1bb18
            2c71c58b66498f903b3bbbda3d05ce8ffb571a4b3cf83533f3f71b99a04f6e6b
            039dce37f94d1bbd97ccea32a224fe2afaefbcbd080c84dcea90b54f4e0a858f
            27dc44977efe6b3746a290706f4f7275783c73cfe56847d848fd93b63bf32083
            0a5366266dd7b71a10b356030226a2de0cbf2edc8f085b16d73652b15eced8f5
            136097d79e1b0ae373255e8760c49900a7588ec4d6809c90bb451005a3de3077
            13dd7515ccac4095302d204f06f0bff2595d77bdf72e4acdb0b0b43969860d98
            16ff3501369121d410b445929239ba057fe211dad1b706e49a3b55920fac20ec
            1e190987ebd9cf480f608b82134a00eb8007673c1ed10b834a695adf0068522a
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            "
        )
    }

    #[rstest]
    fn deserialize_serialize_solidity_vk(valid_vk: [u8; VK_SIZE]) {
        let deserialized_vk =
            VerificationKey::<TestHooks>::try_from_solidity_bytes(&valid_vk).unwrap();
        let vk = deserialized_vk.as_solidity_bytes();
        pretty_assertions::assert_eq!(valid_vk, vk.as_slice())
    }

    mod reject {
        use super::*;

        #[rstest]
        fn a_vk_with_invalid_circuit_type(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[3] = 3;

            assert_eq!(
                VerificationKey::<TestHooks>::try_from_solidity_bytes(&invalid_vk[..]).unwrap_err(),
                VerificationKeyError::InvalidCircuitType
            );
        }

        #[rstest]
        fn a_vk_containing_a_recursive_proof(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[VK_SIZE - 33] = 1;

            assert_eq!(
                VerificationKey::<TestHooks>::try_from_solidity_bytes(&invalid_vk[..]).unwrap_err(),
                VerificationKeyError::RecursionNotSupported
            );
        }

        #[rstest]
        fn a_vk_with_a_point_not_on_curve(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[32 * 4..32 * 5].fill(0);

            assert_eq!(
                VerificationKey::<TestHooks>::try_from_solidity_bytes(&invalid_vk[..]).unwrap_err(),
                VerificationKeyError::PointNotOnCurve { field: "ID_1" }
            );
        }

        #[rstest]
        fn a_vk_from_a_short_buffer() {
            let invalid_vk = [0u8; 10];

            assert_eq!(
                VerificationKey::<TestHooks>::try_from_solidity_bytes(&invalid_vk[..]).unwrap_err(),
                VerificationKeyError::BufferTooShort
            );
        }
    }
}
