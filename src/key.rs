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

#[derive(Debug, PartialEq, Snafu)]
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

        // let recursive_proof_indices = read_u32_and_check(
        //     raw_vk,
        //     &mut offset,
        //     0,
        //     VerificationKeyError::RecursionNotSupported,
        // )?;

        // this is merely a workaround
        while offset < VK_SIZE {
            let _ = read_bool_and_check(
                raw_vk,
                &mut offset,
                false,
                VerificationKeyError::RecursionNotSupported,
            )?;
        }

        let recursive_proof_indices = 0u32;

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

#[cfg(test)]
mod should {
    use crate::testhooks::TestHooks;

    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_vk() -> [u8; VK_SIZE] {
        hex_literal::hex!(
            "
        000000020000001000000001000000170000000449445f31068ae63477ca649f
        ffc34e466c212c208b89ff7dfebff7831183169ea0cfd64d0d44dc459b23e94c
        e13c419e7feeb1d4bb61991ce667557d0ecc1ee6c29b3c3b0000000449445f32
        093cf3ec6e1328ec2e9963bae3f0769bd8eb45e32cb91e2435d33daf3b336ea9
        29432aa4a2a667ca8a6781517f689f573e78164764701f7190e07eeb282d7752
        0000000449445f33211045f9f4618ac7e73d1ba72682487e558f73d6737ff364
        5a9824352fb90e51012d9c85c11bcc8b2407f4764c4209c06e9027d21764554f
        5a20e9361d4d94ba0000000449445f342eea648c8732596b1314fe2a4d2f0536
        3f0c994e91cecad25835338edee2294f0ab49886c2b94bd0bd3f6ed1dbbe2cb2
        671d2ae51d31c1210433c3972bb6457800000003515f311a8732b002f5686833
        04140deecc1ca5ce2553c9988950ea13c198f1afe44e132c44ea8c14491b4acc
        57cc74ead43131d09e58937ae057f69f29b4af8ecc344100000003515f321eeb
        be1207643a8bd1669b999e82265d340a5ecb1a33c0b7055734ef91200c972f08
        a6a07ed616c588bcf4e3555c006b27d5d1ffba12754d0718481e1a9a419a0000
        0003515f332a7e71e447b5645910a429e7f48f1a5deba7f7d446b95a5edd242b
        55f67993d32b1ea7f7453a8c80a89a675245da0c33db05ba8e95ecea432ab85f
        6b2d6a1e8600000003515f3402d6fd9e84dbe74b7531e1801405a1c292117b1a
        17fefe9de0bfd9edf1a84bf9293c6ab3c06a0669af13393a82c60a459a3b2a0b
        768da45ac7af7f2aec40fc420000000c515f41524954484d4554494318c3e78f
        81e83b52719158e4ac4c2f4b6c55389300451eb2a2deddf244129e7a0002e9c9
        02fe5cd49b64563cadf3bb8d7beb75f905a5894e18d27c42c62fd79700000005
        515f415558155a0f51fec78c33ffceb7364d69d7ac27e570ae50bc180509764e
        b3fef948151c1c4720bed44a591d97cbc72b6e44b644999713a8d3c66e9054aa
        5726324c7600000003515f43117d457bfb28869ab380fd6e83133eeb5b6ab48e
        5df1ae9bc204b608170066552a958a537a99428a1019fd2c8d6b97c48f3e74ad
        77f0e2c63c9dfb6dccf9a29c0000000a515f454c4c49505449430ad34b5e8db7
        2a5acf4427546c7294be6ed4f4d252a79059e505f9abc1bdf3ed1e5b26790a26
        eb340217dd9ad28dbf90a049f42a3852acd45e6f521f24b4900e00000003515f
        4d0efe5ad29f99fce939416b6638dff26c845044cca9a2d9dbf94039a11d999a
        aa0a44bf49517a4b66ae6b51eee6ac68587f768022c11ac8e37cd9dce243d01e
        f200000006515f534f52542cbce7beee3076b78dace04943d69d0d9e28aa6d00
        e046852781a5f20816645c2bc27ec2e1612ea284b08bcc55b6f2fd915d11bfed
        bdc0e59de09e5b28952080000000075349474d415f31210fa88bc935d90241f7
        33cc4f011893a7d349075a0de838001178895da2aa391d270bb763cb26b2438b
        0760dfc7fb68fc98f87155867a2cf5c4b4ba06f637a6000000075349474d415f
        32163a9c8b67447afccc64e9ccba9d9e826ba5b1d1ddd8d6bb960f01cd1321a1
        6919256311d43dbc795f746c63b209667653a773088aba5c6b1337f435188d72
        c4000000075349474d415f331aa81f5a2a21e5f2ce127892122ad0d3c35ac30e
        8556f343a85b66bb0207b0552402d1ec00759182e950c3193c439370013802e6
        819544320a08b8682727f6c6000000075349474d415f342e6367e7e914347a3b
        b11215add814670b848a66aa5c015faedb4f2cef37454f17609c6252f0214568
        96ab4c02adc333912c2f58020c8e55fb2e52096185a0bf000000075441424c45
        5f3102c397073c8abce6d4140c9b961209dd783bff1a1cfc999bb29859cfb16c
        46fc2b7bba2d1efffce0d033f596b4d030750599be670db593af86e1923fe8a1
        bb18000000075441424c455f322c71c58b66498f903b3bbbda3d05ce8ffb571a
        4b3cf83533f3f71b99a04f6e6b039dce37f94d1bbd97ccea32a224fe2afaefbc
        bd080c84dcea90b54f4e0a858f000000075441424c455f3327dc44977efe6b37
        46a290706f4f7275783c73cfe56847d848fd93b63bf320830a5366266dd7b71a
        10b356030226a2de0cbf2edc8f085b16d73652b15eced8f5000000075441424c
        455f34136097d79e1b0ae373255e8760c49900a7588ec4d6809c90bb451005a3
        de307713dd7515ccac4095302d204f06f0bff2595d77bdf72e4acdb0b0b43969
        860d980000000a5441424c455f5459504516ff3501369121d410b445929239ba
        057fe211dad1b706e49a3b55920fac20ec1e190987ebd9cf480f608b82134a00
        eb8007673c1ed10b834a695adf0068522a000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000
        "
        )
    }

    #[rstest]
    fn parse_vk_with_invalid_circuit_type(valid_vk: [u8; VK_SIZE]) {
        let mut invalid_vk = [0u8; VK_SIZE];
        invalid_vk.copy_from_slice(&valid_vk);
        invalid_vk[3] = 3;

        assert_eq!(
            VerificationKey::<TestHooks>::try_from(&invalid_vk[..]).unwrap_err(),
            VerificationKeyError::InvalidCircuitType
        );
    }

    #[rstest]
    fn parse_vk_with_invalid_commitments_number(valid_vk: [u8; VK_SIZE]) {
        let mut invalid_vk = [0u8; VK_SIZE];
        invalid_vk.copy_from_slice(&valid_vk);
        invalid_vk[15] = 0;

        assert_eq!(
            VerificationKey::<TestHooks>::try_from(&invalid_vk[..]).unwrap_err(),
            VerificationKeyError::InvalidCommitmentsNumber
        );
    }

    #[rstest]
    fn parse_vk_containing_recursive_proof(valid_vk: [u8; VK_SIZE]) {
        let mut invalid_vk = [0u8; VK_SIZE];
        invalid_vk.copy_from_slice(&valid_vk);
        invalid_vk[1714] = 1;

        assert_eq!(
            VerificationKey::<TestHooks>::try_from(&invalid_vk[..]).unwrap_err(),
            VerificationKeyError::RecursionNotSupported
        );
    }

    #[rstest]
    fn parse_vk_with_invalid_field(valid_vk: [u8; VK_SIZE]) {
        let mut invalid_vk = [0u8; VK_SIZE];
        invalid_vk.copy_from_slice(&valid_vk);
        invalid_vk[20..=23].fill(0);

        assert_eq!(
            VerificationKey::<TestHooks>::try_from(&invalid_vk[..]).unwrap_err(),
            VerificationKeyError::InvalidCommitmentField {
                value: "\0\0\0\0".to_string()
            }
        );
    }

    #[rstest]
    fn parse_vk_with_point_not_on_curve(valid_vk: [u8; VK_SIZE]) {
        let mut invalid_vk = [0u8; VK_SIZE];
        invalid_vk.copy_from_slice(&valid_vk);
        invalid_vk[24..88].fill(0);

        assert_eq!(
            VerificationKey::<TestHooks>::try_from(&invalid_vk[..]).unwrap_err(),
            VerificationKeyError::PointNotOnCurve { field: "ID_1" }
        );
    }
}
