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
    types::G1,
    Fq, Fr, U256,
};
use ark_bn254_ext::CurveHooks;
use ark_ff::PrimeField;

pub(crate) trait IntoFq {
    fn into_fq(self) -> Fq;
}

impl IntoFq for U256 {
    fn into_fq(self) -> Fq {
        Fq::from(self)
    }
}

impl IntoFq for u64 {
    fn into_fq(self) -> Fq {
        Fq::new(U256::from(self))
    }
}

impl IntoFq for Fr {
    fn into_fq(self) -> Fq {
        // Convert the `Fr` field element into a `BigInteger256`
        let big_int = self.into_bigint();

        // Use the `from_bigint` method of `Fq` to convert it into a base field element
        Fq::from_bigint(big_int).expect("Fr value is always a valid Fq element")
    }
}

pub(crate) trait IntoFr {
    fn into_fr(self) -> Fr;
}

impl IntoFr for &[u8; 32] {
    fn into_fr(self) -> Fr {
        self.into_u256().into_fr()
    }
}

impl IntoFr for [u8; 32] {
    fn into_fr(self) -> Fr {
        (&self).into_fr()
    }
}

impl IntoFr for U256 {
    fn into_fr(self) -> Fr {
        Fr::new(self)
    }
}

impl IntoFr for u64 {
    fn into_fr(self) -> Fr {
        // Fr::from(self)
        Fr::new(U256::from(self))
    }
}

impl IntoFr for Fq {
    fn into_fr(self) -> Fr {
        Fr::from(self.into_bigint())
    }
}

#[allow(unused)]
pub(crate) trait IntoU256 {
    fn into_u256(self) -> U256;
}

impl IntoU256 for u32 {
    fn into_u256(self) -> U256 {
        U256::from(self)
    }
}

impl IntoU256 for &[u8; 32] {
    fn into_u256(self) -> U256 {
        // Convert the byte array to a little-endian byte vector
        let mut bytes = self.to_vec(); // Convert the &[u8; 32] slice to a Vec<u8>
        bytes.reverse(); // Reverse the bytes to ensure little-endian order

        // Create a BigInteger256 from the little-endian byte array
        let mut limbs = [0u64; 4];

        // Populate the limbs from the byte vector (which is little-endian)
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(
                bytes[(i << 3)..((i + 1) << 3)]
                    .try_into()
                    .expect("Invalid byte slice"),
            );
        }

        U256::new(limbs)
    }
}

impl IntoU256 for [u8; 32] {
    fn into_u256(self) -> U256 {
        (&self).into_u256()
    }
}

pub(crate) trait IntoBytes {
    fn into_bytes(self) -> [u8; 32];
}

impl IntoBytes for U256 {
    fn into_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, limb) in self.0.iter().rev().enumerate() {
            // Convert each limb to big-endian bytes
            let limb_bytes = limb.to_be_bytes();
            // Copy the bytes into the correct position in the output array
            bytes[(i << 3)..((i + 1) << 3)].copy_from_slice(&limb_bytes);
        }
        bytes
    }
}

impl IntoBytes for Fr {
    fn into_bytes(self) -> [u8; 32] {
        self.into_bigint().into_bytes()
    }
}

impl IntoBytes for Fq {
    fn into_bytes(self) -> [u8; 32] {
        self.into_bigint().into_bytes()
    }
}

// Parsing utility for points in G1
pub(crate) fn read_g1_util<H: CurveHooks>(data: &[u8], reverse: bool) -> Result<G1<H>, GroupError> {
    if data.len() != 64 {
        return Err(GroupError::InvalidSliceLength);
    }

    let x: Fq;
    let y: Fq;

    if reverse {
        y = read_fq_util(&data[0..32]).unwrap();
        x = read_fq_util(&data[32..64]).unwrap();
    } else {
        x = read_fq_util(&data[0..32]).unwrap();
        y = read_fq_util(&data[32..64]).unwrap();
    }

    let point = G1::new_unchecked(x, y);

    // Validate point
    if !point.is_on_curve() {
        return Err(GroupError::NotOnCurve);
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(GroupError::NotInSubgroup);
    }

    Ok(point)
}

// Utility function for parsing points in G2
pub(crate) fn read_fq_util(data: &[u8]) -> Result<Fq, FieldError> {
    if data.len() != 32 {
        return Err(FieldError::InvalidSliceLength);
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::macros::decode;
    use ark_ff::BigInteger;

    // IMPORTANT NOTE: The `muln` is deprecated as of ark-ff 0.4.2 and should be replaced with <<
    #[test]
    fn test_u32_to_u256() {
        let x = 16_u32;
        let mut x_u256 = x.into_u256();
        println!("x = {}", x);
        println!("x_u256 = {:?}", x_u256);
        println!("x_u256 (bytes) = {:?}", x_u256.into_bytes());
        x_u256.muln(224);
        println!("x_u256 << 224 = {:?}", x_u256);
        println!("x_u256 << 224 (bytes) = {:?}", x_u256.into_bytes());
    }

    #[test]
    fn test_u256_to_fq() {
        let input = "15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5";
        let value = decode(input.as_bytes());
        println!("value = {:?}", value);
        let value_fq = value.into_fq();
        println!("value_fq = {:?}", value_fq);
    }

    #[test]
    fn test_large_u256_to_fq() {
        let input = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        // BigInt([18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615])
        let value = decode(input.as_bytes());
        println!("value = {:?}", value);
        let value_fq = value.into_fq();
        println!("value_fq = {:?}", value_fq);
    }

    #[test]
    fn test_large_u256_to_fr() {
        let input = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        // BigInt([18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615])
        let value = decode(input.as_bytes());
        println!("value = {:?}", value);
        let value_fr = value.into_fr();
        println!("value_fr = {:?}", value_fr);
    }

    #[test]
    fn test_addition_in_fr() {
        // let value: U256 = BigInteger256::new([1, 2, 3, 4]);
        let input = "15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5";
        let value = decode(input.as_bytes());
        let field_element: Fr = value.into_fr();
        println!("Converted field element: {:#?}", field_element);
        let other = U256::new([0, 0, 0, 1]).into_fr();
        println!("other = {:#?}", other);
        let res = field_element + other;
        println!("The result is {:#?}", res);
    }

    #[test]
    fn test_fr_from_u64() {
        let x: u64 = 1;
        let y = x.into_fr();
        println!("x = {}", x);
        println!("y = {:#?}", y);
    }

    #[test]
    fn test_fq_from_u64() {
        let u: u64 = 1;
        let v = u.into_fq();
        println!("u = {}", u);
        println!("v = {:#?}", v);
    }

    #[test]
    fn test_u256_to_bytes() {
        let input = "15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5";
        let value = decode(input.as_bytes());
        let expected_bytes = value.into_bytes();
        let actual_bytes = [
            21, 210, 203, 48, 190, 84, 174, 208, 74, 19, 86, 188, 171, 191, 98, 23, 162, 10, 123,
            75, 231, 112, 183, 114, 134, 217, 181, 112, 130, 112, 85, 213,
        ];
        assert_eq!(actual_bytes, expected_bytes);
    }

    #[test]
    fn test_fr_to_fq() {
        let input = "15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5";
        let value = decode(input.as_bytes());
        let fr_element: Fr = value.into_fr();

        let fq_element: Fq = fr_element.into_fq();

        println!("fq_element = {:?}", fq_element);
    }

    #[test]
    fn test_fq_to_fr() {
        let value = crate::macros::u256!(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46" // q - 1
        );

        let fq_element: Fq = value.into_fq();

        println!("fq_element = {:?}", fq_element);

        let fr_element: Fr = fq_element.into_fr();

        println!("fr_element = {:?}", fr_element);
    }

    #[test]
    fn test_bytes_to_fr() {
        // Given byte array
        let bytes: &[u8; 32] = &[
            21, 210, 203, 48, 190, 84, 174, 208, 74, 19, 86, 188, 171, 191, 98, 23, 162, 10, 123,
            75, 231, 112, 183, 114, 134, 217, 181, 112, 130, 112, 85, 213,
        ];

        // Convert the byte array to Fr
        let fr_element: Fr = bytes.into_fr();

        // Convert to BigInt and check if it matches the expected limbs
        let expected_bigint = U256::new([
            9716997165857920469,
            11676280549847119730,
            5337705351699456535,
            1572542630117813968,
        ]);

        // Extract the BigInt from the Fr element
        let actual_bigint = fr_element.into_bigint();

        // Check if the actual result matches the expected BigInt
        assert_eq!(actual_bigint, expected_bigint);

        // Optionally, print to verify manually
        println!("fr_element = {:?}", fr_element);
    }

    #[test]
    fn test_bytes_to_u256() {
        // Given byte array
        let bytes: &[u8; 32] = &[
            21, 210, 203, 48, 190, 84, 174, 208, 74, 19, 86, 188, 171, 191, 98, 23, 162, 10, 123,
            75, 231, 112, 183, 114, 134, 217, 181, 112, 130, 112, 85, 213,
        ];

        // Convert the byte array to U256
        let u256_element: U256 = bytes.into_u256();

        // Expected BigInteger256 (U256)
        let expected_bigint = U256::new([
            9716997165857920469,
            11676280549847119730,
            5337705351699456535,
            1572542630117813968,
        ]);

        // Check if the actual result matches the expected BigInt (U256)
        assert_eq!(u256_element, expected_bigint);
    }
}
