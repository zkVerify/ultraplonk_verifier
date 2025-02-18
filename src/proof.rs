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

#[derive(Debug, PartialEq, Snafu)]
pub enum ProofError {
    #[snafu(display(
        "Incorrect buffer size. Expected: {}; Got: {}",
        expected_size,
        actual_size
    ))]
    IncorrectBufferSize {
        expected_size: usize,
        actual_size: usize,
    },

    #[snafu(display(
        "Invalid slice size. Expected: {}; Got: {}",
        expected_length,
        actual_length
    ))]
    InvalidSliceLength {
        expected_length: usize,
        actual_length: usize,
    },

    #[snafu(display("Point for field is not on curve"))]
    PointNotOnCurve,

    // #[snafu(display("Point is not in the correct subgroup"))]
    // PointNotInCorrectSubgroup,
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
            GroupError::InvalidSliceLength {
                expected_length,
                actual_length,
            } => ProofError::InvalidSliceLength {
                expected_length,
                actual_length,
            },
        })
        .inspect(|_| {
            *offset += 64;
        })
}

fn read_proof_fq(data: &[u8], offset: &mut usize) -> Result<Fq, ProofError> {
    read_fq_util(&data[*offset..*offset + 32])
        .map_err(|e| match e {
            FieldError::NotMember => ProofError::NotMember,
            FieldError::InvalidSliceLength {
                expected_length,
                actual_length,
            } => ProofError::InvalidSliceLength {
                expected_length,
                actual_length,
            },
        })
        .inspect(|_| {
            *offset += 32;
        })
}

impl<H: CurveHooks> TryFrom<&[u8]> for Proof<H> {
    type Error = ProofError;

    fn try_from(proof: &[u8]) -> Result<Self, ProofError> {
        if proof.len() != PROOF_SIZE {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: PROOF_SIZE,
                actual_size: proof.len(),
            });
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

#[cfg(test)]
mod should {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_proof() -> [u8; PROOF_SIZE] {
        hex_literal::hex!(
            "
        15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5
        1e33c5b02a6b10e4e34705620f96db583a46531edb67ed54f5cd8e1ca98bea8b
        1c4e2003c9a844fc7afb84010fc53a773f0b2bacea45345fb2eb4bd9ab638a55
        23630ae86706266aed6a82c0a729cf7c38ac7db37da246c99e77cda5efc41c24
        0c985adc08d6763ce7dd8287bd2cd201243f7f4031e836729c15b8f6cb4cf507
        07fdc6f741c84477a7e42f8a480ee64a3d1c7fceecac94055eb24a3efa580cec
        0a95d4a2e9688d0759a87a2981a38d746683c17b279db1eef35152a55cbdde25
        00f9204aa9544b599fdfa411abb0b6a779f9437f08fedc4421405cbca27c1b7a
        0fe1ba3146ee70914c49716272161c3700940bd8c1a9e4741e105fc08dac8e2e
        2f442bc8d3df8524f0916a93a6c6cc5d4b1d28a55e1a5531bad46b316f95e0bc
        25ca0b2ea7f3e365f0ad209d726935cab91f67d5ae985a934d38becd8aaa603a
        04b319d8591a137cde07a5f82c6749130603435be93c9a3c8764559723ee4dc0
        194a87ca976963c90a77a8ebaca268dc1c5f8286f9d4ad5016c757080baeef58
        0892aff5f163d3d89418a1835a2f768cb1421a1b10a298037cdcdb4a040ef292
        00b8e0558b77daed027ad8a2d7f6027de8e2dc9ddafd572170312d511f0e5df8
        2a927caded56827ac403fab8e088eb4e4b80da829ed406e1ef308b95f18181fd
        0952d7f350a0019b47b3aad37ce0883a2f6c842f48392f6a8c9230872117414f
        0d0c07547ea86d3a7f446c019cf99ae44b251dc51c2a22dec3f716649263e01d
        1a67b3f521c82483bdd0a513ff382073193cb4588bc7253c011f5aa31924110a
        0ae3441e2c685cf0d54b83c99798415509144bfcaa881e6e30ade37e572399ba
        08d632a5ce80aff8e5ba0361b99095ddc633c678b5296dd56e87a0496fea1eb1
        012cd30fc1dce7ff3a99173aea24327920c6aeadda5a15f765df7719088b66d2
        210b5e4ea13de0415a33c50ccbe9e6eaad4ddfca26d8a4938350387479d9e09d
        0962e6b3452b23cdcbea70d2123a2eeaa81d7bf390c185b66504a80ecf3ef82b
        099d2178bac44b9d3321dc0526524b221cdc8a374cd2202fd6215464ff3f8476
        2ac49b998bf39f10397bf4f548b49ce7bdb17e9b287fb3e8a605974894717dc0
        2518385d5e81584d61e671405e2585de4bfeb7fbf01d8ec3660758ba6defa4b7
        009e3d83d677371e58bc62dbc55046a82a3579d5283beaa4426a422be86b14e9
        09a6df873f123568af5f8904f66f6ad44d22355db3d3bfabeb3a55ec9594e961
        0164bdcf0258a4194289526455191edbf6c8cafaad5042d4423cb5812b5d9827
        1207fc52674841378d5b7a73f8750fdc3d593c04242c7abb61098a24b7987e45
        2f0ac3265215a262614a752c2cdbdd8e59cf8fe47386e3d49a22d781aebfde93
        1c6540f3bc4d17c3303b2993b3903b333a0655f952af0fce11bb61b8570be298
        2064d62d1af0f813cb9e49aa4537e7339a93a889199185b91c378334fe8747ce
        133f1692b5fb32bd0f5160684f8dba06c35ac1e6265e897552971fe383e817ea
        0decf78938ce20085b226a81c9ecb989eb91b3b6a3d7e5cce47f2d2e05e14a55
        15bae71eb000ea4bad8975881995317a954c7a899b00ef8d0103db19ceba8375
        2a97e16d9a73a3a4c858be5d8d5858ccd70980f5fc0697b51a9912948291d3e4
        0f108d49a3b4bcd42ad7c17c7f9a27c1f0929f19e352cf4bf04c547b46692452
        1e6d394705e59912563aeb5f17d2161dcfaeb79889a30ecff21fefcf89688cf8
        0799175f0e83f4c1f862aa8cbba3ab70569ef82c998ad006fd411bef685fb58f
        1e125b763bd56e9f4dccd54ae0dc4bd5234cbeca7ac18d0c044190ecaecf980d
        16803802f1907c3300c9af02231952900d112596672fdc3031fa3e0e3c833c84
        0866337497688f5ca8260d70e59f1e094bd8c3aa2ba4af0adf94cddcbe17c52f
        1d432dc381db48b5c2f556465962455b8d95ca168caa5732f92a055771ef159e
        01bbd99f8b1c61e5257459654ba41450a71ee83a73f68ec9cedd473e35c6660c
        1698d3ee758f1b3e4043a23abf673ba2e8dbeea6d4fc36f1e8727eb8e99db67b
        23ed87988e27762d45a70a51f35d4f14324fa5864458777409e18bf5fa4074c1
        242fac8d503f8c14e2c4a16b8dfcbe9b53b51bdfd5f739eaf956631b3e16c795
        2fd61e179b6416e97c65e480f55a0c1898f18b808b7534c16dfd5a3c2e38fc19
        29c693280c4280cde2df9a1f6cc5a509906870e52301051e99e4ecb1e8eda509
        19fca4d8911b78bed6950208f04ad45df291d98eb685ed98caa1b1a263cf8cda
        2c051af6edb513da1b7be8e444c700e06b55338bcc3231b7cdfed446ca03873c
        0fb2806943438f4b66f367b5e0a1dacb4595d3f05331821056c4337165b95817
        2c944ab23a04420dfad52c3a998aa9baec080e4974b2073504acfc3cef414ec4
        124acdb4271aca62aec07a8b89e900a80bc5bb59c15d5dd94e221c04abfb4836
        192d7d5dc100b4e0c628b7493490dcbb20ef7d859e1a39c815c41b89e5b84cca
        271d16d948b87dff4d5bcd19930c384ac72876accb639eb8018ed26d2457eab4
        2d79c77f7a8aaed8551f908cb8bdb6e16a7de1be7d07e9a1358f40cfb6992269
        017c832aee48022cc6ae47169dd144416b0f36f783a85f8399e2ba5695521b9d
        1dd6bbdc302af51e2d6ba0584bd8d2d28b6ec30bc04d3e78a3a4191ec318f340
        09cca61a90dc47e5dbd8b3e3785f0906839a66d78338acdc6983825300dfcae2
        2626decbd2bf3ad742960d2526669797a3f9f2ebbfdd8bd17344e11b2ea6a285
        16808fc616ff267412c838fa8c551d3d9cfb7a8647685a018e8cc1bd7a6a3460
        048aa7e7f24eee374cf90c841436d24a056b61ad4c60d74c7dd6cc94f96df371
        296609d66f3d55d39d5eae092cce3113bd892ee417a22a5ba014dd731a72688b
        19ef4d11b948ceb06aef6ab97c0cf7a04486fdd998784f200d26e2bbc0aa79b3
        "
        )
    }

    #[rstest]
    fn successfully_parse_a_well_formed_proof(valid_proof: [u8; PROOF_SIZE]) {
        assert!(Proof::<()>::try_from(&valid_proof[..]).is_ok());
    }

    mod reject {
        use super::*;

        #[rstest]
        fn a_proof_from_a_short_buffer(valid_proof: [u8; PROOF_SIZE]) {
            let invalid_proof = &valid_proof[..10];
            assert_eq!(
                Proof::<()>::try_from(invalid_proof).unwrap_err(),
                ProofError::IncorrectBufferSize {
                    expected_size: PROOF_SIZE,
                    actual_size: invalid_proof.len()
                }
            );
        }

        #[rstest]
        fn a_proof_with_a_point_not_on_curve(valid_proof: [u8; PROOF_SIZE]) {
            let mut invalid_proof = [0u8; PROOF_SIZE];
            invalid_proof.copy_from_slice(&valid_proof);
            invalid_proof[32 * 4..32 * 5].fill(0);

            assert_eq!(
                Proof::<()>::try_from(&invalid_proof[..]).unwrap_err(),
                ProofError::PointNotOnCurve
            );
        }
    }
}
