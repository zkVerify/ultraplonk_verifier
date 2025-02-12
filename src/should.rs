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

use crate::*;
use curvehooks_impl::CurveHooksImpl;
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

#[fixture]
fn valid_pub() -> [PublicInput; 1] {
    [hex_literal::hex!(
        "000000000000000000000000000000000000000000000000000000000000000a"
    )]
}

#[rstest]
fn verify_valid_proof(
    valid_vk: [u8; VK_SIZE],
    valid_proof: [u8; PROOF_SIZE],
    valid_pub: [PublicInput; 1],
) {
    assert!(verify::<CurveHooksImpl>(&valid_vk, &valid_proof, &valid_pub).is_ok());
}

mod reject {
    use alloc::string::ToString;

    use super::*;

    #[rstest]
    fn an_invalid_vk(valid_proof: [u8; PROOF_SIZE], valid_pub: [PublicInput; 1]) {
        let invalid_vk = [0u8; VK_SIZE];

        assert_eq!(
            verify::<CurveHooksImpl>(&invalid_vk, &valid_proof, &valid_pub),
            Err(VerifyError::KeyError)
        );
    }

    #[rstest]
    fn an_invalid_proof(valid_vk: [u8; VK_SIZE], valid_pub: [PublicInput; 1]) {
        let invalid_proof = [0u8; PROOF_SIZE];

        assert_eq!(
            verify::<CurveHooksImpl>(&valid_vk, &invalid_proof, &valid_pub),
            Err(VerifyError::InvalidProofError)
        );
    }

    #[rstest]
    fn an_invalid_pub_input(valid_proof: [u8; PROOF_SIZE], valid_vk: [u8; VK_SIZE]) {
        let invalid_pub = [hex_literal::hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )];

        assert_eq!(
            verify::<CurveHooksImpl>(&valid_vk, &valid_proof, &invalid_pub),
            Err(VerifyError::PublicInputError {
                message: "Found public input greater than scalar field modulus".to_string()
            })
        );
    }

    #[rstest]
    fn a_public_input_with_invalid_length(valid_proof: [u8; PROOF_SIZE], valid_vk: [u8; VK_SIZE]) {
        let invalid_pubs = [
            hex_literal::hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            hex_literal::hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ];

        assert_eq!(
            verify::<CurveHooksImpl>(&valid_vk, &valid_proof, &invalid_pubs),
            Err(VerifyError::PublicInputError {
                message: "Provided public inputs length does not match. Expected: 1; Got: 2"
                    .to_string()
            })
        );
    }

    #[rstest]
    fn invalid_valid_proof(
        valid_vk: [u8; VK_SIZE],
        valid_proof: [u8; PROOF_SIZE],
        mut valid_pub: [PublicInput; 1],
    ) {
        valid_pub[0][31] -= 1;
        assert_eq!(
            verify::<CurveHooksImpl>(&valid_vk, &valid_proof, &valid_pub),
            Err(VerifyError::VerificationError)
        );
    }
}
