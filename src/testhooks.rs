// Copyright 2022 arkworks contributors
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

use crate::CurveHooks;
use ark_bn254::{g1::Config as ArkG1Config, g2::Config as ArkG2Config, Bn254 as ArkBn254};
use ark_models_ext::{pairing::Pairing, CurveConfig};

pub struct TestHooks;

type Bn254 = ark_bn254_ext::Bn254<TestHooks>;
type G1Projective = ark_bn254_ext::G1Projective<TestHooks>;
type G2Projective = ark_bn254_ext::G2Projective<TestHooks>;
type G1Affine = ark_bn254_ext::G1Affine<TestHooks>;
type G2Affine = ark_bn254_ext::G2Affine<TestHooks>;
type G1Config = ark_bn254_ext::g1::Config<TestHooks>;
type G2Config = ark_bn254_ext::g2::Config<TestHooks>;

impl CurveHooks for TestHooks {
    fn bn254_multi_miller_loop(
        g1: impl Iterator<Item = <Bn254 as Pairing>::G1Prepared>,
        g2: impl Iterator<Item = <Bn254 as Pairing>::G2Prepared>,
    ) -> Result<<Bn254 as Pairing>::TargetField, ()> {
        test_utils::multi_miller_loop_generic::<Bn254, ArkBn254>(g1, g2)
    }

    fn bn254_final_exponentiation(
        target: <Bn254 as Pairing>::TargetField,
    ) -> Result<<Bn254 as Pairing>::TargetField, ()> {
        test_utils::final_exponentiation_generic::<Bn254, ArkBn254>(target)
    }

    fn bn254_msm_g1(
        bases: &[G1Affine],
        scalars: &[<G1Config as CurveConfig>::ScalarField],
    ) -> Result<G1Projective, ()> {
        test_utils::msm_sw_generic::<G1Config, ArkG1Config>(bases, scalars)
    }

    fn bn254_msm_g2(
        bases: &[G2Affine],
        scalars: &[<G2Config as CurveConfig>::ScalarField],
    ) -> Result<G2Projective, ()> {
        test_utils::msm_sw_generic::<G2Config, ArkG2Config>(bases, scalars)
    }

    fn bn254_mul_projective_g1(base: &G1Projective, scalar: &[u64]) -> Result<G1Projective, ()> {
        test_utils::mul_projective_sw_generic::<G1Config, ArkG1Config>(base, scalar)
    }

    fn bn254_mul_projective_g2(base: &G2Projective, scalar: &[u64]) -> Result<G2Projective, ()> {
        test_utils::mul_projective_sw_generic::<G2Config, ArkG2Config>(base, scalar)
    }
}
