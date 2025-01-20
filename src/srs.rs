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

/// A constant byte slice representing BN254 G2 point. `noir-compiler` when installed will
/// downloads this data and stores it in ~/.nargo/backends/acvm-backend-barretenberg/crs/bn254_g2.dat
pub static SRS_G2: [u8; 128] = hex_literal::hex!(
    "
        0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0
        260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1
        22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55
        04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4
    "
);
