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

/// The verification error type
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// Failure due to another reason.
    OtherError,
    /// Provided data has not valid public inputs.
    InvalidInput,
    /// Provided data has not valid proof.
    InvalidProofData,
    /// Verify proof failed.
    VerificationError,
    /// Provided an invalid verification key.
    InvalidVerificationKey,
}

#[derive(Debug)]
pub enum GroupError {
    InvalidSliceLength,
    NotOnCurve,
    NotInSubgroup,
}

#[derive(Debug)]
pub enum FieldError {
    InvalidSliceLength,
    InvalidU512Encoding,
    NotMember,
}
