// Copyright 2024, The Horizen Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::PathBuf;
use ultraplonk_no_std::testhooks::TestHooks;
use ultraplonk_no_std::{verify as verify_proof, PublicInput};

use crate::errors::CliError;

pub fn verify(
    key: &PathBuf,
    proof: &PathBuf,
    pubs: &PathBuf,
    verbose: bool,
) -> Result<(), CliError> {
    if verbose {
        println!("Reading key file: {:?}", key);
        println!("Reading proof file: {:?}", proof);
        println!("Reading pubs file: {:?}", pubs);
    }

    // Read and process the proof file
    let key_data = std::fs::read(key).map_err(|_| {
        CliError::CliError(format!(
            "Failed to parse verification key from file: {:?}",
            key
        ))
    })?;

    // let vk = VerificationKey::try_from(&key_data[..]).map_err(|_| {
    //     CliError::CliError(format!(
    //         "Failed to parse verification key from file: {:?}",
    //         key
    //     ))
    // })?;

    let vk = &key_data;

    // Read and process the proof file
    let proof = read_proof_file(proof)
        .map_err(|_| CliError::CliError(format!("Failed to read proof file: {:?}", proof)))?;

    // Read and process the key file
    let pubs = std::fs::read(pubs)
        .map_err(|_| CliError::CliError(format!("Failed to read key file: {:?}", pubs)))?;

    // Convert input data into a slice of [PublicInput]
    let pubs = convert_to_pub_inputs(&pubs)?;

    if verbose {
        println!("Verifying proof...");
    }

    match verify_proof::<TestHooks>(vk, &proof, pubs) {
        Ok(_) => {
            println!("Proof is valid");
            Ok(())
        }
        Err(e) => Err(CliError::CliError(format!(
            "Verification failed with error: {:?}",
            e
        ))),
    }
}

pub(crate) fn convert_to_pub_inputs(data: &[u8]) -> Result<&[PublicInput], CliError> {
    if data.len() % 32 != 0 {
        return Err(CliError::CliError(format!(
            "Invalid public inputs length: {:?}",
            data.len()
        )));
    }

    let pub_inputs =
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const PublicInput, data.len() / 32) };

    Ok(pub_inputs)
}

fn read_proof_file(path: &PathBuf) -> Result<[u8; ultraplonk_no_std::PROOF_SIZE], CliError> {
    let data = std::fs::read(path)
        .map_err(|_| CliError::CliError(format!("Failed to read file: {:?}", path)))?;

    if data.len() != ultraplonk_no_std::PROOF_SIZE {
        return Err(CliError::CliError(format!(
            "File size is not 2144 bytes: {:?}",
            ultraplonk_no_std::PROOF_SIZE
        )));
    }

    let mut array = [0u8; ultraplonk_no_std::PROOF_SIZE];
    array.copy_from_slice(&data);
    Ok(array)
}
