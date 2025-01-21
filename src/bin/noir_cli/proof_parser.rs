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

use crate::errors::CliError;
use crate::utils::{self, out_file};

pub fn parse_proof_data(
    num_inputs: &usize,
    input_proof: &PathBuf,
    output_proof: &Option<PathBuf>,
    output_pubs: &Option<PathBuf>,
    verbose: bool,
) -> Result<(), CliError> {
    if verbose {
        println!("Parsing proof");
    }
    // Parse proof and strip it from the pub ins
    let mut proof = std::fs::read(input_proof).map_err(|e| {
        CliError::CliError(format!(
            "Failed to read file: {:?}. Reason :{:?}",
            input_proof, e
        ))
    })?;

    let expected_len = ultraplonk_no_std::PROOF_SIZE + 32 * num_inputs;
    if proof.len() != expected_len {
        return Err(CliError::CliError(format!(
            "File size is not as expected. Expected {:?}, Actual: {:?}",
            expected_len,
            proof.len()
        )));
    }

    if verbose {
        println!("Parsing public inputs");
    }

    let proof_without_pubs = proof.split_off(32 * num_inputs);

    if verbose {
        println!("Writing output files");
    }

    // Write output proof in binary format
    out_file(output_proof.as_ref())?
        .write_all(&proof_without_pubs)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;

    // Write proof in hex format
    let mut w = out_file(
        output_proof
            .as_ref()
            .map(|out_path| out_path.with_extension("hex"))
            .as_ref(),
    )?;
    utils::dump_data_hex(&mut w, &proof_without_pubs)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;

    // Write output pub ins
    out_file(output_pubs.as_ref())?
        .write_all(&proof)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;

    // Write pub ins in hex format
    let mut w = out_file(
        output_pubs
            .as_ref()
            .map(|out_path| out_path.with_extension("hex"))
            .as_ref(),
    )?;

    let pubs_vec = crate::verifier::convert_to_pub_inputs(&proof)?;

    for ins in pubs_vec {
        utils::dump_data_hex(&mut w, ins)
            .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;
    }

    Ok(())
}
