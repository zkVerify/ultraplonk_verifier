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

use anyhow::{anyhow, Context, Result};
use log::info;
use std::path::PathBuf;
use ultraplonk_no_std::{verify as verify_proof, PublicInput};

pub fn verify(key: &PathBuf, proof: &PathBuf, pubs: &PathBuf) -> Result<()> {
    info!("Reading key file: {key:?}");
    let key_data = std::fs::read(key)
        .with_context(|| format!("Failed to read verification key file: {key:?}"))?;

    let vk = &key_data;

    info!("Reading proof file: {proof:?}");
    let proof =
        read_proof_file(proof).with_context(|| format!("Failed to read proof file: {proof:?}"))?;

    info!("Reading pubs file: {pubs:?}");
    let pubs = std::fs::read(pubs)
        .with_context(|| format!("Failed to read public input file: {pubs:?}"))?;

    let pubs = convert_to_pub_inputs(&pubs)?;

    info!("Verifying proof...");
    match verify_proof::<()>(vk, &proof, &pubs) {
        Ok(_) => {
            info!("Proof is valid");
            Ok(())
        }
        Err(e) => Err(anyhow!("Verification failed with error: {:?}", e)),
    }
}

pub(crate) fn convert_to_pub_inputs(data: &[u8]) -> Result<Vec<PublicInput>> {
    if data.len() % 32 != 0 {
        Err(anyhow!("Invalid public inputs length: {:?}", data.len()))?;
    }

    Ok(data
        .chunks_exact(32)
        .map(|v| v.try_into().unwrap())
        .collect())
}

fn read_proof_file(path: &PathBuf) -> Result<[u8; ultraplonk_no_std::PROOF_SIZE]> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {path:?}"))?;

    data.as_slice().try_into().map_err(|_| {
        anyhow!(
            "File size is not correct: expected {:?}, got {:?}",
            ultraplonk_no_std::PROOF_SIZE,
            data.len()
        )
    })
}
