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

use crate::utils::{self, out_file};
use anyhow::{anyhow, Context, Result};
use log::info;
use ultraplonk_no_std::key::VerificationKey;

pub fn parse_verification_key(input: &PathBuf, output: &Option<PathBuf>) -> Result<()> {
    info!("Parsing proof");
    let bb_vk = std::fs::read(input).with_context(|| format!("Failed to read file: {input:?}"))?;

    let zkv_vk = VerificationKey::<()>::try_from(bb_vk.as_slice())
        .map(|vk| vk.as_solidity_bytes())
        .map_err(|e| anyhow!("{}", e))?;

    info!("Writing output files");
    out_file(output.as_ref())?
        .write_all(&zkv_vk)
        .with_context(|| format!("Failed to write output file: {output:?}"))?;

    let output_hex = output
        .as_ref()
        .map(|out_path| out_path.with_extension("hex"));
    let mut w = out_file(output_hex.as_ref())?;
    utils::dump_data_hex(&mut w, &zkv_vk)
        .with_context(|| format!("Failed to write output file: {output_hex:?}"))?;
    Ok(())
}
