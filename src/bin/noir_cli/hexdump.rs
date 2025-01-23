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
use anyhow::{Context, Result};

pub fn hexdump(input: &PathBuf, output: &Option<PathBuf>) -> Result<()> {
    let binary_input =
        std::fs::read(input).with_context(|| format!("Failed to read file: {input:?}"))?;

    let mut w = out_file(output.as_ref())?;
    utils::dump_data_hex(&mut w, &binary_input)
        .with_context(|| format!("Failed to write output file: {output:?}"))?;

    Ok(())
}
