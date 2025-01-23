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

use anyhow::{Context, Result};
use std::fs::File;
use std::io::Write;

pub fn out_file(output: Option<&std::path::PathBuf>) -> Result<Box<dyn std::io::Write>> {
    // Attempt to create the file if a path is specified
    let from_path = output
        .map(|p| {
            // Try to create the file and add context to any error that occurs
            File::create(p).with_context(|| format!("Failed to create output file {p:?}"))
        })
        .transpose()? // Convert Option<Result<File>> to Result<Option<File>>
        .map(|f| Box::new(f) as Box<dyn Write>); // Box the file writer

    // If no path is specified, default to stdout
    Ok(from_path.unwrap_or_else(|| Box::new(std::io::stdout()) as Box<dyn Write>))
}

pub(crate) fn dump_data_hex<W: Write>(mut w: W, data: &[u8]) -> Result<()> {
    w.write_all(b"0x")?;
    w.write_all(hex::encode(data).as_bytes())?;
    writeln!(w)?;
    Ok(())
}
