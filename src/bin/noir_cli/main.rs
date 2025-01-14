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

// NOTE: This utility program is for Noir v.0.36.0.

use anyhow::Result;
use clap::Parser;

mod cli;
mod errors;
mod key_parser;
mod proof_parser;
mod utils;
mod verifier;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    if args.verbose {
        println!("Running in verbose mode");
    }

    match args.command {
        cli::Commands::Key { .. } => {
            key_parser::process_verification_key(&args.command, args.verbose)?
        }
        cli::Commands::KeyToHex { input, output } => key_parser::dump_key_hex(&input, &output)?,
        cli::Commands::ProofData { .. } => {
            proof_parser::process_proof_data(&args.command, args.verbose)?
        }
        cli::Commands::ProofDatav2 { .. } => {
            proof_parser::process_proof_data_v2(&args.command, args.verbose)?
        }
        cli::Commands::Verify { .. } => verifier::process_command(&args.command, args.verbose)?,
    }

    Ok(())
}
