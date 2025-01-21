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
mod proof_parser;
mod utils;
mod verifier;
mod vk_parser;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    if args.verbose {
        println!("Running in verbose mode");
    }

    match args.command {
        cli::Commands::Key { input, output } => {
            vk_parser::parse_verification_key(&input, &output, args.verbose)?
        }
        cli::Commands::KeyToHex { input, output } => vk_parser::dump_key_hex(&input, &output)?,
        cli::Commands::ProofDatav2 {
            num_inputs,
            input_proof,
            output_proof,
            output_pubs,
        } => proof_parser::parse_proof_data_v2(
            &num_inputs,
            &input_proof,
            &output_proof,
            &output_pubs,
            args.verbose,
        )?,
        cli::Commands::Verify { proof, pubs, key } => {
            verifier::verify(&key, &proof, &pubs, args.verbose)?
        }
    }

    Ok(())
}
