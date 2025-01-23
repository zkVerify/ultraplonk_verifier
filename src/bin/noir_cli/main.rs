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

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;

mod cli;
mod hexdump;
mod proof_parser;
mod utils;
mod verifier;
mod vk_parser;

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    let log_level = if args.verbose {
        LevelFilter::max()
    } else {
        LevelFilter::Error
    };
    env_logger::Builder::new().filter_level(log_level).init();

    match args.command {
        cli::Commands::Key { input, output } => vk_parser::parse_verification_key(&input, &output)?,
        cli::Commands::Hexdump { input, output } => hexdump::hexdump(&input, &output)?,
        cli::Commands::ProofData {
            num_inputs,
            input_proof,
            output_proof,
            output_pubs,
        } => {
            proof_parser::parse_proof_data(&num_inputs, &input_proof, &output_proof, &output_pubs)?
        }
        cli::Commands::Verify { proof, pubs, key } => verifier::verify(&key, &proof, &pubs)?,
    }

    Ok(())
}
