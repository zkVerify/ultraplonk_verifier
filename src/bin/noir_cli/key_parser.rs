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

use std::{io::Write, path::PathBuf};
use ultraplonk_no_std::{
    curvehooks_impl::CurveHooksImpl,
    key::{CommitmentField, VerificationKey},
};

use crate::cli::Commands;
use crate::errors::CliError;
use crate::utils::{
    self, encode_str, encode_u32, encode_value_as_u256, encode_value_as_u32, out_file,
};

pub fn process_verification_key(command: &Commands, verbose: bool) -> Result<(), CliError> {
    if let Commands::Key { input, output } = command {
        parse_key_file(input, output.clone(), verbose)
    } else {
        Err(CliError::CliError("Invalid command".to_string()))
    }
}

fn parse_key_file(input: &PathBuf, output: Option<PathBuf>, verbose: bool) -> Result<(), CliError> {
    if verbose {
        println!("Reading input file: {:?}", input);
    }

    let vk_file = std::fs::read_to_string(&input)
        .map_err(|_| CliError::CliError(format!("Failed to read input file: {:?}", input)))?;
    let mut vk_out = out_file(output.as_ref())?;

    if verbose {
        println!("Parsing Solidity file");
    }

    let vk = parse_solidity_file(&vk_file)
        .map_err(|e| CliError::CliError(format!("Failed to parse Solidity file: {:?}", e)))?;

    if verbose {
        println!("Writing output");
    }

    vk_out.write_all(&vk.as_bytes()).map_err(|_| {
        CliError::CliError(format!(
            "Failed to write output file: {:?}",
            output.unwrap().to_string_lossy()
        ))
    })?;

    Ok(())
}

fn parse_solidity_file(vk_file: &str) -> Result<VerificationKey<CurveHooksImpl>, CliError> {
    let mut buf = [0u8; ultraplonk_no_std::VK_SIZE];
    let mut offset = 0;

    encode_u32(0x02, &mut buf, &mut offset); // circuit_type

    encode_value_as_u32(vk_file, "0x00", &mut buf, &mut offset)?; // circuit_size
    encode_value_as_u32(vk_file, "0x20", &mut buf, &mut offset)?; // num_pub_inputs

    encode_u32(23, &mut buf, &mut offset); // num of commitments
    encode_str(&CommitmentField::ID_1.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x540", &mut buf, &mut offset)?; // ID1.x
    encode_value_as_u256(vk_file, "0x560", &mut buf, &mut offset)?; // ID1.y
    encode_str(&CommitmentField::ID_2.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x580", &mut buf, &mut offset)?; // ID2.x
    encode_value_as_u256(vk_file, "0x5a0", &mut buf, &mut offset)?; // ID2.y
    encode_str(&CommitmentField::ID_3.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x5c0", &mut buf, &mut offset)?; // ID3.x
    encode_value_as_u256(vk_file, "0x5e0", &mut buf, &mut offset)?; // ID3.y
    encode_str(&CommitmentField::ID_4.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x600", &mut buf, &mut offset)?; // ID4.x
    encode_value_as_u256(vk_file, "0x620", &mut buf, &mut offset)?; // ID4.y
    encode_str(&CommitmentField::Q_1.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x80", &mut buf, &mut offset)?; // Q1.x
    encode_value_as_u256(vk_file, "0xa0", &mut buf, &mut offset)?; // Q1.y
    encode_str(&CommitmentField::Q_2.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0xc0", &mut buf, &mut offset)?; // Q2.x
    encode_value_as_u256(vk_file, "0xe0", &mut buf, &mut offset)?; // Q2.y
    encode_str(&CommitmentField::Q_3.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x100", &mut buf, &mut offset)?; // Q3.x
    encode_value_as_u256(vk_file, "0x120", &mut buf, &mut offset)?; // Q3.y
    encode_str(&CommitmentField::Q_4.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x140", &mut buf, &mut offset)?; // Q4.x
    encode_value_as_u256(vk_file, "0x160", &mut buf, &mut offset)?; // Q4.y
    encode_str(&CommitmentField::Q_ARITHMETIC.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x200", &mut buf, &mut offset)?; // QArithmetic.x
    encode_value_as_u256(vk_file, "0x220", &mut buf, &mut offset)?; // QArithmetic.y
    encode_str(&CommitmentField::Q_AUX.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x2c0", &mut buf, &mut offset)?; // QAux.x
    encode_value_as_u256(vk_file, "0x2e0", &mut buf, &mut offset)?; // QAux.y
    encode_str(&CommitmentField::Q_C.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x1c0", &mut buf, &mut offset)?; // QC.x
    encode_value_as_u256(vk_file, "0x1e0", &mut buf, &mut offset)?; // QC.y
    encode_str(&CommitmentField::Q_ELLIPTIC.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x280", &mut buf, &mut offset)?; // QElliptic.x
    encode_value_as_u256(vk_file, "0x2a0", &mut buf, &mut offset)?; // QElliptic.y
    encode_str(&CommitmentField::Q_M.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x180", &mut buf, &mut offset)?; // QM.x
    encode_value_as_u256(vk_file, "0x1a0", &mut buf, &mut offset)?; // QM.y
    encode_str(&CommitmentField::Q_SORT.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x240", &mut buf, &mut offset)?; // QSort.x
    encode_value_as_u256(vk_file, "0x260", &mut buf, &mut offset)?; // QSort.y
    encode_str(&CommitmentField::SIGMA_1.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x300", &mut buf, &mut offset)?; // Sigma1.x
    encode_value_as_u256(vk_file, "0x320", &mut buf, &mut offset)?; // Sigma1.y
    encode_str(&CommitmentField::SIGMA_2.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x340", &mut buf, &mut offset)?; // Sigma2.x
    encode_value_as_u256(vk_file, "0x360", &mut buf, &mut offset)?; // Sigma2.y
    encode_str(&CommitmentField::SIGMA_3.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x380", &mut buf, &mut offset)?; // Sigma3.x
    encode_value_as_u256(vk_file, "0x3a0", &mut buf, &mut offset)?; // Sigma3.y
    encode_str(&CommitmentField::SIGMA_4.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x3c0", &mut buf, &mut offset)?; // Sigma4.x
    encode_value_as_u256(vk_file, "0x3e0", &mut buf, &mut offset)?; // Sigma4.y
    encode_str(&CommitmentField::TABLE_1.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x400", &mut buf, &mut offset)?; // Table1.x
    encode_value_as_u256(vk_file, "0x420", &mut buf, &mut offset)?; // Table1.y
    encode_str(&CommitmentField::TABLE_2.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x440", &mut buf, &mut offset)?; // Table2.x
    encode_value_as_u256(vk_file, "0x460", &mut buf, &mut offset)?; // Table2.y
    encode_str(&CommitmentField::TABLE_3.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x480", &mut buf, &mut offset)?; // Table3.x
    encode_value_as_u256(vk_file, "0x4a0", &mut buf, &mut offset)?; // Table3.y
    encode_str(&CommitmentField::TABLE_4.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x4c0", &mut buf, &mut offset)?; // Table4.x
    encode_value_as_u256(vk_file, "0x4e0", &mut buf, &mut offset)?; // Table4.y
    encode_str(&CommitmentField::TABLE_TYPE.str(), &mut buf, &mut offset)?;
    encode_value_as_u256(vk_file, "0x500", &mut buf, &mut offset)?; // TableType.x
    encode_value_as_u256(vk_file, "0x520", &mut buf, &mut offset)?; // TableType.y

    VerificationKey::try_from(&buf[..])
        .map_err(|e| CliError::CliError(format!("Failed to parse verification key: {:?}", e)))
}

pub fn dump_key_hex(input_vk: &PathBuf, output_vk: &Option<PathBuf>) -> Result<(), CliError> {
    let vk = std::fs::read(input_vk).map_err(|e| {
        CliError::CliError(format!(
            "Failed to read file: {:?}. Reason :{:?}",
            input_vk, e
        ))
    })?;

    let mut w = out_file(output_vk.as_ref())?;
    utils::dump_data_hex(&mut w, &vk)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;

    Ok(())
}
