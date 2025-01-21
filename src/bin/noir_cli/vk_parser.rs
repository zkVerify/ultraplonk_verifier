use std::path::PathBuf;

use ultraplonk_no_std::key::VerificationKey;
use ultraplonk_no_std::testhooks::TestHooks;

use crate::cli::Commands;
use crate::errors::CliError;
use crate::utils::{self, out_file};

pub fn process_verification_key(command: &Commands, verbose: bool) -> Result<(), CliError> {
    if let Commands::Key { input, output } = command {
        parse_verification_key(input, output)
    } else {
        return Err(CliError::CliError("Invalid command".to_string()));
    }
}

fn parse_verification_key(input: &PathBuf, output: &Option<PathBuf>) -> Result<(), CliError> {
    let bb_vk = std::fs::read(input).map_err(|e| {
        CliError::CliError(format!("Failed to read file: {:?}. Reason :{:?}", input, e))
    })?;

    let zkv_vk = VerificationKey::<TestHooks>::try_from(bb_vk.as_slice())
        .map(|vk| vk.as_solidity_bytes())
        .map_err(|e| CliError::CliError(e.to_string()))?;

    out_file(output.as_ref())?
        .write_all(&zkv_vk)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;

    let mut w = out_file(
        output
            .as_ref()
            .map(|out_path| out_path.with_extension("hex"))
            .as_ref(),
    )?;
    utils::dump_data_hex(&mut w, &zkv_vk)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;
    Ok(())
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
