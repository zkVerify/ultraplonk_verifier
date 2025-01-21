use std::path::PathBuf;

use crate::{
    errors::CliError,
    utils::{self, out_file},
};

pub fn hexdump(input: &PathBuf, output: &Option<PathBuf>) -> Result<(), CliError> {
    let binary_input = std::fs::read(input).map_err(|e| {
        CliError::CliError(format!("Failed to read file: {:?}. Reason :{:?}", input, e))
    })?;

    let mut w = out_file(output.as_ref())?;
    utils::dump_data_hex(&mut w, &binary_input)
        .map_err(|_| CliError::CliError("Failed to write output file".to_string()))?;

    Ok(())
}
