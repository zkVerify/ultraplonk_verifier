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
