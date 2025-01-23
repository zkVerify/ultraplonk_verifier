use std::path::PathBuf;

use crate::utils::{self, out_file};
use anyhow::{anyhow, Context, Result};
use ultraplonk_no_std::key::VerificationKey;
use ultraplonk_no_std::testhooks::TestHooks;

pub fn parse_verification_key(
    input: &PathBuf,
    output: &Option<PathBuf>,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("Parsing proof");
    }
    let bb_vk = std::fs::read(input).with_context(|| format!("Failed to read file: {input:?}"))?;

    let zkv_vk = VerificationKey::<TestHooks>::try_from(bb_vk.as_slice())
        .map(|vk| vk.as_solidity_bytes())
        .map_err(|e| anyhow!("{}", e))?;

    if verbose {
        println!("Writing output files");
    }
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
