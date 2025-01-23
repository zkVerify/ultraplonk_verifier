#![cfg(feature = "bins")]

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use rstest::*;
use std::{path::PathBuf, process::Command};

#[test]
fn hexdump() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("noir-cli")?;

    let file = assert_fs::NamedTempFile::new("sample.bin")?;
    file.write_binary(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])?;

    cmd.arg("hexdump").arg("--input").arg(file.path());
    cmd.assert()
        .success()
        .stdout(predicate::eq("0xaabbccddeeff\n"));

    Ok(())
}

#[rstest]
fn convert_proof_and_vk_and_verify(
    #[files("tests/resources/v*")] version: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let zkv_proof = assert_fs::NamedTempFile::new("zkv_proof.bin")?;
    let zkv_pubs = assert_fs::NamedTempFile::new("zkv_pubs.bin")?;
    let zkv_vk = assert_fs::NamedTempFile::new("zkv_vk.bin")?;

    let mut proof_path = version.to_path_buf();
    proof_path.push("proof.bin");

    let mut cmd_proof_data = Command::cargo_bin("noir-cli")?;
    cmd_proof_data
        .arg("proof-data")
        .arg("-n")
        .arg("1")
        .arg("--input-proof")
        .arg(proof_path)
        .arg("--output-proof")
        .arg(zkv_proof.path())
        .arg("--output-pubs")
        .arg(zkv_pubs.path());

    cmd_proof_data.assert().success();

    let mut vk_path = version.to_path_buf();
    vk_path.push("vk.bin");

    let mut cmd_key = Command::cargo_bin("noir-cli")?;
    cmd_key
        .arg("key")
        .arg("--input")
        .arg(vk_path)
        .arg("--output")
        .arg(zkv_vk.path());

    cmd_key.assert().success();

    let mut cmd_verify = Command::cargo_bin("noir-cli")?;
    cmd_verify
        .arg("verify")
        .arg("--proof")
        .arg(zkv_proof.path())
        .arg("--pubs")
        .arg(zkv_pubs.path())
        .arg("--key")
        .arg(zkv_vk.path());

    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof is valid"));
    Ok(())
}
