The [`generate_test_data.sh`](generate_test_data.sh) script is provided for generating sample proofs and verification keys for a specific version of the noir toolchain.
The script relies on docker, so a working docker installation is required.

In order to use the script, the docker image must be built by issuing the following command from the `tests/generate_test_data` directory
```bash
docker build -t generate_test_data .
```
Once the docker image has been built, the script can be run with the command
```bash
./generate_test_data.sh <noir-version>
```
where `<noir-version>` is the desired version of the noir toolchain, prepended with `v` (e.g., for version `0.36.0`, it would be `v0.36.0`). If the script execution is successful, the sample `proof.bin` and `vk.bin` binary files will be placed into the directory `tests/resources/<noir-version>`.