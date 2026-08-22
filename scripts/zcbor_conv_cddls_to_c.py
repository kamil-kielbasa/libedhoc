import subprocess
import os
import sys

"""
## Steps to run script zcbor_conv_cddls_to_c.sh:
- `python3 -m venv env`
- `source env/bin/activate`
- `pip3 install -r ../externals/zcbor/scripts/requirements-base.txt`
- `python3 zcbor_conv_cddls_to_c.py`
- `deactivate`
"""

# Define paths
zcbor_py = "../externals/zcbor/zcbor/zcbor.py"
cddl = "cddls/libedhoc.cddl"
types_header = "backend_cbor_types"
src_dir = "../backends/cbor/src"
inc_dir = "../backends/cbor/include"

# Every entry type and the file pair it is generated into. A single model shared
# by all of them keeps identical rules as one C structure.
entry_types = {
    "ead": "backend_cbor_ead",
    "message_1": "backend_cbor_message_1",
    "message_2": "backend_cbor_message_2",
    "message_3": "backend_cbor_message_3",
    "message_4": "backend_cbor_message_4",
    "message_error": "backend_cbor_message_error",
    "info": "backend_cbor_info",
    "id_cred_x": "backend_cbor_id_cred_x",
    "plaintext_2": "backend_cbor_plaintext_2",
    "plaintext_3": "backend_cbor_plaintext_3",
    "plaintext_4": "backend_cbor_plaintext_4",
    "plaintext_2a": "backend_cbor_plaintext_2a",
    "plaintext_3a": "backend_cbor_plaintext_3a",
    "plaintext_3b": "backend_cbor_plaintext_3b",
    "sig_structure": "backend_cbor_sig_structure",
    "enc_structure": "backend_cbor_enc_structure",
    "connection_identifier": "backend_cbor_connection_identifier",
    "byte_string_type": "backend_cbor_bstr_type",
    "integer_type": "backend_cbor_int_type",
}


# Helper function to run commands
def run_command(command):
    subprocess.run(command, shell=True)


def delete_files_by_name(directory, substring):
    if not os.path.isdir(directory):
        return

    for file in os.listdir(directory):
        if substring in file:
            file_path = os.path.join(directory, file)
            try:
                os.remove(file_path)
            except OSError:
                pass


# Remove old files
print("Remove old generated files ...")
for dir in [src_dir, inc_dir]:
    for file in os.listdir(dir):
        if file.endswith(".c") or file.endswith(".h"):
            os.remove(os.path.join(dir, file))


# Function to generate CBOR encoding and decoding functions
def generate_cbor_functions(entries, output):
    # -O disables an over-eager assert in zcbor 0.8.1 that rejects every rule
    # holding an optional group.
    command = (
        f"{sys.executable} -O {zcbor_py} code -c {cddl} --encode --decode"
        f" --entry-types {entries}"
        f" --oc {src_dir}/{output}.c --oh {inc_dir}/{output}.h"
        f" --oht {inc_dir}/{types_header}.h"
    )

    print(f"\nGenerating cbor encoding and decoding functions for {entries} ...")
    run_command(command)


for entry, output in entry_types.items():
    generate_cbor_functions(entry, output)

# Each run above narrows the types header to what its own entry needs; this last
# pass restores the union of them all.
generate_cbor_functions(" ".join(entry_types.keys()), "to_delete")

# Remove temporary files
delete_files_by_name(inc_dir, "to_delete")
delete_files_by_name(src_dir, "to_delete")
