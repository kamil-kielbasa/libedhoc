import subprocess
import os

"""
## Steps to run script zcbor_conv_cddls_to_c.sh:
- `python3 -m venv env`
- `source env/bin/activate`
- `pip3 install -r ../externals/zcbor/scripts/requirements-base.txt`
- `python3 zcbor_conv_cddls_to_c.py`
- `deactivate`
"""

# Define paths and models
zcbor_py = "../externals/zcbor/zcbor/zcbor.py"
models = {
    "EDHOC": "cddls/edhoc.cddl",
    "COSE": "cddls/cose.cddl",
    "COSE_X509": "cddls/cose_x509.cddl",
    "TYPES": "cddls/types.cddl"
}
src_dir = "../backends/cbor/src"
inc_dir = "../backends/cbor/include"

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
def generate_cbor_functions(model, entry_types, output, output_ht=None):
    # Build the base command
    command = f"python3 {zcbor_py} code -c {models[model]} --encode --decode --entry-types {entry_types} --oc {src_dir}/{output}.c --oh {inc_dir}/{output}.h"
    
    # Add the optional header type file parameter
    if output_ht:
        command += f" --oht {inc_dir}/{output_ht}.h"
    
    print(f"\nGenerating cbor encoding and decoding functions for {entry_types} ...")
    run_command(command)

# Generate CBOR encoding and decoding functions for EDHOC
entry_types = {
    "ead": ["backend_cbor_ead", "backend_cbor_edhoc_types"],
    "message_1": ["backend_cbor_message_1", "backend_cbor_edhoc_types"],
    "message_2": ["backend_cbor_message_2", "backend_cbor_edhoc_types"],
    "message_3": ["backend_cbor_message_3", "backend_cbor_edhoc_types"],
    "message_4": ["backend_cbor_message_4", "backend_cbor_edhoc_types"],
    "message_error": ["backend_cbor_message_error", "backend_cbor_edhoc_types"],
    "info": ["backend_cbor_info", "backend_cbor_edhoc_types"]
}

for entry, files in entry_types.items():
    generate_cbor_functions("EDHOC", entry, *files)

generate_cbor_functions("EDHOC", " ".join(entry_types.keys()), "to_delete", "backend_cbor_edhoc_types")

# Generate CBOR encoding and decoding functions for COSE_X509
entry_types = {
    "id_cred_x": ["backend_cbor_id_cred_x", "backend_cbor_x509_types"],
    "plaintext_2": ["backend_cbor_plaintext_2", "backend_cbor_x509_types"],
    "plaintext_3": ["backend_cbor_plaintext_3", "backend_cbor_x509_types"],
    "plaintext_4": ["backend_cbor_plaintext_4", "backend_cbor_x509_types"]
}

for entry, files in entry_types.items():
    generate_cbor_functions("COSE_X509", entry, *files)

generate_cbor_functions("COSE_X509", " ".join(entry_types.keys()), "to_delete", "backend_cbor_x509_types")

# Generate CBOR encoding and decoding functions for COSE
generate_cbor_functions("COSE", "sig_structure", "backend_cbor_sig_structure")
generate_cbor_functions("COSE", "enc_structure", "backend_cbor_enc_structure")

# Generate CBOR encoding and decoding functions for TYPES
generate_cbor_functions("TYPES", "byte_string_type", "backend_cbor_bstr_type")
generate_cbor_functions("TYPES", "integer_type", "backend_cbor_int_type")

# Remove temporary files
delete_files_by_name(inc_dir, "to_delete")
delete_files_by_name(src_dir, "to_delete")