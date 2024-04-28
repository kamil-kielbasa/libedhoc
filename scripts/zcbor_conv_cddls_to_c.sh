#!/bin/sh

# zcbor python script to generate C code
ZCBOR_PY="../externals/zcbor/zcbor/zcbor.py"

# CDDL models
EDHOC_MODEL="cddls/edhoc.cddl"
COSE_MODEL="cddls/cose.cddl"
COSE_X509_MODEL="cddls/cose_x509.cddl"
TYPES_MODEL="cddls/types.cddl"

# path for cbor backend
SRC="../backends/cbor/src"
INC="../backends/cbor/include"

echo "Remove old generated files ..."
rm $SRC/*.c
rm $INC/*.h

echo "\nGenerating cbor encoding and decoding functions for EAD ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types ead   				\
        --oc $SRC/backend_cbor_ead.c          				\
        --oh $INC/backend_cbor_ead.h                  		\

echo "\nGenerating cbor encoding and decoding functions for edhoc message 1 ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types message_1   		\
        --oc $SRC/backend_cbor_message_1.c          		\
        --oh $INC/backend_cbor_message_1.h                  \


echo "\nGenerating cbor encoding and decoding functions for edhoc message 2 ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types message_2   		\
        --oc $SRC/backend_cbor_message_2.c          		\
        --oh $INC/backend_cbor_message_2.h                  \

echo "\nGenerating cbor encoding and decoding functions for edhoc message 3 ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types message_3   		\
        --oc $SRC/backend_cbor_message_3.c          		\
        --oh $INC/backend_cbor_message_3.h                  \

echo "\nGenerating cbor encoding and decoding functions for edhoc message 4 ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types message_4   		\
        --oc $SRC/backend_cbor_message_4.c          		\
        --oh $INC/backend_cbor_message_4.h                  \

echo "\nGenerating cbor encoding and decoding functions for edhoc error message ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types error       		\
        --oc $SRC/backend_cbor_error.c              		\
        --oh $INC/backend_cbor_error.h                      \

echo "\nGenerating cbor encoding and decoding functions for edhoc info ..."
python3 $ZCBOR_PY code -c $EDHOC_MODEL              		\
        --encode --decode --entry-types info       			\
        --oc $SRC/backend_cbor_info.c              			\
        --oh $INC/backend_cbor_info.h                       \

echo "\nGenerating cbor encoding and decoding functions for COSE signature structure ..."
python3 $ZCBOR_PY code -c $COSE_MODEL          				\
        --encode --decode --entry-types sig_structure		\
        --oc $SRC/backend_cbor_sig_structure.c        		\
        --oh $INC/backend_cbor_sig_structure.h              \

echo "\nGenerating cbor encoding and decoding functions for COSE encryption structure ..."
python3 $ZCBOR_PY code -c $COSE_MODEL          				\
        --encode --decode --entry-types enc_structure		\
        --oc $SRC/backend_cbor_enc_structure.c        		\
        --oh $INC/backend_cbor_enc_structure.h              \

echo "\nGenerating cbor encoding and decoding functions for COSE X509 chain with one certificate ..."
python3 $ZCBOR_PY code -c $COSE_X509_MODEL          		\
        --encode --decode --entry-types id_cred_x  			\
        --oc $SRC/backend_cbor_id_cred_x.c        			\
        --oh $INC/backend_cbor_id_cred_x.h                  \

echo "\nGenerating cbor encoding and decoding functions for edhoc plaintext_2 ..."
python3 $ZCBOR_PY code -c $COSE_X509_MODEL              	\
        --encode --decode --entry-types plaintext_2   		\
        --oc $SRC/backend_cbor_plaintext_2.c          		\
        --oh $INC/backend_cbor_plaintext_2.h                \

echo "\nGenerating cbor encoding and decoding functions for edhoc plaintext_3 ..."
python3 $ZCBOR_PY code -c $COSE_X509_MODEL              	\
        --encode --decode --entry-types plaintext_3   		\
        --oc $SRC/backend_cbor_plaintext_3.c          		\
        --oh $INC/backend_cbor_plaintext_3.h                \

echo "\nGenerating cbor encoding and decoding functions for edhoc plaintext_4 ..."
python3 $ZCBOR_PY code -c $COSE_X509_MODEL              	\
        --encode --decode --entry-types plaintext_4   		\
        --oc $SRC/backend_cbor_plaintext_4.c          		\
        --oh $INC/backend_cbor_plaintext_4.h                \

echo "\nGenerating cbor encoding and decoding functions for byte string type ..."
python3 $ZCBOR_PY code -c $TYPES_MODEL          			\
        --encode --decode --entry-types byte_string_type	\
        --oc $SRC/backend_cbor_bstr_type.c        			\
        --oh $INC/backend_cbor_bstr_type.h                  \

echo "\nGenerating cbor encoding and decoding functions for int type ..."
python3 $ZCBOR_PY code -c $TYPES_MODEL          			\
        --encode --decode --entry-types integer_type  		\
        --oc $SRC/backend_cbor_int_type.c        			\
        --oh $INC/backend_cbor_int_type.h                   \
