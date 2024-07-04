#-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -
#Section : shell commands.
RM := rm -rf
AR := ar rcs
CF := clang-format -i
CPPCHECK := cppcheck --enable=warning,style --inline-suppr

#Colors for echo in shell.
COLOUR_GREEN 	:= \033[0;32m
COLOUR_RED 	:= \033[0;31m
COLOUR_YELLOW	:= \033[0;33m
COLOUR_BLUE 	:= \033[0;34m
COLOUR_MAGNETA	:= \033[0;35m
END_COLOUR 	:= \033[0m

#Verbose mode.
ifeq ("$(origin VERBOSE)", "command line")
	Q := 
else
	Q := @
endif

#-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -
#Section : macros for pretty prints.
define print_cc
	$(if $(Q), @echo "$(COLOUR_YELLOW)[CC]$(END_COLOUR)       $(1)")
endef

define print_bin
	$(if $(Q), @echo "$(COLOUR_GREEN)[BIN]$(END_COLOUR)      $(1)")
endef

define print_ar
	$(if $(Q), @echo "$(COLOUR_BLUE)[AR]$(END_COLOUR)       $(1)")
endef

define print_rm
	$(if $(Q), @echo "$(COLOUR_RED)[RM]$(END_COLOUR)       $(1)")
endef

define print_cf
	$(if $(Q), @echo "$(COLOUR_MAGNETA)[CF]$(END_COLOUR)       $(1)")
endef

define print_cppcheck
	$(if $(Q), @echo "$(COLOUR_MAGNETA)[CPPCHECK]$(END_COLOUR)       $(1)")
endef

#-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -
#Section : external libraries.

# mbedtls library.
SOURCE_DIR_MBEDTLS 	:= ./externals/mbedtls/library
INCLUDE_DIR_MBEDTLS 	:= ./externals/mbedtls/include		\
		 	   ./externals/mbedtls/include/mbedtls	\
			   ./externals/mbedtls/include/psa	\
			   ./externals/mbedtls/library
SOURCE_MBEDTLS 		:= $(wildcard $(SOURCE_DIR_MBEDTLS)/*.c)
OBJECTS_MBEDTLS 	:= $(SOURCE_MBEDTLS:%.c=%.o)

# X25519 & Ed25519 library
SOURCE_DIR_COMPACT25519		:= ./externals/compact25519/src
INCLUDE_DIR_COMPACT25519	:= ./externals/compact25519/src	\
				   ./externals/compact25519/src/c25519
SOURCE_COMPACT25519 		:= $(wildcard $(SOURCE_DIR_COMPACT25519)/*.c)	\
				   $(wildcard $(SOURCE_DIR_COMPACT25519)/c25519/*.c)
OBJECTS_COMPACT25519 		:= $(SOURCE_COMPACT25519:%.c=%.o)

# CBOR engine.
SOURCE_DIR_ZCBOR 	:= ./externals/zcbor/src
INCLUDE_DIR_ZCBOR 	:= ./externals/zcbor/include
SOURCE_ZCBOR 		:= $(wildcard $(SOURCE_DIR_ZCBOR)/*.c)
OBJECTS_ZCBOR 		:= $(SOURCE_ZCBOR:%.c=%.o)

# -------------------------------------------------------------------------------------------------
# Section: backends.

# CBOR backend.
SOURCE_DIR_BACKEND_CBOR 	:= ./backends/cbor/src
INCLUDE_DIR_BACKEND_CBOR	:= ./backends/cbor/include
SOURCE_BACKEND_CBOR 		:= $(wildcard $(SOURCE_DIR_BACKEND_CBOR)/*.c)
OBJECTS_BACKEND_CBOR 		:= $(SOURCE_BACKEND_CBOR:%.c=%.o)

# -------------------------------------------------------------------------------------------------
# Section: library code.

# Application C code.
SOURCE_DIR_APP 	:= ./library
INCLUDE_DIR_APP	:= ./include
SOURCE_APP 	:= $(wildcard $(SOURCE_DIR_APP)/*.c)
OBJECTS_APP 	:= $(SOURCE_APP:%.c=%.o)

# -------------------------------------------------------------------------------------------------
# Section: test code.

# Unit tests
SOURCE_DIR_TEST		:= ./tests/src
INCLUDE_DIR_TEST 	:= ./tests/include
SOURCE_TEST 		:= $(wildcard $(SOURCE_DIR_TEST)/*.c) 			\
                           $(wildcard $(SOURCE_DIR_TEST)/cipher_suites/*.c) 	\
			   $(wildcard $(SOURCE_DIR_TEST)/edhoc_trace_1/*.c) 	\
			   $(wildcard $(SOURCE_DIR_TEST)/x509_chain_cs_0/*.c)	\
			   $(wildcard $(SOURCE_DIR_TEST)/x509_chain_cs_2/*.c)	\
			   $(wildcard $(SOURCE_DIR_TEST)/x509_hash_cs_2/*.c)	\
			   $(wildcard $(SOURCE_DIR_TEST)/edhoc_trace_2/*.c)	\
			   $(wildcard $(SOURCE_DIR_TEST)/error_message/*.c)
OBJECTS_TEST 		:= $(SOURCE_TEST:%.c=%.o)

# -------------------------------------------------------------------------------------------------
# Section: collection of object files and include paths.

# All object files from externals and components.
OBJ := $(OBJECTS_MBEDTLS)	\
       $(OBJECTS_COMPACT25519)	\
       $(OBJECTS_ZCBOR)		\
       $(OBJECTS_BACKEND_CBOR)	\
       $(OBJECTS_APP)		\
       $(OBJECTS_TEST)		\

# All header files.
ALL_INCLUDES_PATHS	:= $(INCLUDE_DIR_MBEDTLS)	\
			   $(INCLUDE_DIR_COMPACT25519)	\
			   $(INCLUDE_DIR_ZCBOR)		\
			   $(INCLUDE_DIR_BACKEND_CBOR)	\
			   $(INCLUDE_DIR_APP)		\
	    		   $(INCLUDE_DIR_TEST)		\

INC := $(foreach d, $(ALL_INCLUDES_PATHS), -I$d)

# -------------------------------------------------------------------------------------------------
# Section: compiler and linker setting.
CC		:= gcc
DEFINES		:= -DEDHOC_KID_LEN=4 				\
		   -DEDHOC_MAX_CSUITES_LEN=2 			\
		   -DEDHOC_MAX_CID_LEN=1 			\
		   -DEDHOC_MAX_ECC_KEY_LEN=32 			\
		   -DEDHOC_MAX_MAC_LEN=32 			\
		   -DEDHOC_MAX_NR_OF_EAD_TOKENS=5		\
		   \
		   -DZCBOR_CANONICAL 				\
		   \
		   -DEDHOC_CRED_KEY_ID_LEN=1			\
		   -DEDHOC_CRED_X509_HASH_ALG_LEN=1 		\
		   \
		   -DMBEDTLS_PSA_KEY_SLOT_COUNT=64		\
		   \
		   -DEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN=2	\

STANDARD	:= -std=gnu11
DEBUG_LEVEL 	:= -g3
OPT_LEVEL	:= -O0
C_WARNINGS	:= -Wall 			\
		   -Wextra 			\
		   -pedantic 			\
		   -Wcast-align 		\
		   -Winit-self 			\
		   -Wlogical-op 		\
		   -Wmissing-include-dirs	\
		   -Wshadow			\
		   -Wundef  			\
		   -Wwrite-strings		\
		   -Wpointer-arith		\
		   -Wmissing-declarations 	\
		   -Wuninitialized		\
		   -Wold-style-definition	\
		   -Wstrict-prototypes 		\
		   -Wmissing-prototypes 	\
		   -Wnested-externs		\
		   -Wunreachable-code		\

CC_FLAGS := -c $(STANDARD) $(DEFINES) $(OPT_LEVEL) $(C_WARNINGS) $(DEBUG_LEVEL)

# -------------------------------------------------------------------------------------------------
# Section: library compilation dependency.

LIB	:=	libedhoc.a
TEST 	:= 	testedhoc.out

all: lib test

lib: $(LIB)

test: $(TEST)

$(LIB): $(OBJ)
	$(call print_ar,$@)
	$(Q)$(AR) $@ $^

$(TEST): $(OBJ)
	$(call print_bin,$@)
	$(Q)$(CC) $(INC) $(OBJ) -o $@

%.o:%.c
	$(call print_cc,$<)
	$(Q)$(CC) $(CC_FLAGS) $(INC) -c $< -o $@

# -------------------------------------------------------------------------------------------------
# Section: Format all source and header files.
format:
	$(call print_cf,$(INCLUDE_DIR_APP)/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_APP)/*.h

	$(call print_cf,$(SOURCE_DIR_APP)/*.c)
	$(Q)$(CF) $(SOURCE_DIR_APP)/*.c

	$(call print_cf,$(INCLUDE_DIR_TEST)/cipher_suites/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/cipher_suites/*.h
	$(call print_cf,$(INCLUDE_DIR_TEST)/edhoc_trace_1/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/edhoc_trace_1/*.h
	$(call print_cf,$(INCLUDE_DIR_TEST)/x509_chain_cs_0/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/x509_chain_cs_0/*.h
	$(call print_cf,$(INCLUDE_DIR_TEST)/x509_chain_cs_2/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/x509_chain_cs_2/*.h
	$(call print_cf,$(INCLUDE_DIR_TEST)/x509_hash_cs_2/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/x509_hash_cs_2/*.h
	$(call print_cf,$(INCLUDE_DIR_TEST)/edhoc_trace_2/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/edhoc_trace_2/*.h
	$(call print_cf,$(INCLUDE_DIR_TEST)/error_message/*.h)
	$(Q)$(CF) $(INCLUDE_DIR_TEST)/error_message/*.h

	$(call print_cf,$(SOURCE_DIR_TEST)/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/cipher_suites/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/cipher_suites/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/edhoc_trace_1/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/edhoc_trace_1/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/x509_chain_cs_0/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/x509_chain_cs_0/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/x509_chain_cs_2/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/x509_chain_cs_2/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/x509_hash_cs_2/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/x509_hash_cs_2/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/edhoc_trace_2/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/edhoc_trace_2/*.c
	$(call print_cf,$(SOURCE_DIR_TEST)/error_message/*.c)
	$(Q)$(CF) $(SOURCE_DIR_TEST)/error_message/*.c

# -------------------------------------------------------------------------------------------------
# Section: Format all source and header files.
cppcheck:
	$(call print_cppcheck, $(SOURCE_DIR_APP)/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_APP)/*.c

	$(call print_cppcheck, $(SOURCE_DIR_TEST)/cipher_suites/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/cipher_suites/*.c
	$(call print_cppcheck, $(SOURCE_DIR_TEST)/edhoc_trace_1/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/edhoc_trace_1/*.c
	$(call print_cppcheck, $(SOURCE_DIR_TEST)/x509_chain_cs_0/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/x509_chain_cs_0/*.c
	$(call print_cppcheck, $(SOURCE_DIR_TEST)/x509_chain_cs_2/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/x509_chain_cs_2/*.c
	$(call print_cppcheck, $(SOURCE_DIR_TEST)/x509_hash_cs_2/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/x509_hash_cs_2/*.c
	$(call print_cppcheck, $(SOURCE_DIR_TEST)/edhoc_trace_2/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/edhoc_trace_2/*.c
	$(call print_cppcheck, $(SOURCE_DIR_TEST)/error_message/*.c)
	$(Q)$(CPPCHECK) $(SOURCE_DIR_TEST)/error_message/*.c

# -------------------------------------------------------------------------------------------------
# Section: Removed all generated files.
clean:
	$(call print_rm,$(LIB))
	$(Q)$(RM) $(LIB)

	$(call print_rm,$(TEST))
	$(Q)$(RM) $(TEST)

	$(call print_rm,$(SOURCE_DIR_MBEDTLS)/*.o)
	$(Q)$(RM) $(SOURCE_DIR_MBEDTLS)/*.o

	$(call print_rm,$(SOURCE_DIR_COMPACT25519)/*.o)
	$(Q)$(RM) $(SOURCE_DIR_COMPACT25519)/*.o
	$(call print_rm,$(SOURCE_DIR_COMPACT25519)/c25519/*.o)
	$(Q)$(RM) $(SOURCE_DIR_COMPACT25519)/c25519/*.o

	$(call print_rm,$(SOURCE_DIR_ZCBOR)/*.o)
	$(Q)$(RM) $(SOURCE_DIR_ZCBOR)/*.o

	$(call print_rm,$(SOURCE_DIR_BACKEND_CBOR)/*.o)
	$(Q)$(RM) $(SOURCE_DIR_BACKEND_CBOR)/*.o

	$(call print_rm,$(SOURCE_DIR_APP)/*.o)
	$(Q)$(RM) $(SOURCE_DIR_APP)/*.o

	$(call print_rm,$(SOURCE_DIR_TEST)/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/cipher_suites/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/cipher_suites/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/edhoc_trace_1/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/edhoc_trace_1/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/x509_chain_cs_0/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/x509_chain_cs_0/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/x509_chain_cs_2/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/x509_chain_cs_2/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/x509_hash_cs_2/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/x509_hash_cs_2/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/edhoc_trace_2/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/edhoc_trace_2/*.o
	$(call print_rm,$(SOURCE_DIR_TEST)/error_message/*.o)
	$(Q)$(RM) $(SOURCE_DIR_TEST)/error_message/*.o
