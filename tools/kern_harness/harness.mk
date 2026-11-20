# Builds sw_kern_harness inside a Kern checkout: copy this file and sw_kern_harness.c into
# main/core/test/ of the Kern tree, then `make -f harness.mk sw_kern_harness`. It reuses Kern's
# own Makefile variables and the link line of its psbt classification test (minus the test-only
# -Wl,--wrap flags and -DPSBT_TESTING, so psbt.c is compiled as in the firmware).
include Makefile

sw_kern_harness: sw_kern_harness.c $(PSBT_SRC) ../psbt_gate.c ../psbt_gate.h $(SS_SRC) $(KEY_SRC) \
		$(REGISTRY_SRC) $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) \
		$(DESCRIPTOR_CHECKSUM_SRC) $(DESCRIPTOR_PARSE_SRC) $(SP_PSBT_SRC) $(LIBWALLY) \
		$(PSBT_KEY_OBJ) $(CRYPTO_INIT_LIB)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ sw_kern_harness.c $(PSBT_KEY_OBJ) ../ss_whitelist.c \
		../registry.c $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) ../psbt.c \
		../psbt_gate.c ../bip32_path.c ../script_templates.c ../descriptor_checksum.c \
		../descriptor_parse.c $(SP_PSBT_LINK) $(CRYPTO_INIT_LIB) $(LIBWALLY) -lmbedcrypto
