# Builds sw_kern_harness inside a Kern checkout: copy this file and sw_kern_harness.c into
# main/core/test/ of the Kern tree, then `make -f harness.mk sw_kern_harness`. It reuses Kern's
# own Makefile variables and the link line of its psbt classification test (minus the test-only
# -Wl,--wrap flags and -DPSBT_TESTING, so psbt.c is compiled as in the firmware).
include Makefile

# key.c with the fingerprint and key derivation renamed, so the harness can answer them (raw-key
# mode) and fall back to the seed's own.
sw_key.o: ../key.c $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -Dkey_get_fingerprint=key_get_fingerprint_raw \
		-Dkey_get_derived_key_components=key_get_derived_key_components_seed -c -o $@ ../key.c

sw_kern_harness: sw_kern_harness.c $(PSBT_SRC) ../psbt_gate.c ../psbt_gate.h ../psbt_parse.c $(SS_SRC) $(KEY_SRC) \
		$(REGISTRY_SRC) $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) \
		$(DESCRIPTOR_CHECKSUM_SRC) $(DESCRIPTOR_PARSE_SRC) $(SP_PSBT_SRC) $(LIBWALLY) \
		sw_key.o $(CRYPTO_INIT_LIB)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ sw_kern_harness.c sw_key.o ../ss_whitelist.c \
		../registry.c $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) ../psbt.c \
		../psbt_gate.c ../psbt_parse.c ../bip32_path.c ../script_templates.c ../descriptor_checksum.c \
		../descriptor_parse.c $(SP_PSBT_LINK) $(CRYPTO_INIT_LIB) $(LIBWALLY) -lmbedcrypto
