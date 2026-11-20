/* SilentWitness harness for Kern's PSBT signing path (core/psbt.c, core/sp_psbt.c).
 *
 * Built inside a checkout of Kern at a pinned commit (see tools/kern_harness/harness.mk and
 * .github/workflows/scorecard.yml), never on a developer machine. It follows the order of the
 * firmware's scan flow without its screens:
 *
 *   parse -> classify -> pre-review gate -> BIP 375 share round (sp_psbt_complete)
 *         -> classify -> review gate -> psbt_sign -> trim -> serialize
 *
 * stdin:  line 1 the mnemonic, line 2 "1" for testnet or "0", line 3 the PSBT in base64.
 * stdout: one JSON line {"outcome": "signed"|"refused"|"crashed", "reason": "...", "psbt": "..."}.
 * Every string in the output is either fixed text from this file or base64.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_psbt.h>

#include "core/crypto_init.h"
#include "core/key.h"
#include "core/psbt.h"
#include "core/psbt_gate.h"
#include "core/registry.h"
#include "core/settings.h"
#include "core/sp_psbt.h"
#include "core/storage.h"
#include "core/wallet.h"

/* --- What the firmware gets from its storage, settings and wallet pages --- */
esp_err_t storage_save_descriptor(storage_location_t loc, const char *id, const uint8_t *data,
                                  size_t len, storage_descriptor_format_t format) {
  (void)loc; (void)id; (void)data; (void)len; (void)format;
  return ESP_OK;
}
esp_err_t storage_delete_descriptor(storage_location_t loc, const char *filename) {
  (void)loc; (void)filename;
  return ESP_OK;
}
esp_err_t storage_list_descriptors(storage_location_t loc, char ***filenames_out, int *count_out) {
  (void)loc;
  if (filenames_out) *filenames_out = NULL;
  if (count_out) *count_out = 0;
  return ESP_OK;
}
esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename, uint8_t **data_out,
                                  size_t *len_out, storage_descriptor_format_t *format_out) {
  (void)loc; (void)filename;
  if (data_out) *data_out = NULL;
  if (len_out) *len_out = 0;
  if (format_out) *format_out = STORAGE_DESCRIPTOR_TXT;
  return -1;
}
void storage_free_file_list(char **files, int count) { (void)files; (void)count; }

static bool g_testnet = false;
wallet_network_t wallet_get_network(void) {
  return g_testnet ? WALLET_NETWORK_TESTNET : WALLET_NETWORK_MAINNET;
}

/* Default settings: no permissive signing, no expected-owned signing, no partial signing. */
bool settings_get_permissive_signing(void) { return false; }

/* psbt.c is linked against key.c compiled with key_get_fingerprint renamed (the unit tests
 * replace it); here the real one is what is wanted. */
extern bool key_get_fingerprint_raw(unsigned char *fingerprint_out);
bool key_get_fingerprint(unsigned char *fp) { return key_get_fingerprint_raw(fp); }

/* --- output --- */
static void emit(const char *outcome, const char *reason, const char *psbt_b64) {
  printf("{\"outcome\":\"%s\",\"reason\":\"%s\"", outcome, reason ? reason : "");
  if (psbt_b64) printf(",\"psbt\":\"%s\"", psbt_b64);
  printf("}\n");
  fflush(stdout);
}

static void refuse(const char *reason) { emit("refused", reason, NULL); exit(0); }

static const char *gate_name(psbt_gate_t g) {
  switch (g) {
  case PSBT_GATE_NOTHING_SIGNABLE: return "gate: nothing signable";
  case PSBT_GATE_UNBUILDABLE_TX: return "gate: transaction cannot be built";
  case PSBT_GATE_UNSHOWABLE_OUTPUT: return "gate: an output cannot be shown";
  case PSBT_GATE_UNSUPPORTED_SIGHASH: return "gate: unsupported sighash";
  case PSBT_GATE_INVALID_AMOUNT: return "gate: invalid input amount";
  case PSBT_GATE_UNSUMMABLE_OUTPUTS: return "gate: outputs cannot be summed";
  case PSBT_GATE_IMPOSSIBLE_FEE: return "gate: impossible fee";
  case PSBT_GATE_TAPROOT_MISSING_AMOUNT: return "gate: taproot input amount missing";
  case PSBT_GATE_EXPECTED_OWNED: return "gate: input expected to be ours but unverifiable";
  case PSBT_GATE_PERMISSIVE: return "gate: non-standard derivation path";
  case PSBT_GATE_PARTIAL: return "gate: inputs of other signers (partial signing off)";
  default: return "gate: refused";
  }
}

/* Classify every input and output and run the pre-review gate. Returns the gate result. */
static psbt_gate_t classify_and_gate(struct wally_psbt *psbt) {
  psbt_gate_t gate = PSBT_GATE_NOTHING_SIGNABLE;
  input_ownership_t *inputs = calloc(psbt->num_inputs ? psbt->num_inputs : 1, sizeof(*inputs));
  output_ownership_t *outputs = calloc(psbt->num_outputs ? psbt->num_outputs : 1, sizeof(*outputs));
  psbt_gate_settings_t settings = {.expected_owned = false, .permissive = false, .partial = false};
  psbt_gate_report_t report;
  memset(&report, 0, sizeof(report));
  if (inputs && outputs) {
    for (size_t i = 0; i < psbt->num_inputs; i++)
      inputs[i] = psbt_classify_input(psbt, i, g_testnet);
    for (size_t i = 0; i < psbt->num_outputs; i++)
      outputs[i] = psbt_classify_output(psbt, i, g_testnet);
    gate = psbt_gate_check(psbt, inputs, outputs, &settings, &report);
  }
  free(inputs);
  free(outputs);
  return gate;
}

static bool read_line(char *buf, size_t cap) {
  if (!fgets(buf, (int)cap, stdin)) return false;
  size_t n = strlen(buf);
  while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
  return true;
}

int main(void) {
  static char mnemonic[512], net[8], b64[1 << 22];
  if (!read_line(mnemonic, sizeof(mnemonic)) || !read_line(net, sizeof(net)) ||
      !read_line(b64, sizeof(b64))) {
    emit("crashed", "harness input incomplete", NULL);
    return 2;
  }
  g_testnet = net[0] == '1';
  if (!crypto_init()) {
    emit("crashed", "crypto_init failed", NULL);
    return 2;
  }
  if (!key_load_from_mnemonic(mnemonic, "", g_testnet)) {
    emit("crashed", "could not load the mnemonic", NULL);
    return 2;
  }

  size_t cap = strlen(b64), len = 0;
  unsigned char *data = malloc(cap + 1);
  if (!data || wally_base64_to_bytes(b64, 0, data, cap + 1, &len) != WALLY_OK) refuse("not base64");

  struct wally_psbt *psbt = NULL;
  psbt_parse_result_t parsed = psbt_parse_payload_result(data, len, &psbt);
  free(data);
  if (parsed == PSBT_PARSE_SP_SIGHASH)
    refuse("silent payment outputs beside a sighash other than ALL");
  if (parsed != PSBT_PARSE_OK || !psbt) refuse("Invalid PSBT data");

  psbt_gate_t gate = classify_and_gate(psbt);
  if (gate != PSBT_GATE_ALLOW) refuse(gate_name(gate));

  if (sp_psbt_has_fields(psbt)) {
    sp_psbt_result_t r = sp_psbt_complete(&psbt, g_testnet);
    if (r == SP_PSBT_PENDING) refuse("pending: a silent payment script waits for another signer");
    if (r != SP_PSBT_OK) refuse(sp_psbt_result_message(r));
    gate = classify_and_gate(psbt);
    if (gate != PSBT_GATE_ALLOW) refuse(gate_name(gate));
  }

  psbt_sign_policy_t policy = {.allow_unsafe = false, .allow_expected_owned = false};
  psbt_sign_result_t result;
  memset(&result, 0, sizeof(result));
  size_t added = psbt_sign(psbt, g_testnet, policy, &result);
  if (added == 0 || result.signed_ok == 0) refuse("no input was signed");
  if (result.signed_ok < result.attempted)
    refuse("an input the policy cleared could not be signed");

  /* Export as the firmware does: trimmed, falling back to the whole PSBT. */
  struct wally_psbt *trimmed = psbt_trim(psbt);
  char *out = NULL;
  bool ok = sp_psbt_base64_alloc(trimmed ? trimmed : psbt, &out);
  if (!ok || !out) {
    emit("crashed", "could not encode the signed PSBT", NULL);
    return 2;
  }
  emit("signed", "", out);
  return 0;
}
