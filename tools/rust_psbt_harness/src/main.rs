//! One case in, one verdict out: reads a JSON request on stdin, runs the psbt-v2 Signer
//! role on it, and prints a JSON response. It makes no pass/fail decision; the judge does.
//!
//! Request:  {"psbt": "<base64 v2 PSBT>", "input_keys": {"0": "<privkey hex>"},
//!            "output_scripts": {"1": "<spk hex>"}}
//! Response: {"outcome": "signed"|"refused", "reason": "...", "psbt": "<base64>"|null}
//!
//! psbt-v2 does not verify DLEQ proofs or derive BIP-352 scripts; the caller does. So
//! `output_scripts` are supplied by SilentWitness (computed outside this crate). The PSBT is
//! checked as sent before they are committed, so a rule like "modifiable flags must be clear
//! once scripts are set" is judged on the host's PSBT, not on one this harness repaired. A script
//! the host already set that differs from the derived one is refused by the commit.

use std::collections::BTreeMap;
use std::io::Read;
use std::str::FromStr;

use psbt_v2::bitcoin::bip32::Xpriv;
use psbt_v2::bitcoin::hex::FromHex;
use psbt_v2::bitcoin::secp256k1::{Secp256k1, Signing};
use psbt_v2::bitcoin::{Network, PrivateKey, PublicKey, ScriptBuf};
use psbt_v2::{GetKey, GetKeyError, KeyRequest, Psbt, Signer};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    psbt: String,
    #[serde(default)]
    input_keys: BTreeMap<usize, String>,
    #[serde(default)]
    output_scripts: BTreeMap<usize, String>,
    /// BIP-39 seed (hex) the signer holds, used for inputs that name a BIP-32 derivation.
    #[serde(default)]
    seed_hex: Option<String>,
}

/// Raw keys for requests by public key, the seed's master key for requests by derivation path.
struct Keys {
    by_pubkey: BTreeMap<PublicKey, PrivateKey>,
    master: Option<Xpriv>,
}

impl GetKey for Keys {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match request {
            KeyRequest::Bip32(_) => match &self.master {
                Some(master) => master.get_key(request, secp),
                None => Ok(None),
            },
            _ => self.by_pubkey.get_key(request, secp),
        }
    }
}

#[derive(Serialize)]
struct Response {
    outcome: &'static str,
    reason: String,
    psbt: Option<String>,
}

fn refused(reason: impl Into<String>) -> Response {
    Response {
        outcome: "refused",
        reason: reason.into(),
        psbt: None,
    }
}

fn run(req: Request) -> Response {
    let secp = Secp256k1::new();

    let mut key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();
    for hex in req.input_keys.values() {
        let Ok(bytes) = Vec::<u8>::from_hex(hex) else {
            return refused("harness: input key is not hex");
        };
        let Ok(key) = PrivateKey::from_slice(&bytes, Network::Regtest) else {
            return refused("harness: input key is not a valid secret key");
        };
        key_map.insert(key.public_key(&secp), key);
    }

    let master = match req.seed_hex.as_deref().map(Vec::<u8>::from_hex) {
        None => None,
        Some(Ok(seed)) => match Xpriv::new_master(Network::Regtest, &seed) {
            Ok(master) => Some(master),
            Err(_) => return refused("harness: seed is not usable"),
        },
        Some(Err(_)) => return refused("harness: seed is not hex"),
    };
    let keys = Keys {
        by_pubkey: key_map,
        master,
    };

    let mut psbt = match Psbt::from_str(&req.psbt) {
        Ok(psbt) => psbt,
        Err(e) => return refused(format!("ParsePsbtError: {e:?}")),
    };

    let has_sp = psbt.outputs.iter().any(|o| o.sp_v0_info.is_some());
    if has_sp && !req.output_scripts.is_empty() {
        let missing_script = psbt
            .outputs
            .iter()
            .any(|o| o.sp_v0_info.is_some() && o.script_pubkey.is_empty());
        // A PSBT that already carries every script is checked as sent first: committing
        // would clear the modifiable flags and hide a host that left them set.
        if !missing_script {
            if let Err(e) = psbt.silent_payment_signer_checks() {
                return refused(format!("SilentPaymentSignerError: {e:?}"));
            }
        }
        let mut scripts = Vec::new();
        for (index, hex) in &req.output_scripts {
            let Ok(bytes) = Vec::<u8>::from_hex(hex) else {
                return refused("harness: output script is not hex");
            };
            scripts.push((*index, ScriptBuf::from_bytes(bytes)));
        }
        // Supplying the scripts the caller derived also catches a host-set script that
        // differs (`ScriptMismatch`); the crate does not derive scripts itself.
        psbt = match psbt.commit_silent_payment_outputs(scripts) {
            Ok(psbt) => psbt,
            Err(e) => return refused(format!("CommitSilentPaymentOutputsError: {e:?}")),
        };
    }

    let resolved = match psbt.try_resolve() {
        Ok(resolved) => resolved,
        Err(e) => return refused(format!("DetermineLockTimeError: {e:?}")),
    };
    let mut signer = Signer::new(resolved);
    let sigs = signer.session(|mut session| match session.signable_inputs() {
        Ok(inputs) => Ok(session.get_all(&inputs, &keys, &secp)),
        Err(errors) => Err(errors),
    });
    let sigs = match sigs {
        Ok(sigs) => sigs,
        Err(errors) => {
            let first = errors
                .iter()
                .next()
                .map(|(i, e)| format!("input {i}: {e:?}"));
            return refused(format!("SignError: {}", first.unwrap_or_default()));
        }
    };
    let psbt = match signer.apply(sigs) {
        Ok(signer) => signer.psbt(),
        Err(e) => return refused(format!("SignError: {e:?}")),
    };

    let signed = psbt.inputs.iter().any(|i| {
        !i.partial_sigs.is_empty() || i.tap_key_sig.is_some() || !i.tap_script_sigs.is_empty()
    });
    if !signed {
        return refused("signer added no signatures");
    }
    Response {
        outcome: "signed",
        reason: String::new(),
        psbt: Some(psbt.to_string()),
    }
}

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(2);
    }
    let Ok(req) = serde_json::from_str::<Request>(&input) else {
        eprintln!("bad request");
        std::process::exit(2);
    };
    println!(
        "{}",
        serde_json::to_string(&run(req)).expect("response serializes")
    );
}
