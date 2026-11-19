// SilentWitness harness for the BitBox02 simulator.
//
// Lives inside a checkout of bitbox-api-rs that has tools/bitbox02_spike/sp-spike.patch applied:
// CI copies this file to examples/sw_harness.rs and builds it there (see
// .github/workflows/bitbox02.yml). It needs `btc_sign_psbt_sp` from that patch.
//
// Reads one JSON request on stdin, connects to a simulator already listening on 127.0.0.1:15423,
// restores the simulator's fixed mnemonic, signs, and prints one JSON response on stdout:
//
//   request:  {"psbt_hex": "<PSBT v0>", "sp_outputs": {"<index>": "<sp1 address>"}, "coin": "btc"}
//   response: {"outcome": "signed", "inputs": [{"partial_sigs": [[pubkey, sig]],
//              "tap_key_sig": null}], "generated": [{"index": 0, "pkscript": "..",
//              "dleq_proof": ".."}]}
//          or {"outcome": "refused" | "skipped" | "crashed", "reason": "..."}
//
// "refused" is the device saying no. "skipped" is bitbox-api (the host library) being unable to
// express the case. Anything else is "crashed". Test keys only: the simulator's mnemonic is public.

use std::collections::BTreeMap;
use std::io::Read;

use bitbox_api::error::Error;
use bitbox_api::runtime::TokioRuntime;
use bitbox_api::{pb, BitBox, NoiseConfigNoCache};
use serde_json::{json, Value};

fn respond(value: Value) {
    println!("{value}");
}

fn classify(e: &Error) -> (&'static str, String) {
    match e {
        // The firmware answered with an error: it refused.
        Error::BitBox(b) => ("refused", format!("{b}")),
        // The host library could not build or accept the request: not the device's decision.
        Error::Psbt(_) | Error::BtcSign(_) | Error::Version(_) | Error::KeypathParse(_) => {
            ("skipped", format!("{e}"))
        }
        _ => ("crashed", format!("{e}")),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read request");
    let req: Value = serde_json::from_str(&input).expect("request is JSON");

    let psbt_bytes = hex::decode(req["psbt_hex"].as_str().expect("psbt_hex")).expect("hex");
    let mut psbt = match bitcoin::psbt::Psbt::deserialize(&psbt_bytes) {
        Ok(p) => p,
        Err(e) => {
            return respond(json!({"outcome": "skipped", "reason": format!("PSBT v0: {e}")}));
        }
    };
    let mut sp_outputs: BTreeMap<usize, String> = BTreeMap::new();
    for (idx, addr) in req["sp_outputs"].as_object().expect("sp_outputs") {
        sp_outputs.insert(
            idx.parse().expect("output index"),
            addr.as_str().unwrap().into(),
        );
    }
    let coin = match req["coin"].as_str().unwrap_or("btc") {
        "btc" => pb::BtcCoin::Btc,
        "tbtc" => pb::BtcCoin::Tbtc,
        other => panic!("unsupported coin {other}"),
    };

    // The simulator may take a few seconds to start listening.
    let mut connected = None;
    for _ in 0..20 {
        if let Ok(b) =
            BitBox::<TokioRuntime>::from_simulator(None, Box::new(NoiseConfigNoCache {})).await
        {
            connected = Some(b);
            break;
        }
    }
    let bitbox = connected.expect("simulator did not accept a connection");
    let bitbox = bitbox
        .unlock_and_pair()
        .await
        .expect("unlock and pair")
        .wait_confirm()
        .await
        .expect("confirm pairing");
    bitbox
        .restore_from_mnemonic()
        .await
        .expect("restore the simulator mnemonic");

    let result = bitbox
        .btc_sign_psbt_sp(
            coin,
            &mut psbt,
            None,
            pb::btc_sign_init_request::FormatUnit::Default,
            &sp_outputs,
        )
        .await;

    match result {
        Ok(generated) => {
            let inputs: Vec<Value> = psbt
                .inputs
                .iter()
                .map(|i| {
                    let partial: Vec<Value> = i
                        .partial_sigs
                        .iter()
                        .map(|(pk, sig)| {
                            json!([hex::encode(pk.to_bytes()), hex::encode(sig.serialize())])
                        })
                        .collect();
                    json!({
                        "partial_sigs": partial,
                        "tap_key_sig": i.tap_key_sig.map(|s| hex::encode(s.serialize())),
                    })
                })
                .collect();
            let generated: Vec<Value> = generated
                .iter()
                .map(|g| {
                    json!({
                        "index": g.output_index,
                        "pkscript": hex::encode(&g.pkscript),
                        "dleq_proof": hex::encode(&g.dleq_proof),
                    })
                })
                .collect();
            respond(json!({"outcome": "signed", "inputs": inputs, "generated": generated}));
        }
        Err(e) => {
            let (outcome, reason) = classify(&e);
            respond(json!({"outcome": outcome, "reason": reason}));
        }
    }
}
