/*******************************************************************************
*   (c) 2018, 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
// Integration tests

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

#[macro_use]
extern crate lazy_static;
extern crate ledger_filecoin;
#[macro_use]
extern crate matches;
extern crate secp256k1;
extern crate sha2;

use std::sync::Mutex;

use blake2b_simd::Params;
use ledger_filecoin::utils::{from_hex_string, to_hex_string};
use ledger_filecoin::{BIP44Path, Error, FilecoinApp};

lazy_static! {
    static ref APP: Mutex<FilecoinApp> = Mutex::new(FilecoinApp::connect().unwrap());
}

#[test]
fn version() {
    let mut error_detected = false;
    {
        let app = APP.lock().unwrap();

        let resp = app.version();

        match resp {
            Ok(version) => {
                println!("mode  {}", version.mode);
                println!("major {}", version.major);
                println!("minor {}", version.minor);
                println!("patch {}", version.patch);

                assert_eq!(version.major, 0x00);
                assert!(version.minor >= 0x0a);
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                error_detected = true;
            }
        }
    }
    assert!(!error_detected);
}

#[test]
fn address() {
    let mut error_detected = false;
    {
        let app = APP.lock().unwrap();
        let path = BIP44Path {
            purpose: 44,
            coin: 461,
            account: 0,
            change: 0,
            index: 0,
        };
        let resp = app.address(&path, false);

        match resp {
            Ok(addr) => {
                assert_eq!(
                    to_hex_string(&addr.public_key.serialize()),
                    "0235e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795"
                );
                assert_eq!(
                    to_hex_string(&addr.addr_byte),
                    "011eaf1c8a4bbfeeb0870b1745b1f57503470b7116"
                );
                assert_eq!(
                    addr.addr_string,
                    "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
                );

                println!(
                    "Public Key  {:?}",
                    to_hex_string(&addr.public_key.serialize())
                );
                println!("Address Byte Format  {:?}", to_hex_string(&addr.addr_byte));
                println!("Address String Format  {:?}", addr.addr_string);
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                error_detected = true;
            }
        }
    }
    assert!(!error_detected);
}

#[test]
fn address_testnet() {
    let mut error_detected = false;
    {
        let app = APP.lock().unwrap();
        let path = BIP44Path {
            purpose: 44,
            coin: 1,
            account: 0,
            change: 0,
            index: 0,
        };
        let resp = app.address(&path, false);

        match resp {
            Ok(addr) => {
                assert_eq!(
                    to_hex_string(&addr.public_key.serialize()),
                    "0266f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b"
                );
                assert_eq!(
                    to_hex_string(&addr.addr_byte),
                    "01dfe49184d46adc8f89d44638beb45f78fcad2590"
                );
                assert_eq!(
                    addr.addr_string,
                    "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"
                );

                println!(
                    "Public Key  {:?}",
                    to_hex_string(&addr.public_key.serialize())
                );
                println!("Address Byte Format  {:?}", to_hex_string(&addr.addr_byte));
                println!("Address String Format  {:?}", addr.addr_string);
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                error_detected = true;
            }
        }
    }
    assert!(!error_detected);
}

#[test]
fn sign_empty() {
    let app = APP.lock().unwrap();

    let path = BIP44Path {
        purpose: 44,
        coin: 1,
        account: 0,
        change: 0,
        index: 0,
    };
    let some_message0 = b"";
    let signature = app.sign(&path, some_message0);
    assert!(signature.is_err());
    assert!(matches!(
            signature.err().unwrap(),
            Error::InvalidEmptyMessage
        ));
}

#[test]
fn sign_verify() {
    let mut error_detected = false;
    {
        let app = APP.lock().unwrap();

        let txstr = "885501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C6285501B882619D46558F3D9E316D11B48DCF211327025A0144000186A0430009C4430061A80040";
        let blob = from_hex_string(txstr).unwrap();

        let path = BIP44Path {
            purpose: 44,
            coin: 461,
            account: 0,
            change: 0,
            index: 0,
        };
        match app.sign(&path, &blob) {
            Ok(signature) => {
                println!("{:#?}", to_hex_string(&signature.sig.serialize_compact()));

                // First, get public key
                let addr = app.address(&path, false).unwrap();

                let message_hashed = Params::new()
                    .hash_length(32)
                    .to_state()
                    .update(&blob)
                    .finalize();

                println!("Message hashed {}", &message_hashed.to_hex());

                let cid = from_hex_string("0171a0e40220").unwrap();
                let cid_hashed = Params::new()
                    .hash_length(32)
                    .to_state()
                    .update(&cid)
                    .update(message_hashed.as_bytes())
                    .finalize();

                println!("Cid hashed {}", &cid_hashed.to_hex());

                let message = secp256k1::Message::from_slice(cid_hashed.as_bytes()).expect("32 bytes");

                // Verify signature
                let secp = secp256k1::Secp256k1::new();
                assert!(secp
                    .verify(&message, &signature.sig, &addr.public_key)
                    .is_ok());
            }
            Err(e) => {
                println!("Err {:#?}", e);
                error_detected = true;
            }
        }
    }
    assert!(!error_detected);
}
