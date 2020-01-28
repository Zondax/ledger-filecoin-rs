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

use ledger_filecoin::utils::{from_hex_string, to_hex_string};
use ledger_filecoin::{BIP44Path, Error, FilecoinApp};
use blake2b_simd::Params;

lazy_static! {
    static ref APP: Mutex<FilecoinApp> = Mutex::new(FilecoinApp::connect().unwrap());
}

#[test]
fn version() {
    let app = APP.lock().unwrap();

    let resp = app.version();

    match resp {
        Ok(version) => {
            println!("mode  {}", version.mode);
            println!("major {}", version.major);
            println!("minor {}", version.minor);
            println!("patch {}", version.patch);

            assert_eq!(version.major, 0x00);
            assert!(version.minor >= 0x04);
        }
        Err(err) => {
            eprintln!("Error: {:?}", err);
        }
    }
}

#[test]
fn address() {
    let app = APP.lock().unwrap();
    let path = BIP44Path {
        purpose: 44,
        coin: 461,
        account: 0,
        change: 0,
        index: 5,
    };
    let resp = app.address(&path, false);

    match resp {
        Ok(addr) => {
            assert_eq!(
                to_hex_string(&addr.public_key.serialize()),
                "0320316dba4ab1c0eb296467d69c32c6395af0cbc304e46f33e6929e9e6870bc3b"
            );
            assert_eq!(
                to_hex_string(&addr.addr_byte),
                "015ef7a0ab9bf25ca47e0e4e04ab311bd5c1ac8de4"
            );
            assert_eq!(
                addr.addr_string,
                "f1l332bk436joki7qojyckwmi32xa2zdpesvuitoi"
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
            assert!(false);
        }
    }
}

#[test]
fn address_testnet() {
    let app = APP.lock().unwrap();
    let path = BIP44Path {
        purpose: 44,
        coin: 1,
        account: 0,
        change: 0,
        index: 5,
    };
    let resp = app.address(&path, false);

    match resp {
        Ok(addr) => {
            assert_eq!(
                to_hex_string(&addr.public_key.serialize()),
                "033fc5ccea9872313b75fec78704b27420de29dd3db298a562559f90f332059465"
            );
            assert_eq!(
                to_hex_string(&addr.addr_byte),
                "010da3da04b90cad27a181be8c0a658066a4e5988c"
            );
            assert_eq!(
                addr.addr_string,
                "t1bwr5ubfzbswspimbx2gauzmam2solgemalycbmi"
            );

            println!(
                "Public Key {:?}",
                to_hex_string(&addr.public_key.serialize())
            );
            println!("Address Byte Format {:?}", to_hex_string(&addr.addr_byte));
            println!("Address String Format {:?}", addr.addr_string);
        }
        Err(err) => {
            eprintln!("Error: {:?}", err);
            assert!(false);
        }
    }
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
            assert!(secp.verify(&message, &signature.sig, &addr.public_key).is_ok());
        }
        Err(e) => {
            println!("Err {:#?}", e);
            assert!(false);
        }
    }
}
