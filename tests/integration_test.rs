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

extern crate ledger_filecoin;

use blake2::{digest::typenum, Blake2b, Digest};
use ecdsa::{signature::Verifier, VerifyingKey};
use k256::{elliptic_curve::sec1::ToEncodedPoint, Secp256k1};

use ledger_filecoin::{BIP44Path, FilError, FilecoinApp, LedgerAppError};
use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};

use once_cell::sync::Lazy;
use serial_test::serial;

static HIDAPI: Lazy<HidApi> = Lazy::new(|| HidApi::new().expect("Failed to create Hidapi"));

type Blake2b256 = Blake2b<typenum::U32>;

fn app() -> FilecoinApp<TransportNativeHID> {
    FilecoinApp::new(TransportNativeHID::new(&HIDAPI).expect("unable to create transport"))
}

#[tokio::test]
#[serial]
async fn version() {
    let app = app();

    let version = app.version().await.unwrap();

    println!("mode  {}", version.mode);
    println!("major {}", version.major);
    println!("minor {}", version.minor);
    println!("patch {}", version.patch);

    assert_eq!(version.major, 0x00);
    assert!(version.minor >= 0x12);
}

#[tokio::test]
#[serial]
async fn address() {
    let app = app();
    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 461,
        account: 0,
        change: 0,
        index: 0,
    };

    let addr = app.address(&path, false).await.unwrap();

    let public_key_bytes = addr.public_key.to_encoded_point(true);

    assert_eq!(
        hex::encode(&public_key_bytes),
        "0235e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795"
    );
    assert_eq!(
        hex::encode(&addr.addr_byte),
        "011eaf1c8a4bbfeeb0870b1745b1f57503470b7116"
    );
    assert_eq!(
        addr.addr_string,
        "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
    );

    println!("Public Key  {:?}", hex::encode(&public_key_bytes));
    println!("Address Byte Format  {:?}", hex::encode(&addr.addr_byte));
    println!("Address String Format  {:?}", addr.addr_string);
}

#[tokio::test]
#[serial]
async fn address_testnet() {
    let app = app();
    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 1,
        account: 0,
        change: 0,
        index: 0,
    };

    let addr = app.address(&path, false).await.unwrap();

    let public_key_bytes = addr.public_key.to_encoded_point(true);

    assert_eq!(
        hex::encode(&public_key_bytes),
        "0266f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b"
    );
    assert_eq!(
        hex::encode(&addr.addr_byte),
        "01dfe49184d46adc8f89d44638beb45f78fcad2590"
    );
    assert_eq!(
        addr.addr_string,
        "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"
    );

    println!("Public Key  {:?}", hex::encode(&public_key_bytes));
    println!("Address Byte Format  {:?}", hex::encode(&addr.addr_byte));
    println!("Address String Format  {:?}", addr.addr_string);
}

#[tokio::test]
#[serial]
async fn sign_empty() {
    let app = app();

    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 1,
        account: 0,
        change: 0,
        index: 0,
    };
    let some_message0 = b"";
    let signature = app.sign(&path, some_message0).await;
    assert!(signature.is_err());
    assert!(matches!(
        signature.err().unwrap(),
        FilError::Ledger(LedgerAppError::InvalidEmptyMessage)
    ));
}

#[tokio::test]
#[serial]
async fn sign_verify() {
    let app = app();

    let txstr = "8a0058310396a1a3e4ea7a14d49985e661b22401d44fed402d1d0925b243c923589c0fbc7e32cd04e29ed78d15d37d3aaa3fe6da3358310386b454258c589475f7d16f5aac018a79f6c1169d20fc33921dd8b5ce1cac6c348f90a3603624f6aeb91b64518c2e80950144000186a01961a8430009c44200000040";
    let blob = hex::decode(txstr).unwrap();

    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 461,
        account: 0,
        change: 0,
        index: 0,
    };

    // First, get public key
    let addr = app.address(&path, false).await.unwrap();

    let signature = app.sign(&path, &blob).await.unwrap();
    println!("{:#?}", hex::encode(&signature.sig.to_vec()));

    let mut blake2b = Blake2b256::new();
    blake2b.update(&blob);

    let message_hashed = blake2b.finalize_reset();
    println!("Message hashed {}", hex::encode(&message_hashed));

    let cid = hex::decode("0171a0e40220").unwrap();
    blake2b.update(&cid);
    blake2b.update(&message_hashed);

    let cid_hashed = blake2b.clone().finalize();
    println!("Cid hashed {}", hex::encode(&cid_hashed));

    let verifying_key =
        VerifyingKey::<Secp256k1>::from_encoded_point(&addr.public_key.to_encoded_point(true))
            .unwrap();
    assert!(verifying_key
        .verify(&blake2b.finalize(), &signature.sig)
        .is_ok())
}
