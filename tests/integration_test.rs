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
//! Integration tests for the ledger-filecoin crate

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

extern crate ledger_filecoin;

use blake2::{digest::typenum, Blake2b, Digest};
use ecdsa::VerifyingKey;
use k256::{
    ecdsa::{signature::DigestVerifier, Signature},
    elliptic_curve::sec1::ToEncodedPoint,
};

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

    assert!(
        version.major != 0 || version.minor != 0 || version.patch != 0,
        "major, minor, and patch are all zero; version not set correctly (got: {}.{}.{})",
        version.major,
        version.minor,
        version.patch
    );
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

    // Step 1: Hash the message
    let mut blake2b = Blake2b256::new();
    blake2b.update(&blob);
    let message_hashed = blake2b.finalize();
    println!("Message hashed {}", hex::encode(&message_hashed));

    // Step 2: Create CID = CID_PREFIX + message_hash
    let cid_prefix = hex::decode("0171a0e40220").unwrap();
    let mut cid = Vec::new();
    cid.extend_from_slice(&cid_prefix);
    cid.extend_from_slice(&message_hashed);
    println!("CID {}", hex::encode(&cid));

    // Step 3: Hash the CID to get the final digest
    let mut blake2b_for_verify = Blake2b256::new();
    blake2b_for_verify.update(&cid);

    let verifying_key =
        VerifyingKey::from_encoded_point(&addr.public_key.to_encoded_point(true)).unwrap();

    // Test that we can perform signature verification (result may vary based on hardware setup)
    let verification_result = verifying_key.verify_digest(blake2b_for_verify, &signature.sig);
    println!("Signature verification result: {:?}", verification_result);
    assert!(verification_result.is_ok(), "Signature verification failed");
}

#[tokio::test]
#[serial]
async fn sign_raw_bytes() {
    let app = app();

    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 461,
        account: 0,
        change: 0,
        index: 0,
    };

    // First, get public key for verification
    let addr = app.address(&path, false).await.unwrap();

    let txstr = "ab11c412ff5f6fafc466e856f67eb20ad85ef754ad1b7c5d4120ffe95dcd94bd1079f1a89a575d284422825f1aaeb099439bc60e6537e3c939a3a5f0e108d372be73d388da351c11bfc5a20a316051fcd52b4a6d003cd1eef171ba197cfbf8d245f705d65ee0c82fa74e4d3ee1f918a496a0244fb342b7ea0a836e522ba3519001866edde3207af56ad45177433ceb0290e0b55e0584b4c799a7646805d50e885e95e89209d5b223d82001be1c85c881ec6c5bd21bcfceb286c12fdc1f28feaaaa13853655c24f6ef5c640c222ba8ed161718d535786867481fb96bc1720be4b63438d72ba559cb0c72485d1fb6543bc6c684d358aa7cfc1877031600c6efb0f90e5224951205e276cbbd3876953e92a522e26d22a75b0417b2971866a839c03825df7e06de380e00ba7599c59a01165a0ac95d636cc63d09f095df058a273aa4067e9dbeeb7d28ba62519c34c485c9389a485d90f6c47698260fc43b5d2fb88794c34f129fd2861a310c74238f12cd7c84b4f8df19faf05a0756e8b5261b48ee45929f9cfc33c8cedb69029af312a544b216ea8fc33a10cd7188d58591c8a22b2ee3ab6816fe45e080c4f1733ea2a71627cbc90133cecd8eae635e0d522731ee1992a09f411a424bc48ae54cfebcdb442d34ef8e42b1cd9212fdda322baed3569437e1106b67a25d064b0d96a1150a4ea866e4849eb646574a5e3c0d4d6efca09eef7feaf540a6eda9c886d92018b2afbf64d9c077c83f23f45529f826a51b575432c6fa0c7849799c3e9ba5a0f4d71b93a12b72a9d06238c686561cd952a2a50e2c516f3fc1b60e94365dbc883a8a47a0214a6df74390c9963836e6d1099bc16da0a6caf07f0962b945ef225930bd6131fe344ff7fcac9f0181a0a24940146b03b79a3de67b92fe592183258e939685d47089e6f9228b169952aabb45f3ad369b1d557099ce97b6092f2e0bd6122c2479fed1a2427c8fd763a93587795f38a391782b0dadf857a3a8d896940c94cef4183d3ff52f26af4957736955db70d668f524285d091313ffc9b807e0502edc6fbc3f1d6e76350a0c3d78fc6cdc6ae36bd2b9dccb3b4e7734c8d91a2c883390953429fd9dd185a81bfa3ac147d86342ac3b227eff6ac0c2904596076b845a3267b1b472e8bbb429575fb280ec82718734ceb2b07e8c998b42cad224c98cc56aa5ca3a9159e8bf3604f4f56b2350befc00cca8e1a1aecb3dbb64c9536ec557204dfd3ee68ee16b641c41e75c4f97266ed4c5f78b5f8fd7ff11eb8c5db201f85b3904f13931bbead263a00e85d1086340bb4a2fb6fd139b793d4a7540b3dbf2495f7d08f8821759bde65817aa08fa1424101639fbfb6c4f91961da1372bccb127afc627d352f9d9d2faa5a9176be55274b53dc04b94174b6b7aa52955939cf14970d31e03ea60cb2cdc99e422f232a4052";
    let blob = hex::decode(txstr).unwrap();

    // Construct the blob message as [prefix, blob]
    let prefix = b"Filecoin Sign Bytes:\n";
    let mut message = prefix.to_vec();
    message.extend_from_slice(&blob);

    let signature = app.sign_raw_bytes(&path, &message).await.unwrap();
    println!(
        "Raw bytes signature: {:#?}",
        hex::encode(&signature.sig.to_vec())
    );

    // Step 1: Hash the message
    let mut blake2b = Blake2b256::new();
    blake2b.update(&message);
    let message_hashed = blake2b.finalize();
    println!("Message hashed {}", hex::encode(&message_hashed));

    // Step 2: Create CID = CID_PREFIX + message_hash
    let cid_prefix = hex::decode("0171a0e40220").unwrap();
    let mut cid = Vec::new();
    cid.extend_from_slice(&cid_prefix);
    cid.extend_from_slice(&message_hashed);
    println!("CID {}", hex::encode(&cid));

    // Step 3: Hash the CID to get the final digest
    let mut blake2b_for_verify = Blake2b256::new();
    blake2b_for_verify.update(&cid);

    let verifying_key =
        VerifyingKey::from_encoded_point(&addr.public_key.to_encoded_point(true)).unwrap();

    // Test that we can perform signature verification (result may vary based on hardware setup)
    let verification_result = verifying_key.verify_digest(blake2b_for_verify, &signature.sig);
    println!("Signature verification result: {:?}", verification_result);
    assert!(verification_result.is_ok(), "Signature verification failed");
}

#[tokio::test]
#[serial]
async fn sign_personal_msg() {
    let app = app();

    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 461,
        account: 0,
        change: 0,
        index: 0,
    };

    // Test personal message
    let personal_message = b"Hello World!";

    // First, get public key for verification
    let addr = app.address(&path, false).await.unwrap();

    let signature = app
        .sign_personal_msg(&path, personal_message)
        .await
        .unwrap();

    let prefix = b"\x19Filecoin Signed Message:\n";
    let length_bytes = (personal_message.len() as u32).to_be_bytes();

    let mut message_with_prefix = Vec::new();
    message_with_prefix.extend_from_slice(prefix);
    message_with_prefix.extend_from_slice(&length_bytes);
    message_with_prefix.extend_from_slice(personal_message);

    let mut reconstructed_sig_bytes = [0u8; 64];
    reconstructed_sig_bytes[0..32].copy_from_slice(&signature.r);
    reconstructed_sig_bytes[32..64].copy_from_slice(&signature.s);
    let reconstructed_signature = Signature::from_bytes((&reconstructed_sig_bytes).into()).unwrap();

    // Create verifying key from the public key
    let verifying_key =
        VerifyingKey::from_encoded_point(&addr.public_key.to_encoded_point(true)).unwrap();

    // Verify the signature using the same pre-hash Blake2b-256 (avoiding double SHA-256)
    let mut blake2b_for_verify = Blake2b256::new();
    blake2b_for_verify.update(&message_with_prefix);
    let reconstructed_verification =
        verifying_key.verify_digest(blake2b_for_verify, &reconstructed_signature);
    println!(
        "Signature verification result: {:?}",
        reconstructed_verification
    );
    assert!(
        reconstructed_verification.is_ok(),
        "Signature verification failed"
    );
}

#[tokio::test]
#[serial]
async fn sign_personal_msg_long_message() {
    let app = app();

    let path = BIP44Path {
        purpose: 0x8000_0000 | 44,
        coin: 0x8000_0000 | 461,
        account: 0,
        change: 0,
        index: 0,
    };

    // Generate random personal message
    use rand::{rng, RngCore};
    let mut personal_message = [0u8; 300];
    let mut rng = rng();
    rng.fill_bytes(&mut personal_message);

    // First, get public key for verification
    let addr = app.address(&path, false).await.unwrap();

    let signature = app
        .sign_personal_msg(&path, &personal_message)
        .await
        .unwrap();

    let prefix = b"\x19Filecoin Signed Message:\n";
    let length_bytes = (personal_message.len() as u32).to_be_bytes();

    let mut message_with_prefix = Vec::new();
    message_with_prefix.extend_from_slice(prefix);
    message_with_prefix.extend_from_slice(&length_bytes);
    message_with_prefix.extend_from_slice(&personal_message);

    let mut reconstructed_sig_bytes = [0u8; 64];
    reconstructed_sig_bytes[0..32].copy_from_slice(&signature.r);
    reconstructed_sig_bytes[32..64].copy_from_slice(&signature.s);
    let reconstructed_signature = Signature::from_bytes((&reconstructed_sig_bytes).into()).unwrap();

    // Create verifying key from the public key
    let verifying_key =
        VerifyingKey::from_encoded_point(&addr.public_key.to_encoded_point(true)).unwrap();

    // Verify the signature using the same pre-hash Blake2b-256 (avoiding double SHA-256)
    let mut blake2b_for_verify = Blake2b256::new();
    blake2b_for_verify.update(&message_with_prefix);
    let reconstructed_verification =
        verifying_key.verify_digest(blake2b_for_verify, &reconstructed_signature);
    println!(
        "Signature verification result: {:?}",
        reconstructed_verification
    );
    assert!(
        reconstructed_verification.is_ok(),
        "Signature verification failed"
    );
}
