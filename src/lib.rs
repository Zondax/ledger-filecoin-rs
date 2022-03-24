/*******************************************************************************
*   (c) 2020 ZondaX GmbH
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
//! Support library for Filecoin Ledger Nano S/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/ledger-filecoin/0.1.0")]

use ledger::ApduCommand;

mod params;
use params::{
    APDUErrors, PayloadType, CLA, INS_GET_ADDR_SECP256K1, INS_GET_VERSION, INS_SIGN_SECP256K1,
    USER_MESSAGE_CHUNK_SIZE,
};

use std::str;

/// Public Key Length
const PK_LEN: usize = 65;

/// Ledger App Error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid version error
    #[error("This version is not supported")]
    InvalidVersion,

    /// Invalid path
    #[error("Invalid path value (bigger than 0x8000_0000)")]
    InvalidPath,

    /// The message cannot be empty
    #[error("Message cannot be empty")]
    InvalidEmptyMessage,

    /// The size fo the message to sign is invalid
    #[error("message size is invalid (too big)")]
    InvalidMessageSize,

    /// Public Key is invalid
    #[error("received an invalid PK")]
    InvalidPK,

    /// No signature has been returned
    #[error("received no signature back")]
    NoSignature,

    /// The signature is not valid
    #[error("received an invalid signature")]
    InvalidSignature,

    /// The derivation is invalid
    #[error("invalid derivation path")]
    InvalidDerivationPath,

    /// Device related errors
    #[error("Ledger error: {0}")]
    Ledger(#[from] ledger::Error),

    /// Device related errors
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] k256::elliptic_curve::Error),

    /// Device related errors
    #[error("Ecdsa error: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),

    /// Utf8 conversion related error
    #[error("UTF8Error error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Filecoin App
pub struct FilecoinApp {
    app: ledger::LedgerApp,
}

unsafe impl Send for FilecoinApp {}

/// FilecoinApp address (includes pubkey and the corresponding ss58 address)
pub struct Address {
    /// Public Key
    pub public_key: k256::PublicKey,

    /// Address byte format
    pub addr_byte: [u8; 21],

    /// Address string format
    pub addr_string: String,
}

/// FilecoinApp signature (includes R, S, V and der format)
pub struct Signature {
    /// r value
    pub r: [u8; 32],

    /// s value
    pub s: [u8; 32],

    /// v value
    pub v: u8,

    /// der signature
    pub sig: k256::ecdsa::Signature,
}

/// FilecoinApp App Version
pub struct Version {
    /// Application Mode
    pub mode: u8,
    /// Version Major
    pub major: u8,
    /// Version Minor
    pub minor: u8,
    /// Version Patch
    pub patch: u8,
}

/// BIP44 Path
pub struct BIP44Path {
    /// Purpose
    pub purpose: u32,
    /// Coin
    pub coin: u32,
    /// Account
    pub account: u32,
    /// Change
    pub change: u32,
    /// Address Index
    pub index: u32,
}

fn serialize_bip44(path: &BIP44Path) -> Result<Vec<u8>, Error> {
    use byteorder::{LittleEndian, WriteBytesExt};
    let mut m = Vec::new();

    m.write_u32::<LittleEndian>(path.purpose).unwrap();
    m.write_u32::<LittleEndian>(path.coin).unwrap();
    m.write_u32::<LittleEndian>(path.account).unwrap();
    m.write_u32::<LittleEndian>(path.change).unwrap();
    m.write_u32::<LittleEndian>(path.index).unwrap();

    Ok(m)
}

impl FilecoinApp {
    /// Connect to the Ledger App
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(FilecoinApp { app })
    }

    /// Retrieve the app version
    pub fn version(&self) -> Result<Version, Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = self.app.exchange(command)?;
        if response.retcode != APDUErrors::NoError as u16 {
            return Err(Error::InvalidVersion);
        }

        if response.data.len() < 4 {
            return Err(Error::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        Ok(version)
    }

    /// Retrieves the public key and address
    pub fn address(&self, path: &BIP44Path, require_confirmation: bool) -> Result<Address, Error> {
        let serialized_path = serialize_bip44(path)?;
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_ADDR_SECP256K1,
            p1,
            p2: 0x00,
            length: 0,
            data: serialized_path,
        };

        match self.app.exchange(command) {
            Ok(response) => {
                if response.retcode != APDUErrors::NoError as u16 {
                    println!("WARNING: retcode={:X?}", response.retcode);
                }

                if response.data.len() < PK_LEN {
                    return Err(Error::InvalidPK);
                }

                let public_key = k256::PublicKey::from_sec1_bytes(&response.data[..PK_LEN])?;
                let mut addr_byte = [Default::default(); 21];
                addr_byte.copy_from_slice(&response.data[PK_LEN + 1..PK_LEN + 1 + 21]);
                let tmp = str::from_utf8(&response.data[PK_LEN + 2 + 21..])?;
                let addr_string = tmp.to_owned();

                let address = Address {
                    public_key,
                    addr_byte,
                    addr_string,
                };
                Ok(address)
            }
            Err(err) => Err(Error::Ledger(err)),
        }
    }

    /// Sign a transaction
    pub fn sign(&self, path: &BIP44Path, message: &[u8]) -> Result<Signature, Error> {
        let bip44path = serialize_bip44(path)?;
        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let packet_count = chunks.len() as u8;

        let _command = ApduCommand {
            cla: CLA,
            ins: INS_SIGN_SECP256K1,
            p1: PayloadType::Init as u8,
            p2: 0x00,
            length: bip44path.len() as u8,
            data: bip44path,
        };

        let mut response = self.app.exchange(_command)?;

        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            let mut p1 = PayloadType::Add as u8;
            if packet_idx == (packet_count - 1) as usize {
                p1 = PayloadType::Last as u8
            }

            let _command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_SECP256K1,
                p1,
                p2: 0,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = self.app.exchange(_command)?;
        }

        if response.data.is_empty() && response.retcode == APDUErrors::NoError as u16 {
            return Err(Error::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() < 3 {
            return Err(Error::InvalidSignature);
        }

        //let sig_buffer_len = response.data.len();

        let mut r = [Default::default(); 32];
        r.copy_from_slice(&response.data[..32]);

        let mut s = [Default::default(); 32];
        s.copy_from_slice(&response.data[32..64]);

        let v = response.data[64];

        let sig = k256::ecdsa::Signature::from_der(&response.data[65..])?;

        let signature = Signature { r, s, v, sig };

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::{serialize_bip44, BIP44Path};

    #[test]
    fn bip44() {
        let path = BIP44Path {
            purpose: 0x8000_0000 | 0x2c,
            coin: 0x8000_0000 | 1,
            account: 0x1234,
            change: 0,
            index: 0x5678,
        };
        let serialized_path = serialize_bip44(&path).unwrap();
        assert_eq!(serialized_path.len(), 20);
        assert_eq!(
            hex::encode(&serialized_path),
            "2c00008001000080341200000000000078560000"
        );
    }
}
