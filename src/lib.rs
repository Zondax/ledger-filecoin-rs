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

use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{App, AppExt, ChunkPayloadType, Version};

pub use ledger_zondax_generic::LedgerAppError;

mod params;
use params::{InstructionCode, CLA};

use std::str;

/// Public Key Length
const PK_LEN: usize = 65;

/// Ledger App Error
#[derive(Debug, thiserror::Error)]
pub enum FilError<E>
where
    E: std::error::Error,
{
    #[error("Ledger | {0}")]
    /// Common Ledger errors
    Ledger(#[from] LedgerAppError<E>),

    /// Device related errors
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] k256::elliptic_curve::Error),

    /// Device related errors
    #[error("Ecdsa error: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),
}

/// Filecoin App
pub struct FilecoinApp<E> {
    apdu_transport: E,
}

impl<E: Exchange> App for FilecoinApp<E> {
    const CLA: u8 = CLA;
}

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

impl BIP44Path {
    /// Serialize a [`BIP44Path`] in the format used in the app
    pub fn serialize_bip44(&self) -> Vec<u8> {
        use byteorder::{LittleEndian, WriteBytesExt};
        let mut m = Vec::new();

        m.write_u32::<LittleEndian>(self.purpose).unwrap();
        m.write_u32::<LittleEndian>(self.coin).unwrap();
        m.write_u32::<LittleEndian>(self.account).unwrap();
        m.write_u32::<LittleEndian>(self.change).unwrap();
        m.write_u32::<LittleEndian>(self.index).unwrap();

        m
    }
}

impl<E> FilecoinApp<E> {
    /// Create a new [`FilecoinApp`] with the given transport
    pub const fn new(transport: E) -> Self {
        FilecoinApp {
            apdu_transport: transport,
        }
    }
}

impl<E> FilecoinApp<E>
where
    E: Exchange + Send + Sync,
    E::Error: std::error::Error,
{
    /// Retrieve the app version
    pub async fn version(&self) -> Result<Version, FilError<E::Error>> {
        <Self as AppExt<E>>::get_version(&self.apdu_transport)
            .await
            .map_err(Into::into)
    }

    /// Retrieves the public key and address
    pub async fn address(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<Address, FilError<E::Error>> {
        let serialized_path = path.serialize_bip44();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::GetAddrSecp256k1 as _,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        let response = self
            .apdu_transport
            .exchange(&command)
            .await
            .map_err(LedgerAppError::TransportError)?;

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.len() < PK_LEN => {
                return Err(FilError::Ledger(LedgerAppError::InvalidPK))
            }
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => {
                return Err(FilError::Ledger(LedgerAppError::AppSpecific(
                    err as _,
                    err.description(),
                )))
            }
            Err(err) => {
                return Err(FilError::Ledger(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                )))
            }
        }

        let public_key = k256::PublicKey::from_sec1_bytes(&response_data[..PK_LEN])?;
        let mut addr_byte = [Default::default(); 21];
        addr_byte.copy_from_slice(&response_data[PK_LEN + 1..PK_LEN + 1 + 21]);
        let tmp =
            str::from_utf8(&response_data[PK_LEN + 2 + 21..]).map_err(|_| LedgerAppError::Utf8)?;
        let addr_string = tmp.to_owned();

        Ok(Address {
            public_key,
            addr_byte,
            addr_string,
        })
    }

    /// Sign a transaction
    pub async fn sign(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<Signature, FilError<E::Error>> {
        let bip44path = path.serialize_bip44();

        let start_command = APDUCommand {
            cla: CLA,
            ins: InstructionCode::SignSecp256k1 as _,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: bip44path,
        };

        let response =
            <Self as AppExt<E>>::send_chunks(&self.apdu_transport, start_command, message).await?;

        let response_data = response.data();
        match response.error_code() {
            Ok(APDUErrorCode::NoError) if response_data.is_empty() => {
                return Err(FilError::Ledger(LedgerAppError::NoSignature))
            }
            // Last response should contain the answer
            Ok(APDUErrorCode::NoError) if response_data.len() < 3 => {
                return Err(FilError::Ledger(LedgerAppError::InvalidSignature))
            }
            Ok(APDUErrorCode::NoError) => {}
            Ok(err) => {
                return Err(FilError::Ledger(LedgerAppError::AppSpecific(
                    err as _,
                    err.description(),
                )))
            }
            Err(err) => {
                return Err(FilError::Ledger(LedgerAppError::AppSpecific(
                    err,
                    "[APDU_ERROR] Unknown".to_string(),
                )))
            }
        }

        let mut r = [0; 32];
        r.copy_from_slice(&response_data[..32]);

        let mut s = [0; 32];
        s.copy_from_slice(&response_data[32..64]);

        let v = response_data[64];

        let sig = k256::ecdsa::Signature::from_der(&response_data[65..])?;

        let signature = Signature { r, s, v, sig };

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::BIP44Path;

    #[test]
    fn bip44() {
        let path = BIP44Path {
            purpose: 0x8000_0000 | 0x2c,
            coin: 0x8000_0000 | 1,
            account: 0x1234,
            change: 0,
            index: 0x5678,
        };
        let serialized_path = path.serialize_bip44();
        assert_eq!(serialized_path.len(), 20);
        assert_eq!(
            hex::encode(&serialized_path),
            "2c00008001000080341200000000000078560000"
        );
    }
}
