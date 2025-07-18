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
//! Support library for Filecoin Ledger Nano S+/X, Stax and Flex apps

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
use std::fmt;
use byteorder::{BigEndian, WriteBytesExt};
use integer_encoding::VarInt;

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

    /// Secp256k1 related errors
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] k256::elliptic_curve::Error),

    /// ECDSA related errors
    #[error("Ecdsa error: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),
}

/// BIP44Path Builder Error
#[derive(Debug, thiserror::Error)]
pub enum BIP44BuilderError {
    /// A required field was not provided to the builder
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
}

/// Filecoin App
pub struct FilecoinApp<E> {
    apdu_transport: E,
}

impl<E: Exchange> App for FilecoinApp<E> {
    const CLA: u8 = CLA;
}

/// FilecoinApp address (includes pubkey and the corresponding ss58 address)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Public Key
    pub public_key: k256::PublicKey,

    /// Address byte format
    pub addr_byte: [u8; 21],

    /// Address string format
    pub addr_string: String,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr_string)
    }
}

/// FilecoinApp signature (includes R, S, V and der format)
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature {{ r: {}, s: {}, v: {} }}",
            hex::encode(self.r),
            hex::encode(self.s),
            self.v
        )
    }
}

/// BIP44 Path
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Create a new builder for BIP44Path
    pub fn builder() -> BIP44PathBuilder {
        BIP44PathBuilder::new()
    }

    /// Create a standard Filecoin path (m/44'/461'/account'/change/index)
    /// 
    /// # Panics
    /// Panics if account >= 2^31 (hardened bit would be set twice)
    pub fn filecoin(account: u32, change: u32, index: u32) -> Self {
        assert!(account < 0x8000_0000, "Account must be less than 2^31");
        Self {
            purpose: 0x8000_0000 | 44,
            coin: 0x8000_0000 | 461,
            account: 0x8000_0000 | account,
            change,
            index,
        }
    }
    
    /// Validate that the path follows BIP44 structure
    pub fn validate(&self) -> Result<(), &'static str> {
        // Check that purpose, coin, and account have hardened bit set
        if self.purpose & 0x8000_0000 == 0 {
            return Err("Purpose must be hardened");
        }
        if self.coin & 0x8000_0000 == 0 {
            return Err("Coin must be hardened");
        }
        if self.account & 0x8000_0000 == 0 {
            return Err("Account must be hardened");
        }
        
        // Standard BIP44 uses purpose 44'
        if self.purpose != (0x8000_0000 | 44) {
            return Err("Non-standard purpose (expected 44')");
        }
        
        Ok(())
    }

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

/// Builder for BIP44Path
/// 
/// Provides a convenient way to construct BIP44 derivation paths with validation.
/// 
/// # Example
/// 
/// ```
/// # use ledger_filecoin::BIP44Path;
/// let path = BIP44Path::builder()
///     .purpose(44)
///     .coin(461)  // Filecoin
///     .account(0)
///     .change(0)
///     .index(5)
///     .build()
///     .unwrap();
/// ```
pub struct BIP44PathBuilder {
    purpose: Option<u32>,
    coin: Option<u32>,
    account: Option<u32>,
    change: Option<u32>,
    index: Option<u32>,
}

impl BIP44PathBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            purpose: None,
            coin: None,
            account: None,
            change: None,
            index: None,
        }
    }

    /// Set purpose (hardened)
    /// 
    /// # Panics
    /// Panics if purpose >= 2^31 (hardened bit would be set twice)
    pub fn purpose(mut self, purpose: u32) -> Self {
        assert!(purpose < 0x8000_0000, "Purpose must be less than 2^31");
        self.purpose = Some(0x8000_0000 | purpose);
        self
    }

    /// Set coin (hardened)
    /// 
    /// # Panics
    /// Panics if coin >= 2^31 (hardened bit would be set twice)
    pub fn coin(mut self, coin: u32) -> Self {
        assert!(coin < 0x8000_0000, "Coin must be less than 2^31");
        self.coin = Some(0x8000_0000 | coin);
        self
    }

    /// Set account (hardened)
    /// 
    /// # Panics
    /// Panics if account >= 2^31 (hardened bit would be set twice)
    pub fn account(mut self, account: u32) -> Self {
        assert!(account < 0x8000_0000, "Account must be less than 2^31");
        self.account = Some(0x8000_0000 | account);
        self
    }

    /// Set change
    pub fn change(mut self, change: u32) -> Self {
        self.change = Some(change);
        self
    }

    /// Set index
    pub fn index(mut self, index: u32) -> Self {
        self.index = Some(index);
        self
    }

    /// Build the BIP44Path
    pub fn build(self) -> Result<BIP44Path, BIP44BuilderError> {
        Ok(BIP44Path {
            purpose: self.purpose.ok_or(BIP44BuilderError::MissingField("purpose"))?,
            coin: self.coin.ok_or(BIP44BuilderError::MissingField("coin"))?,
            account: self.account.ok_or(BIP44BuilderError::MissingField("account"))?,
            change: self.change.ok_or(BIP44BuilderError::MissingField("change"))?,
            index: self.index.ok_or(BIP44BuilderError::MissingField("index"))?,
        })
    }

    /// Build with Filecoin defaults
    pub fn filecoin_defaults(self) -> BIP44Path {
        BIP44Path {
            purpose: self.purpose.unwrap_or(0x8000_0000 | 44),
            coin: self.coin.unwrap_or(0x8000_0000 | 461),
            account: self.account.unwrap_or(0x8000_0000),
            change: self.change.unwrap_or(0),
            index: self.index.unwrap_or(0),
        }
    }
}

impl fmt::Display for BIP44Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let purpose = self.purpose & !0x8000_0000;
        let coin = self.coin & !0x8000_0000;
        let account = self.account & !0x8000_0000;
        
        write!(
            f,
            "m/{}'/{}'/{}'/{}/{}",
            purpose, coin, account, self.change, self.index
        )
    }
}

impl Default for BIP44PathBuilder {
    fn default() -> Self {
        Self::new()
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

    /// Helper function to parse signature from response
    fn parse_signature(response_data: &[u8]) -> Result<Signature, FilError<E::Error>> {
        let mut r = [0; 32];
        r.copy_from_slice(&response_data[..32]);

        let mut s = [0; 32];
        s.copy_from_slice(&response_data[32..64]);

        let v = response_data[64];
        let sig = k256::ecdsa::Signature::from_der(&response_data[65..])?;

        Ok(Signature { r, s, v, sig })
    }

    /// Helper function to execute signing operation
    async fn execute_sign(
        &self,
        path: &BIP44Path,
        instruction: InstructionCode,
        message: &[u8],
    ) -> Result<Signature, FilError<E::Error>> {
        let bip44path = path.serialize_bip44();

        let start_command = APDUCommand {
            cla: CLA,
            ins: instruction as _,
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

        Self::parse_signature(response_data)
    }
    /// Retrieve the app version
    ///
    /// # Example
    /// ```no_run
    /// # use ledger_filecoin::FilecoinApp;
    /// # use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let api = HidApi::new()?;
    /// let transport = TransportNativeHID::new(&api)?;
    /// let app = FilecoinApp::new(transport);
    /// let version = app.version().await?;
    /// println!("App version: {}.{}.{}", version.major, version.minor, version.patch);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn version(&self) -> Result<Version, FilError<E::Error>> {
        <Self as AppExt<E>>::get_version(&self.apdu_transport)
            .await
            .map_err(Into::into)
    }

    /// Retrieves the public key and address
    ///
    /// # Arguments
    /// * `path` - The BIP44 derivation path
    /// * `require_confirmation` - Whether to show address on device for confirmation
    ///
    /// # Example
    /// ```no_run
    /// # use ledger_filecoin::{FilecoinApp, BIP44Path};
    /// # use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let api = HidApi::new()?;
    /// let transport = TransportNativeHID::new(&api)?;
    /// let app = FilecoinApp::new(transport);
    /// let path = BIP44Path::filecoin(0, 0, 0);
    /// let address = app.address(&path, false).await?;
    /// println!("Address: {}", address);
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Arguments
    /// * `path` - The BIP44 derivation path
    /// * `message` - The transaction message to sign
    ///
    /// # Example
    /// ```no_run
    /// # use ledger_filecoin::{FilecoinApp, BIP44Path};
    /// # use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let api = HidApi::new()?;
    /// let transport = TransportNativeHID::new(&api)?;
    /// let app = FilecoinApp::new(transport);
    /// let path = BIP44Path::filecoin(0, 0, 0);
    /// let message = b"transaction data";
    /// let signature = app.sign(&path, message).await?;
    /// println!("Signature: {}", signature);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<Signature, FilError<E::Error>> {
        self.execute_sign(path, InstructionCode::SignSecp256k1, message).await
    }

    /// Sign raw bytes
    pub async fn sign_raw_bytes(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<Signature, FilError<E::Error>> {
        if message.is_empty() {
            return Err(FilError::Ledger(LedgerAppError::InvalidEmptyMessage));
        }

        // Encode message length using varint (no padding)
        let mut encoded_message = message.len().encode_var_vec();
        // Append the message
        encoded_message.extend_from_slice(message);

        self.execute_sign(path, InstructionCode::SignRawBytes, &encoded_message).await
    }

    /// Sign personal message (FVM)
    pub async fn sign_personal_msg(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<Signature, FilError<E::Error>> {
        if message.is_empty() {
            return Err(FilError::Ledger(LedgerAppError::InvalidEmptyMessage));
        }

        // Encode message with 4-byte big-endian length prefix
        let mut encoded_message = Vec::new();
        encoded_message.write_u32::<BigEndian>(message.len() as u32).unwrap();
        encoded_message.extend_from_slice(message);

        self.execute_sign(path, InstructionCode::SignPersonalMsg, &encoded_message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip44_serialization() {
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

    #[test]
    fn test_bip44_builder() {
        let path = BIP44Path::builder()
            .purpose(44)
            .coin(461)
            .account(0)
            .change(0)
            .index(0)
            .build()
            .unwrap();

        assert_eq!(path.purpose, 0x8000_0000 | 44);
        assert_eq!(path.coin, 0x8000_0000 | 461);
        assert_eq!(path.account, 0x8000_0000);
        assert_eq!(path.change, 0);
        assert_eq!(path.index, 0);
    }

    #[test]
    fn test_bip44_filecoin_helper() {
        let path = BIP44Path::filecoin(0, 0, 0);
        assert_eq!(path.purpose, 0x8000_0000 | 44);
        assert_eq!(path.coin, 0x8000_0000 | 461);
        assert_eq!(path.account, 0x8000_0000);
        assert_eq!(path.change, 0);
        assert_eq!(path.index, 0);
    }

    #[test]
    fn test_bip44_display() {
        let path = BIP44Path::filecoin(0, 0, 5);
        assert_eq!(path.to_string(), "m/44'/461'/0'/0/5");
    }

    #[test]
    fn test_bip44_builder_filecoin_defaults() {
        let path = BIP44Path::builder()
            .account(5)
            .index(10)
            .filecoin_defaults();

        assert_eq!(path.purpose, 0x8000_0000 | 44);
        assert_eq!(path.coin, 0x8000_0000 | 461);
        assert_eq!(path.account, 0x8000_0000 | 5);
        assert_eq!(path.change, 0);
        assert_eq!(path.index, 10);
    }

    #[test]
    fn test_address_display() {
        // Use a valid test public key from k256 test vectors
        let pubkey_bytes = hex::decode("04d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6fbdd594388756a7beaf73b4822bc22d36e9bda7db82df2b8b623673eefc0b7495").unwrap();
        
        let addr = Address {
            public_key: k256::PublicKey::from_sec1_bytes(&pubkey_bytes).unwrap(),
            addr_byte: [0; 21],
            addr_string: "f1234567890abcdef".to_string(),
        };
        assert_eq!(addr.to_string(), "f1234567890abcdef");
    }

    #[test]
    fn test_signature_display() {
        let sig = Signature {
            r: [0x11; 32],
            s: [0x22; 32],
            v: 27,
            sig: k256::ecdsa::Signature::from_der(&[
                0x30, 0x44, 0x02, 0x20, // DER header
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x02, 0x20, // s header
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            ]).unwrap(),
        };
        let display = sig.to_string();
        assert!(display.contains("1111111111111111"));
        assert!(display.contains("2222222222222222"));
        assert!(display.contains("v: 27"));
    }

    #[test]
    fn test_bip44_builder_error_handling() {
        // Test missing purpose
        let err = BIP44Path::builder()
            .coin(461)
            .account(0)
            .change(0)
            .index(0)
            .build()
            .unwrap_err();
        
        match err {
            BIP44BuilderError::MissingField(field) => assert_eq!(field, "purpose"),
        }

        // Test missing coin
        let err = BIP44Path::builder()
            .purpose(44)
            .account(0)
            .change(0)
            .index(0)
            .build()
            .unwrap_err();
        
        match err {
            BIP44BuilderError::MissingField(field) => assert_eq!(field, "coin"),
        }

        // Test missing all fields
        let err = BIP44Path::builder()
            .build()
            .unwrap_err();
        
        match err {
            BIP44BuilderError::MissingField(field) => assert_eq!(field, "purpose"),
        }
    }

    #[test]
    #[should_panic(expected = "Account must be less than 2^31")]
    fn test_bip44_filecoin_invalid_account() {
        // This should panic because account is >= 2^31
        BIP44Path::filecoin(0x8000_0000, 0, 0);
    }

    #[test]
    #[should_panic(expected = "Purpose must be less than 2^31")]
    fn test_bip44_builder_invalid_purpose() {
        BIP44Path::builder()
            .purpose(0x8000_0000)
            .coin(461)
            .account(0)
            .change(0)
            .index(0)
            .build()
            .unwrap();
    }

    #[test]
    fn test_bip44_validate_invalid_paths() {
        // Test path with non-hardened purpose
        let invalid_path = BIP44Path {
            purpose: 44, // Not hardened
            coin: 0x8000_0000 | 461,
            account: 0x8000_0000 | 0,
            change: 0,
            index: 0,
        };
        let err = invalid_path.validate().unwrap_err();
        assert_eq!(err, "Purpose must be hardened");

        // Test path with non-standard purpose
        let invalid_path = BIP44Path {
            purpose: 0x8000_0000 | 49, // Wrong purpose (49 instead of 44)
            coin: 0x8000_0000 | 461,
            account: 0x8000_0000 | 0,
            change: 0,
            index: 0,
        };
        let err = invalid_path.validate().unwrap_err();
        assert_eq!(err, "Non-standard purpose (expected 44')");
    }
}
