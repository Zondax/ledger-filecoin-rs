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
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

/// APDU Class byte
pub const CLA: u8 = 0x06;

/// Public Key Length (SEC1 uncompressed format)
pub const PK_LEN: usize = 65;

/// Filecoin address byte length
pub const ADDR_BYTE_LEN: usize = 21;

/// ECDSA signature component length (r and s)
pub const ECDSA_COMPONENT_LEN: usize = 32;

/// Minimum signature response length: r + s + v + minimal DER overhead
pub const MIN_SIGNATURE_LEN: usize = 65;

/// BIP44 purpose value
pub const BIP44_PURPOSE: u32 = 44;

/// Filecoin coin type
pub const FILECOIN_COIN_TYPE: u32 = 461;

/// BIP44 hardened derivation flag
pub const BIP44_HARDENED: u32 = 0x8000_0000;

/// APDU instruction codes
#[repr(u8)]
pub enum InstructionCode {
    /// Get address using secp256k1
    GetAddrSecp256k1 = 1,
    /// Sign transaction using secp256k1
    SignSecp256k1 = 2,
    /// Sign raw bytes
    SignRawBytes = 7,
    /// Sign personal message
    SignPersonalMsg = 8,
}
