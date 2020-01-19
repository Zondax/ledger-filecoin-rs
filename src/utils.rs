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
use std::{fmt, fmt::Write};

/// DecoderError
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// String length is invalid and could not be decoded
    InvalidLength,
    /// hex value could not be decoded
    ParseInt(std::num::ParseIntError),
}

impl From<std::num::ParseIntError> for DecodeError {
    fn from(e: std::num::ParseIntError) -> Self {
        DecodeError::ParseInt(e)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeError::InvalidLength => "Invalid length 0 or odd number of characters".fmt(f),
            DecodeError::ParseInt(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

/// convert array to hexstring
pub fn to_hex_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        write!(&mut s, "{:02x}", byte).expect("ERR");
    }
    s
}

/// convert hexstring to array
pub fn from_hex_string(s: &str) -> Result<Vec<u8>, DecodeError> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err(DecodeError::InvalidLength);
    }

    let mut vec = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let v = u8::from_str_radix(&s[i..i + 2], 16)?;
        vec.push(v);
    }
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use crate::utils::{from_hex_string, to_hex_string};

    #[test]
    fn example_to_hex() {
        let input = [1, 2, 3, 4, 0xFF];
        assert_eq!(to_hex_string(&input), "01020304ff");
    }

    #[test]
    fn example_from_hex() {
        let input = "01020304ff";
        assert_eq!(from_hex_string(&input).unwrap(), [1, 2, 3, 4, 0xFF]);
    }

    #[test]
    fn example_from_hex_bad() {
        let input = "010";
        assert!(from_hex_string(&input).is_err());
    }
}
