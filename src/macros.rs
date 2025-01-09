// Copyright 2022 Aztec
// Copyright 2024 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::U256;

macro_rules! u256 {
    ($s:literal) => {{
        const STRING: &'static [u8] = $s.as_bytes();
        $crate::macros::decode(STRING)
    }};
}
pub(crate) use u256;

macro_rules! fr {
    ($s:literal) => {{
        use $crate::macros::u256;
        u256!($s).into_fr()
    }};
}

pub(crate) use fr;

const fn next_hex_char(string: &[u8], mut pos: usize) -> Option<(u8, usize)> {
    while pos < string.len() {
        let raw_val = string[pos];
        pos += 1;
        let val = match raw_val {
            b'0'..=b'9' => raw_val - 48,
            b'A'..=b'F' => raw_val - 55,
            b'a'..=b'f' => raw_val - 87,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            0..=127 => panic!("Encountered invalid ASCII character"),
            _ => panic!("Encountered non-ASCII character"),
        };
        return Some((val, pos));
    }
    None
}

const fn next_byte(string: &[u8], pos: usize) -> Option<(u8, usize)> {
    let (half1, pos) = match next_hex_char(string, pos) {
        Some(v) => v,
        None => return None,
    };
    let (half2, pos) = match next_hex_char(string, pos) {
        Some(v) => v,
        None => panic!("Odd number of hex characters"),
    };
    Some(((half1 << 4) + half2, pos))
}

pub(crate) const fn decode(string: &[u8]) -> U256 {
    let mut buf = [0_u64; 4];
    let mut buf_pos = 3;
    let mut pos = 0;
    let mut bytes = 0;

    while let Some((byte, new_pos)) = next_byte(string, pos) {
        if bytes == 8 {
            bytes = 0;
            buf_pos -= 1;
        }
        buf[buf_pos] = buf[buf_pos] << 8 | byte as u64;
        bytes += 1;
        pos = new_pos;
    }

    // TODO: Turn this to an error
    assert!(
        bytes == 8 && buf_pos == 0,
        "You should provide exactly 32 bytes hex"
    );

    U256::new(buf)
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_decode() {
//         let input = "15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5";
//         let res = decode(input.as_bytes());
//         println!("Limbs: {:?}", res);
//     }

//     // #[test]
//     // fn decode_u256_correctly() {
//     //     let expected = U256::from_slice(&hex_literal::hex!(
//     //         "15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5"
//     //     ))
//     //     .unwrap();

//     //     println!(
//     //         "Internal repr: {:?}",
//     //         u256!("15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5")
//     //     );
//     //     let e = u256!("15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5").into_fr();
//     //     println!("As a field element: {:?}", e);

//     //     assert_eq!(
//     //         expected,
//     //         u256!("15d2cb30be54aed04a1356bcabbf6217a20a7b4be770b77286d9b570827055d5")
//     //     );
//     // }
// }
