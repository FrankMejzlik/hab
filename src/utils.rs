//!
//! Generally usefull functions.
//!

use std::{
    io::{stdin, BufRead},
    time::{SystemTime, UNIX_EPOCH},
};
// ---
use crate::common::DiscreteDistribution;
use bitreader::BitReader;
use chrono::{DateTime, Utc};
use hex::{decode, encode};
use sha2::{Digest, Sha256};
// ---
#[allow(unused_imports)]
use crate::{debug, error, info, log_input, trace, warn};

pub type UnixTimestamp = u128;

/// A macro similar to `vec![$elem; $size]` which returns a boxed array.
///
/// ```rustc
///     let _: Box<[u8; 1024]> = box_array![0; 1024];
/// ```
#[macro_export]
macro_rules! box_array {
    ($val:expr ; $len:expr) => {{
        // Use a generic function so that the pointer cast remains type-safe
        fn vec_to_boxed_array<T, const LEN: usize>(vec: Vec<T>) -> Box<[T; LEN]> {
            let boxed_slice = vec.into_boxed_slice();

            let ptr = ::std::boxed::Box::into_raw(boxed_slice) as *mut [T; LEN];

            unsafe { Box::from_raw(ptr) }
        }

        vec_to_boxed_array(vec![$val; $len])
    }};
}

/// Formats the given bytes as a lowercase hex String and returns it.
pub fn to_hex(buffer: &[u8]) -> String {
    encode(buffer)
}

#[allow(dead_code)]
pub fn from_hex(hex_bytes: &str) -> Result<Vec<u8>, String> {
    match decode(hex_bytes) {
        Ok(x) => Ok(x),
        Err(e) => Err(format!("{}", e)),
    }
}

#[allow(dead_code)]
pub fn gen_byte_blocks_from<const BLOCK_SIZE: usize>(cont: &[u64]) -> Vec<Vec<u8>> {
    let mut result = vec![];
    for item in cont.iter() {
        let bs = item.to_le_bytes();

        let mut arr = vec![0x0; BLOCK_SIZE];

        arr[0..std::mem::size_of::<u64>()].copy_from_slice(&bs);
        result.push(arr);
    }

    result
}

pub fn get_segment_indices<const K: usize, const HASH_SIZE: usize, const TAU: usize>(
    msg_hash: &[u8; HASH_SIZE],
) -> Vec<usize> {
    let mut res = vec![];

    let mut reader = BitReader::new(msg_hash);

    for _ in 0..K {
        let c_i: usize = reader
            .read_u64(TAU.try_into().unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        res.push(c_i);
    }

    res
}
/// Returns the current UNIX timestamp in milliseconds.
pub fn unix_ts() -> UnixTimestamp {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_millis(),
        Err(_) => 0,
    }
}

/// Returns the name of this binary.
pub fn binary_name() -> String {
    module_path!()
        .split("::")
        .into_iter()
        .next()
        .unwrap_or_default()
        .to_string()
}

pub fn shorten(string: &str, max_len: usize) -> String {
    if string.len() <= max_len {
        string.to_string()
    } else {
        let mut res = String::new();
        let half = (max_len + 2) / 2;
        res.push_str(&string[..half]);
        res.push_str("..");
        res.push_str(&string[(string.len() - half)..]);
        res
    }
}

pub fn unix_ts_to_string(ts: UnixTimestamp) -> String {
    let datetime = DateTime::<Utc>::from_utc(
        chrono::NaiveDateTime::from_timestamp_opt((ts / 1000) as i64, 0).expect("!"),
        Utc,
    );
    datetime.format("%d-%m-%Y %H:%M:%S").to_string()
}

///
/// For the provided certificate interval computes the certificate window length.
/// AKA: A number of certificates to keep (and certify) per layer.
///
pub fn calc_cert_window(ci: usize) -> usize {
    2 * ci + 1
}

pub fn lifetimes_to_probs(key_dist: &Vec<Vec<usize>>) -> Vec<f64> {
    // Instantiate the probability distribution
    let mut weights = vec![];
    let mut percents = vec![];
    let mut max = 0;
    for tuple in key_dist {
        max = max.max(tuple[0]);
        weights.push(tuple[0]);
        percents.push(tuple[1]);
    }

    let mut weights = weights
        .into_iter()
        .map(|x| (max as f64 / x as f64) / max as f64)
        .collect::<Vec<f64>>();

    let mut sum = 0.0;
    for w in weights.iter() {
        sum += *w;
    }

    for w in weights.iter_mut() {
        *w = *w / sum;
    }

    let mut avg_rate = vec![];
    for (i, w) in weights.iter().enumerate() {
        let x = 1.0 / w;
        let frac = percents[i] as f64 / 100 as f64;
        avg_rate.push(x * frac);
    }

    weights
}

pub fn lifetimes_to_distr(key_dist: &Vec<Vec<usize>>) -> (DiscreteDistribution, Vec<f64>) {
    // Instantiate the probability distribution
    let mut weights = vec![];
    let mut percents = vec![];
    let mut max = 0;
    for tuple in key_dist {
        max = max.max(tuple[0]);
        weights.push(tuple[0]);
        percents.push(tuple[1]);
    }

    let mut weights = weights
        .into_iter()
        .map(|x| (max as f64 / x as f64) / max as f64)
        .collect::<Vec<f64>>();

    let mut sum = 0.0;
    for w in weights.iter() {
        sum += *w;
    }

    for w in weights.iter_mut() {
        *w = *w / sum;
    }

    let mut avg_rate = vec![];
    for (i, w) in weights.iter().enumerate() {
        let x = 1.0 / w;
        let frac = percents[i] as f64 / 100 as f64;
        avg_rate.push(x * frac);
    }

    (DiscreteDistribution::new(weights), avg_rate)
}

/// Blocks the thread until some input terminated with newline is sent do STDIN.
pub fn input() {
    let mut handle = stdin().lock();
    let mut input = String::new();
    handle.read_line(&mut input).expect("Failed to read line");
}

pub fn start() -> SystemTime {
    std::time::SystemTime::now()
}

pub fn stop(_scope: &str, _start: SystemTime) {
    #[cfg(feature = "print_times")]
    println!(
        "{}: {} ms",
        _scope,
        std::time::SystemTime::now()
            .duration_since(_start)
            .unwrap()
            .as_millis()
    );
}

pub fn sha2_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn sha2_256_str(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    //< Alias `debug` as `println`
    #[allow(unused_imports)]
    use std::println as debug;
    // ---
    use byteorder::{NativeEndian, ReadBytesExt};
    // ---
    use crate::utils;

    #[test]
    fn test_from_hex() {
        // Empty bytes
        let bytes_empty_hex = String::from("");
        let act_bytes_empty_hex = utils::from_hex(&bytes_empty_hex).unwrap();
        let exp_bytes_empty_hex = vec![];

        // Non-empty bytes
        let bytes_hex = String::from("deadbeef");
        let act_bytes_hex = utils::from_hex(&bytes_hex).unwrap();
        let exp_bytes_hex = vec![0xDE, 0xAD, 0xBE, 0xEF];

        assert_eq!(act_bytes_empty_hex, exp_bytes_empty_hex);
        assert_eq!(act_bytes_hex, exp_bytes_hex);
    }

    #[test]
    fn test_to_hex() {
        // Empty bytes
        let bytes_empty = b"";
        let act_bytes_empty_hex = utils::to_hex(bytes_empty);
        let exp_bytes_empty_hex = String::from("");

        // Non-empty bytes
        let bytes_nonempty_0 = [0xDE, 0xAD, 0xBE, 0xEF];
        let act_bytes_nonempty_0_hex = utils::to_hex(&bytes_nonempty_0);
        let exp_bytes_nonempty_0_hex = String::from("deadbeef");

        assert_eq!(act_bytes_empty_hex, exp_bytes_empty_hex);
        assert_eq!(act_bytes_nonempty_0_hex, exp_bytes_nonempty_0_hex);
    }

    #[test]
    fn test_gen_byte_blocks_from() {
        const NUM_NUMBERS: usize = 8;
        const BLOCK_SIZE: usize = 32;

        let numbers = (0_u64..NUM_NUMBERS as u64).collect::<Vec<u64>>();
        debug!("numbers: {:?}", numbers);
        let leaf_numbers = utils::gen_byte_blocks_from::<BLOCK_SIZE>(&numbers);
        for (ex_num, num) in leaf_numbers.into_iter().enumerate() {
            let mut cursor = Cursor::new(num.clone());
            let num_0 = cursor.read_u64::<NativeEndian>().unwrap();
            let num_1 = cursor.read_u64::<NativeEndian>().unwrap();
            let num_2 = cursor.read_u64::<NativeEndian>().unwrap();
            let num_3 = cursor.read_u64::<NativeEndian>().unwrap();

            debug!("[{}] \t -> 0x{}", ex_num, utils::to_hex(&num));

            assert_eq!(num.len(), BLOCK_SIZE);
            assert_eq!(num_0, ex_num as u64);
            assert_eq!(num_1, 0);
            assert_eq!(num_2, 0);
            assert_eq!(num_3, 0);
        }
    }
}
