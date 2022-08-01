mod constants;

use std::num::NonZeroU32;

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{pbkdf2};

fn generate_entropy(length: usize) -> Vec<u8> {
    let mut entropy = vec![0; length];
    let rand = SystemRandom::new();
    match rand.fill(&mut entropy) {
        Ok(_) => println!("entropy found"),
        Err(_) => println!("error finding entropy"),
    };
    return entropy;
}

fn add_checksum(mut entropy: Vec<u8>) -> Vec<u8> {
    let hash = digest::digest(&digest::SHA256, &entropy);
    entropy.push(hash.as_ref()[0]);
    return entropy;
}

fn bytes_to_binary(bytes: Vec<u8>) -> String {
    let mut str = "".to_owned();
    for byte in bytes {
        let bit_str = format!("{:08b}", byte);
        str.push_str(&bit_str);
    }
    return str;
}

fn get_mnemonic_sentence(str: String) -> String {
    let mut i: usize = 0;
    let mut placeholder: usize = 0;
    let mut mnemonic_array = vec![];

    while i <= str.len() {
        if i != 0 && i % 11 == 0 {
            let index = isize::from_str_radix(&str[placeholder..i], 2)
                .expect("Not a binary number!");
            mnemonic_array.push(constants::wordlist::WORD_LIST[index as usize]);
            placeholder = i;
            i += 1;
            continue;
        }
        i += 1;
    }
    return mnemonic_array.join(" ");
}

fn bytes_to_hex(bytes: [u8; 64]) -> String {
    let mut hex_seed = "".to_owned();
    for byte in bytes {
        let hex = format!("{:02x}", byte);
        hex_seed.push_str(&hex);
    }
    return hex_seed;
}

fn calculate_seed(str: String) -> [u8; 64] {
    const ITERATIONS_OPTION: Option<NonZeroU32> = NonZeroU32::new(2048);
    let iterations: NonZeroU32;
    match ITERATIONS_OPTION {
        Some(n) => iterations = n,
        None => panic!("iterations cannot be 0")
    };
    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    pub type Credential = [u8; CREDENTIAL_LEN];
    let mut seed: Credential = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        iterations,
        b"mnemonic",
        str.as_bytes(),
        &mut seed,
    );
    return seed;
}

fn main() {
    const ENTROPY_LENGTH: usize = 32;

    let entropy = generate_entropy(ENTROPY_LENGTH);

    let entropy_with_checksum = add_checksum(entropy.clone());

    let entropy_str = bytes_to_binary(entropy_with_checksum);

    let mnemonic_sentence = get_mnemonic_sentence(entropy_str);

    let seed = calculate_seed(mnemonic_sentence);

    let hex_seed = bytes_to_hex(seed);

    println!("{:?}", hex_seed);
    
}
