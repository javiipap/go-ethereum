pub mod ffi;

use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use bincode::{deserialize, serialize};
use blind_rsa_signatures::Signature;
use elastic_elgamal::app::{ChoiceParams, EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{Ciphertext, PublicKey};
use ffi::{ByteBuffer, parse_vector};

/// Generates vector of ciphertexts
#[unsafe(no_mangle)]
pub extern "C" fn generate_acc(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= GENERATE ACC =============");
    let data = parse_vector(buffer, length);
    let candidate_count = <U256>::abi_decode(&data).unwrap();

    ByteBuffer::from(
        serialize(&vec![Ciphertext::<Ristretto>::zero(); candidate_count.to()]).unwrap(),
    )
}

/// Verifies vote validity
#[unsafe(no_mangle)]
pub extern "C" fn verify_vote(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= VERIFY VOTE =============");
    let data = parse_vector(buffer, length);

    let (candidate_count, public_key, ballot) =
        <(U256, Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let public_key = PublicKey::<Ristretto>::from_bytes(&public_key.to_vec()).unwrap();
    let ballot = deserialize::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot.to_vec()).unwrap();

    let params = ChoiceParams::single(public_key, candidate_count.to());

    let mut output = vec![0; 32];

    if let Ok(_) = ballot.verify(&params) {
        output[31] = 1;
    };

    ByteBuffer::from(output)
}

/// Add vote to result vector
#[unsafe(no_mangle)]
pub extern "C" fn add_votes(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= ADD VOTE =============");
    let data = parse_vector(buffer, length);

    let (acc, ballot) = <(Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let mut acc = deserialize::<Vec<Ciphertext<Ristretto>>>(&acc.to_vec()).unwrap();
    let ballot = deserialize::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot.to_vec()).unwrap();

    for (i, choice) in ballot.choices_unchecked().iter().enumerate() {
        acc[i] += *choice;
    }

    ByteBuffer::from(serialize(&acc).unwrap())
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_signature(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= VERIFY SIGNATURE =============");
    let data = parse_vector(buffer, length);

    let (public_key, msg, signature) = <(Bytes, Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let public_key = blind_rsa_signatures::PublicKey::from_der(&public_key.to_vec()).unwrap();
    let options = blind_rsa_signatures::Options::default();

    let mut output = vec![0; 32];

    if let Ok(_) = Signature::new(signature.into()).verify(&public_key, None, msg, &options) {
        output[31] = 1;
    }

    ByteBuffer::from(output)
}

#[cfg(test)]
mod test {
    use crate::*;
    use alloy_primitives::{
        Bytes, U256,
        hex::{FromHex, encode},
    };
    use alloy_sol_types::SolValue;
    use bincode::{deserialize, serialize};
    use elastic_elgamal::{
        Ciphertext, DiscreteLogTable, Keypair, PublicKey, SecretKey,
        app::{ChoiceParams, EncryptedChoice},
        group::Ristretto,
    };
    use std::{error::Error, slice};

    fn generate_elgamal_keypair() -> (PublicKey<Ristretto>, SecretKey<Ristretto>) {
        let rng = &mut rand::thread_rng();
        Keypair::<Ristretto>::generate(rng).into_tuple()
    }

    fn encrypt_vote(
        pub_key_bytes: &Vec<u8>,
        choice: usize,
        options_count: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let rng = &mut rand::thread_rng();
        let receiver = PublicKey::<Ristretto>::from_bytes(&pub_key_bytes)?;

        let params = ChoiceParams::single(receiver, options_count);
        let ballot = EncryptedChoice::single(&params, choice, rng);

        Ok(serialize(&ballot).unwrap())
    }

    fn decrypt_result(
        secret_key: &Vec<u8>,
        raw_result: &Vec<u8>,
    ) -> Result<Vec<u64>, Box<dyn Error>> {
        let result = deserialize::<Vec<Ciphertext<Ristretto>>>(raw_result.as_slice())?;

        let sk = match SecretKey::<Ristretto>::from_bytes(&secret_key) {
            Some(res) => res,
            None => return Err(Box::from("Unexpected error")),
        };

        let max: u64 = 1 << 10;

        let lookup_table = DiscreteLogTable::new(0..=max);

        Ok(result
            .iter()
            .map(|choice| sk.decrypt(*choice, &lookup_table).unwrap())
            .collect::<Vec<u64>>())
    }

    #[test]
    fn decrypt_works() {
        let result: Vec<u8> = Vec::from_hex(
            "0x030000000000000020000000000000002018b2fac4c27fb2b12e386ec127d428d7d0e8e6079347c437cbce27372b621b2000000000000000cab4d5a37d6c45cd5a37325208b83ce7fb20f9fcf65265b561efa78d5b0f207f20000000000000001672d3a2efef9acfd1cd8f84cf7f1216967a4ad95ba93e73fcd0f9a269cbc648200000000000000074864c80081e38fc91c81e4078a776531bfdb8af24857e461fd85c1aa7d0e6692000000000000000d606ba95f62a80de1c499cef04fdd05d83970847319f6f4dcbdef6661496510c2000000000000000fc9352399f16cf89df9654ad45483fc638fe6cf2338ed93b06df9fff9ce2c96a",
        ).unwrap();

        let private_key: Vec<u8> =
            Vec::from_hex("0x1fac729b1546551f918a573af12802971fbe97c8697aaa45cef14fb84e121e0e")
                .unwrap();

        let decrypted = decrypt_result(&private_key, &result).unwrap();

        println!("{:?}", decrypted);
    }

    #[test]
    fn acc_generator_works() {
        // let raw = "0x000000000000000000000000000000000000000000000000000000000000000a";
        // let buffer = Vec::from_hex(raw).expect("Invalid Hex String");
        let buffer = Vec::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 20,
        ]);

        let result = generate_acc(buffer.as_ptr(), buffer.len());

        let parsed = unsafe { slice::from_raw_parts(result.ptr, result.length) };

        println!("{:?}, {}", parsed, parsed.len());
    }

    #[test]
    fn it_works() -> Result<(), Box<dyn Error>> {
        let keypair = generate_elgamal_keypair();

        let pub_key_bytes = &Vec::from(keypair.0.as_bytes());
        let priv_key_bytes = &Vec::from(keypair.1.expose_scalar().as_bytes());

        let ballot_1 = encrypt_vote(pub_key_bytes, 2, 10)?;
        let ballot_2 = encrypt_vote(pub_key_bytes, 3, 10)?;

        // ============ Verify vote ============

        let props = (
            U256::from(10),
            Bytes::from(pub_key_bytes.clone()),
            Bytes::from(ballot_1.clone()),
        )
            .abi_encode_sequence();

        verify_vote(props.as_ptr(), props.len());

        // ============ Add vote ============

        let props = U256::from(10).abi_encode();
        let acc_result = generate_acc(props.as_ptr(), props.len());

        let props = (
            Bytes::from(unsafe { slice::from_raw_parts(acc_result.ptr, acc_result.length) }),
            Bytes::from(ballot_1),
        )
            .abi_encode_sequence();

        let raw_result = add_votes(props.as_ptr(), props.len());
        // =================================================
        let props = (
            Bytes::from(unsafe { slice::from_raw_parts(raw_result.ptr, raw_result.length) }),
            Bytes::from(ballot_2),
        )
            .abi_encode_sequence();

        let raw_result = add_votes(props.as_ptr(), props.len());

        let parsed_result = unsafe { slice::from_raw_parts(raw_result.ptr, raw_result.length) };

        let result = decrypt_result(priv_key_bytes, &parsed_result.to_vec())?;

        println!("Tamaño del resultado: {}", parsed_result.len());

        println!("{:?}", result);

        Ok(())
    }

    #[test]
    fn encode_works() {
        let params = U256::from(10).abi_encode();

        let _candidate_count = <U256>::abi_decode(&params).unwrap();
        println!("{:?}", encode(params));
    }

    #[test]
    fn decode_works() {
        let byte_array = Vec::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 22, 161, 206, 139, 148, 59, 181, 69,
            246, 199, 180, 131, 85, 27, 60, 30, 195, 254, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 38, 216, 182, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 64, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 38, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130,
            1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 162, 204, 71, 56, 98, 5, 69, 254, 218, 167,
            51, 217, 188, 31, 90, 135, 195, 144, 163, 146, 160, 237, 35, 130, 194, 202, 88, 126,
            153, 65, 183, 38, 88, 46, 151, 104, 238, 25, 158, 119, 220, 10, 94, 58, 147, 147, 119,
            47, 235, 38, 30, 67, 77, 77, 76, 39, 38, 153, 43, 219, 156, 207, 185, 39, 88, 45, 15,
            145, 224, 247, 131, 100, 48, 103, 172, 209, 249, 197, 108, 220, 193, 237, 171, 195,
            214, 174, 106, 24, 148, 114, 142, 89, 90, 157, 156, 29, 224, 150, 187, 187, 168, 53,
            145, 85, 88, 106, 72, 128, 229, 20, 245, 65, 4, 153, 3, 58, 255, 79, 109, 250, 37, 34,
            219, 75, 35, 167, 105, 63, 215, 201, 22, 143, 120, 163, 107, 151, 1, 136, 129, 107, 6,
            43, 239, 65, 123, 80, 152, 33, 140, 19, 197, 249, 169, 83, 221, 69, 138, 173, 105, 40,
            116, 27, 22, 36, 34, 225, 110, 206, 117, 118, 212, 27, 113, 179, 248, 55, 139, 128,
            102, 232, 186, 63, 153, 36, 195, 41, 100, 18, 163, 251, 56, 197, 245, 227, 201, 63,
            118, 158, 47, 181, 139, 250, 141, 112, 10, 132, 2, 1, 31, 15, 187, 3, 90, 12, 212, 202,
            36, 242, 186, 1, 239, 124, 168, 145, 74, 230, 30, 180, 90, 178, 183, 69, 197, 58, 115,
            82, 106, 134, 85, 19, 63, 125, 164, 38, 80, 154, 10, 13, 255, 8, 249, 153, 23, 12, 85,
            47, 2, 3, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 11, 101, 108, 101, 99, 116, 105, 111, 110, 95, 51, 50, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 25, 85, 252, 44, 25, 135, 150,
            66, 32, 132, 182, 220, 79, 230, 192, 1, 164, 190, 167, 131, 228, 117, 241, 81, 127,
            187, 133, 190, 168, 214, 42, 160, 149, 215, 15, 237, 35, 251, 105, 188, 199, 8, 108,
            202, 220, 100, 132, 1, 144, 88, 72, 187, 157, 39, 244, 116, 235, 240, 152, 12, 139,
            231, 133, 28, 238, 226, 54, 103, 87, 249, 95, 11, 19, 187, 143, 87, 82, 128, 24, 244,
            133, 151, 4, 241, 124, 124, 203, 229, 123, 97, 38, 21, 88, 237, 182, 241, 12, 62, 154,
            198, 112, 23, 56, 230, 42, 185, 221, 106, 207, 46, 60, 255, 111, 80, 150, 158, 79, 135,
            33, 172, 210, 2, 78, 220, 47, 25, 65, 195, 71, 16, 9, 200, 201, 28, 57, 96, 80, 114,
            24, 72, 223, 135, 101, 43, 115, 30, 95, 111, 192, 19, 139, 203, 91, 83, 105, 133, 86,
            45, 128, 154, 82, 48, 37, 94, 124, 92, 13, 73, 241, 150, 183, 35, 76, 26, 240, 182, 91,
            178, 105, 197, 91, 179, 164, 124, 238, 195, 140, 148, 152, 226, 83, 221, 185, 74, 179,
            145, 123, 197, 254, 92, 160, 208, 138, 161, 35, 193, 107, 128, 152, 24, 202, 167, 134,
            57, 79, 249, 45, 211, 163, 192, 117, 239, 142, 71, 75, 157, 113, 135, 236, 97, 180,
            225, 215, 130, 94, 20, 134, 1, 171, 175, 213, 161, 165, 93, 228, 201, 103, 255, 148,
            15, 201, 228, 14, 42, 124, 101,
        ]);

        println!("{:?}", encode(byte_array));
    }

    #[test]
    fn verify_works() {
        let byte_array = Vec::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 38, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72,
            134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 158,
            20, 57, 136, 233, 184, 202, 182, 97, 141, 170, 70, 17, 63, 227, 116, 117, 59, 163, 12,
            150, 123, 242, 133, 99, 14, 196, 242, 247, 29, 207, 248, 125, 71, 30, 216, 6, 104, 196,
            63, 128, 52, 142, 237, 18, 211, 244, 190, 129, 212, 237, 184, 147, 105, 157, 22, 165,
            170, 147, 133, 185, 4, 212, 71, 13, 148, 135, 111, 179, 120, 214, 13, 169, 5, 26, 135,
            213, 163, 8, 165, 3, 2, 233, 203, 132, 137, 205, 57, 113, 119, 240, 183, 211, 56, 132,
            66, 133, 69, 79, 198, 107, 1, 240, 241, 168, 121, 91, 112, 98, 234, 211, 80, 215, 180,
            96, 250, 176, 94, 193, 4, 53, 245, 71, 121, 226, 188, 96, 26, 196, 208, 178, 60, 253,
            83, 166, 98, 14, 111, 21, 138, 244, 160, 45, 222, 42, 250, 37, 219, 222, 44, 48, 83,
            104, 191, 70, 203, 255, 105, 54, 60, 207, 133, 165, 107, 117, 62, 37, 101, 78, 164, 30,
            252, 125, 1, 87, 181, 186, 31, 89, 118, 25, 65, 105, 81, 32, 135, 166, 215, 11, 97,
            195, 73, 48, 180, 0, 170, 88, 183, 215, 189, 57, 124, 184, 130, 188, 199, 58, 202, 168,
            123, 130, 5, 60, 181, 94, 176, 16, 231, 184, 38, 106, 12, 26, 70, 64, 121, 99, 109, 93,
            205, 86, 214, 191, 246, 85, 251, 235, 221, 117, 48, 242, 137, 77, 209, 154, 181, 21,
            48, 240, 22, 250, 118, 51, 205, 67, 121, 2, 3, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 38,
            249, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 42, 48, 120, 101, 52, 99, 50, 99, 98, 54, 52, 100, 53, 57, 98, 48, 48,
            100, 53, 98, 100, 54, 54, 57, 99, 51, 102, 49, 51, 57, 56, 53, 97, 51, 53, 49, 98, 48,
            56, 52, 51, 99, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 11, 101, 108, 101, 99, 116, 105, 111, 110, 95, 51, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 46, 172, 138, 85, 78, 235, 185, 92, 9,
            107, 112, 252, 122, 59, 202, 80, 224, 65, 231, 131, 230, 143, 60, 206, 198, 67, 162,
            195, 69, 214, 45, 128, 94, 219, 157, 85, 12, 1, 55, 193, 231, 111, 243, 207, 81, 85,
            181, 184, 35, 76, 71, 222, 176, 73, 100, 127, 108, 157, 195, 197, 220, 120, 109, 123,
            253, 165, 76, 196, 132, 212, 80, 100, 135, 144, 83, 38, 61, 34, 176, 63, 24, 179, 233,
            83, 242, 33, 47, 29, 240, 142, 227, 71, 187, 188, 243, 138, 163, 30, 96, 7, 11, 166,
            72, 148, 141, 147, 110, 82, 121, 132, 15, 204, 207, 58, 55, 183, 159, 30, 245, 123,
            211, 86, 152, 169, 198, 2, 76, 236, 149, 65, 57, 207, 134, 175, 184, 103, 177, 128, 68,
            245, 130, 114, 236, 203, 48, 67, 158, 36, 70, 239, 99, 174, 51, 254, 153, 164, 245, 47,
            157, 235, 100, 133, 249, 126, 50, 124, 238, 9, 22, 1, 111, 101, 117, 67, 194, 6, 107,
            170, 59, 220, 34, 61, 223, 84, 203, 204, 9, 59, 210, 92, 225, 68, 65, 124, 135, 114,
            175, 70, 137, 230, 223, 10, 128, 221, 77, 241, 130, 39, 121, 135, 56, 95, 142, 23, 196,
            243, 61, 149, 110, 89, 9, 39, 15, 162, 92, 12, 132, 249, 207, 30, 93, 80, 148, 46, 220,
            251, 119, 2, 96, 64, 211, 52, 92, 47, 251, 129, 131, 168, 154, 50, 230, 58, 75, 123,
            114, 150,
        ]);

        let result = verify_signature(byte_array.as_ptr(), byte_array.len());

        let parsed = unsafe { slice::from_raw_parts(result.ptr, result.length) };

        println!("{:?}", parsed);
    }
}
