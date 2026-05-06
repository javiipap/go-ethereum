pub mod ffi;

use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use blind_rsa_signatures::{Deterministic, PSS, Sha384, Signature};
use elastic_elgamal::app::{ChoiceParams, EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{Ciphertext, PublicKey};
use ffi::{ByteBuffer, parse_vector};
use postcard::{from_bytes, to_allocvec};

/// Generates vector of ciphertexts
#[unsafe(no_mangle)]
pub extern "C" fn generate_acc(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= GENERATE ACC =============");
    println!("[generate_acc] input length: {}", length);
    let data = parse_vector(buffer, length);

    let candidate_count = match <U256>::abi_decode(&data) {
        Ok(v) => v,
        Err(e) => {
            println!("[generate_acc] ERROR abi_decode: {:?}", e);
            return ByteBuffer::from(vec![]);
        }
    };
    println!("[generate_acc] candidate_count: {}", candidate_count);

    ByteBuffer::from(
        to_allocvec(&vec![Ciphertext::<Ristretto>::zero(); candidate_count.to()]).unwrap(),
    )
}

/// Verifies vote validity
#[unsafe(no_mangle)]
pub extern "C" fn verify_vote(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= VERIFY VOTE =============");
    println!("[verify_vote] input length: {}", length);
    let data = parse_vector(buffer, length);

    let (candidate_count, public_key, ballot) = match <(U256, Bytes, Bytes)>::abi_decode_sequence(&data) {
        Ok(v) => v,
        Err(e) => {
            println!("[verify_vote] ERROR abi_decode_sequence: {:?}", e);
            return ByteBuffer::from(vec![0; 32]);
        }
    };
    println!("[verify_vote] candidate_count: {}, pubkey len: {}, ballot len: {}", candidate_count, public_key.len(), ballot.len());

    let public_key = match PublicKey::<Ristretto>::from_bytes(&public_key.to_vec()) {
        Ok(pk) => pk,
        Err(e) => {
            println!("[verify_vote] ERROR: invalid public key bytes: {:?}", e);
            return ByteBuffer::from(vec![0; 32]);
        }
    };

    let ballot_bytes = ballot.to_vec();
    println!("[verify_vote] ballot first 64 bytes: {:02x?}", &ballot_bytes[..ballot_bytes.len().min(64)]);
    println!("[verify_vote] ballot last 32 bytes: {:02x?}", &ballot_bytes[ballot_bytes.len().saturating_sub(32)..]);
    let ballot = match from_bytes::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot_bytes) {
        Ok(b) => b,
        Err(e) => {
            println!("[verify_vote] ERROR deserializing ballot: {:?}", e);
            return ByteBuffer::from(vec![0; 32]);
        }
    };

    let params = ChoiceParams::single(public_key, candidate_count.to());

    let mut output = vec![0; 32];

    if let Ok(_) = ballot.verify(&params) {
        println!("[verify_vote] verification PASSED");
        output[31] = 1;
    } else {
        println!("[verify_vote] verification FAILED");
    };

    ByteBuffer::from(output)
}

/// Add vote to result vector
#[unsafe(no_mangle)]
pub extern "C" fn add_votes(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= ADD VOTE =============");
    println!("[add_votes] input length: {}", length);
    let data = parse_vector(buffer, length);

    let (acc, ballot) = match <(Bytes, Bytes)>::abi_decode_sequence(&data) {
        Ok(v) => v,
        Err(e) => {
            println!("[add_votes] ERROR abi_decode_sequence: {:?}", e);
            return ByteBuffer::from(vec![]);
        }
    };
    println!("[add_votes] acc len: {}, ballot len: {}", acc.len(), ballot.len());

    let mut acc = match from_bytes::<Vec<Ciphertext<Ristretto>>>(&acc.to_vec()) {
        Ok(v) => v,
        Err(e) => {
            println!("[add_votes] ERROR deserializing acc: {:?}", e);
            return ByteBuffer::from(vec![]);
        }
    };
    println!("[add_votes] acc entries: {}", acc.len());

    let ballot_bytes = ballot.to_vec();
    println!("[add_votes] ballot first 64 bytes: {:02x?}", &ballot_bytes[..ballot_bytes.len().min(64)]);
    let ballot = match from_bytes::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot_bytes) {
        Ok(b) => b,
        Err(e) => {
            println!("[add_votes] ERROR deserializing ballot: {:?}", e);
            return ByteBuffer::from(vec![]);
        }
    };

    for (i, choice) in ballot.choices_unchecked().iter().enumerate() {
        acc[i] += *choice;
    }

    ByteBuffer::from(to_allocvec(&acc).unwrap())
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_signature(buffer: *const u8, length: usize) -> ByteBuffer {
    println!("============= VERIFY SIGNATURE =============");
    println!("[verify_signature] input length: {}", length);
    let data = parse_vector(buffer, length);

    let (public_key_der, msg, signature) = match <(Bytes, Bytes, Bytes)>::abi_decode_sequence(&data) {
        Ok(v) => v,
        Err(e) => {
            println!("[verify_signature] ERROR abi_decode_sequence: {:?}", e);
            return ByteBuffer::from(vec![0; 32]);
        }
    };
    println!("[verify_signature] pubkey_der len: {}, msg len: {}, sig len: {}", public_key_der.len(), msg.len(), signature.len());

    let public_key = match blind_rsa_signatures::PublicKey::<Sha384, PSS, Deterministic>::from_der(&public_key_der) {
        Ok(pk) => pk,
        Err(e) => {
            println!("[verify_signature] ERROR parsing public key DER: {:?}", e);
            return ByteBuffer::from(vec![0; 32]);
        }
    };

    let signature = Signature::new(signature.to_vec());

    let mut output = vec![0; 32];

    match public_key.verify(&signature, None, msg) {
        Ok(_) => {
            println!("[verify_signature] verification PASSED");
            output[31] = 1;
        }
        Err(e) => {
            println!("[verify_signature] verification FAILED: {:?}", e);
        }
    }

    ByteBuffer::from(output)
}
