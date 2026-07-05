use aes::Aes256;

use ctr::{
    cipher::{KeyIvInit,StreamCipher},
};

type AesCtr=ctr::Ctr128BE<Aes256>;

fn build_counter(
    nonce:&[u8;16],
    chunk_id:u32
)->[u8;16]{

    let mut counter=[0u8;16];

    counter[..8].copy_from_slice(
        &nonce[..8]
    );

    counter[8..].copy_from_slice(
        &(chunk_id as u64).to_be_bytes()
    );

    counter

}

pub fn encrypt_chunk(
    data: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
    chunk_id: u32,
) {
    let counter = build_counter(nonce, chunk_id);

    let mut cipher = AesCtr::new(
        key.into(),
        &counter.into(),
    );

    cipher.apply_keystream(data);
}
pub fn decrypt_chunk(
    data: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
    chunk_id: u32,
) {
    // AES-CTR decrypt == encrypt
    encrypt_chunk(
        data,
        key,
        nonce,
        chunk_id,
    );
}