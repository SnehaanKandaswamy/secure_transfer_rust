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

    data:&[u8],

    key:&[u8;32],

    nonce:&[u8;16],

    chunk_id:u32,

)->Vec<u8>{

    let counter=
        build_counter(
            nonce,
            chunk_id
        );

    let mut cipher=
        AesCtr::new(
            key.into(),
            &counter.into()
        );

    let mut output=data.to_vec();

    cipher.apply_keystream(
        &mut output
    );

    output

}

pub fn decrypt_chunk(

    encrypted:&[u8],

    key:&[u8;32],

    nonce:&[u8;16],

    chunk_id:u32,

)->Vec<u8>{

    encrypt_chunk(

        encrypted,

        key,

        nonce,

        chunk_id,

    )

}