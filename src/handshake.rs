use anyhow::Result;

use rand::rngs::OsRng;

use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    Oaep,
    RsaPrivateKey,
    RsaPublicKey,
};

use sha2::Sha256;

/// Generate a new 2048-bit RSA keypair.
pub fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;

    let private = RsaPrivateKey::new(&mut rng, 2048)?;

    let public = RsaPublicKey::from(&private);

    Ok((private, public))
}

/// Convert public key to PEM bytes.
pub fn public_key_to_bytes(public: &RsaPublicKey) -> Result<Vec<u8>> {
    Ok(public
        .to_public_key_pem(Default::default())?
        .into_bytes())
}

/// Load public key from PEM bytes.
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<RsaPublicKey> {
    let pem = std::str::from_utf8(bytes)?;

    Ok(RsaPublicKey::from_public_key_pem(pem)?)
}

/// Encrypt AES session key.
pub fn encrypt_session_key(
    public: &RsaPublicKey,
    session_key: &[u8],
) -> Result<Vec<u8>> {
    let mut rng = OsRng;

    Ok(public.encrypt(
        &mut rng,
        Oaep::new::<Sha256>(),
        session_key,
    )?)
}

/// Decrypt AES session key.
pub fn decrypt_session_key(
    private: &RsaPrivateKey,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    Ok(private.decrypt(
        Oaep::new::<Sha256>(),
        encrypted,
    )?)
}