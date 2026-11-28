//! Credential generation over the library's own crypto (ADR-0005):
//! mobile consumers must never implement randomness themselves.

use serde_json::{Value, json};

/// Kinds exposed by `generateCredentials` and declared in the schema export
/// (`credential_kinds`). Every result is a structured JSON object; errors are
/// structured messages the JNI layer serializes as `{"error": "..."}`.
pub fn generate_credentials(kind: &str) -> Result<Value, String> {
    match kind {
        "reality_keypair" => {
            let (private_key, public_key) =
                crate::reality::generate_keypair().map_err(|error| error.to_string())?;
            // short_id travels in the cleartext part of the Reality handshake:
            // per-profile randomness, never a shared documentation literal.
            use aws_lc_rs::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut short_id = [0u8; 8];
            rng.fill(&mut short_id).map_err(|error| error.to_string())?;
            let short_id: String = short_id.iter().map(|byte| format!("{byte:02x}")).collect();
            Ok(json!({ "private_key": private_key, "public_key": public_key, "short_id": short_id }))
        }
        "vless_user_id" => Ok(json!({ "user_id": crate::uuid_util::generate_uuid() })),
        // Mirrors the CLI `generate-shadowsocks-2022-password` flow for the
        // default 2022-blake3-aes-256-gcm cipher (32-byte key, standard base64).
        "shadowsocks_2022_password" => {
            use aws_lc_rs::rand::{SecureRandom, SystemRandom};
            use base64::Engine;
            use base64::engine::general_purpose::STANDARD;
            const CIPHER: &str = "2022-blake3-aes-256-gcm";
            let cipher = crate::shadowsocks::ShadowsocksCipher::try_from(
                CIPHER
                    .strip_prefix("2022-blake3-")
                    .expect("known 2022 cipher prefix"),
            )
            .map_err(|error| error.to_string())?;
            let rng = SystemRandom::new();
            let mut key_bytes = vec![0u8; cipher.key_len()];
            rng.fill(&mut key_bytes).map_err(|error| error.to_string())?;
            Ok(json!({
                "cipher": CIPHER,
                "password": STANDARD.encode(&key_bytes),
            }))
        }
        // Same generator as the CLI `generate-vless-encryption` with its
        // default options (native, 0rtt, scaled 600s lifetime, mlkem768x25519).
        "vless_encryption" => {
            let (encryption, decryption) = crate::vless::encryption::generator::generate(&[])
                .map_err(|error| error.to_string())?;
            Ok(json!({
                "encryption": encryption,
                "decryption": decryption.to_string(),
            }))
        }
        other => Err(format!("Unsupported credential kind: {other}")),
    }
}

/// Serialize a `generate_credentials` result for the JNI boundary: values are
/// returned as-is, errors become the structured `{"error": ...}` document.
pub fn generate_credentials_json(kind: &str) -> String {
    match generate_credentials(kind) {
        Ok(value) => serde_json::to_string(&value)
            .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}")),
        Err(message) => {
            let escaped = message.replace('\\', "\\\\").replace('"', "\\\"");
            format!("{{\"error\":\"{escaped}\"}}")
        }
    }
}
