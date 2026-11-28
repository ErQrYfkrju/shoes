//! Tests for `generateCredentials` (ADR-0005): library crypto only, structured
//! results, paired server templates validate with the generated material.

use super::config_credentials::{generate_credentials, generate_credentials_json};
use super::config_schema::config_schema;
use super::config_schema_tests::{
    SampleCredentials, substitute_placeholders, wrap_proxy, wrap_vpn,
};
use super::config_validation::{ValidationMode, validate_config};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

#[test]
fn config_credentials_all_kinds_generate_structured_values() {
    let keypair = generate_credentials("reality_keypair").expect("reality keypair");
    let private_key = keypair["private_key"].as_str().expect("private_key");
    let public_key = keypair["public_key"].as_str().expect("public_key");
    assert_eq!(private_key.len(), 43, "X25519 private key is 32 bytes base64url");
    assert_eq!(public_key.len(), 43, "X25519 public key is 32 bytes base64url");
    let short_id = keypair["short_id"].as_str().expect("short_id");
    assert_eq!(short_id.len(), 16, "reality short_id is 8 bytes hex");
    assert!(
        short_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "short_id must be hex: {short_id}"
    );

    let user_id = generate_credentials("vless_user_id")
        .expect("uuid")
        .get("user_id")
        .and_then(Value::as_str)
        .expect("user_id")
        .to_string();
    assert!(crate::uuid_util::parse_uuid(&user_id).is_ok(), "{user_id}");

    let password = generate_credentials("shadowsocks_2022_password").expect("ss2022 password");
    let encoded = password["password"].as_str().expect("password");
    assert_eq!(
        STANDARD.decode(encoded).expect("base64").len(),
        32,
        "2022-blake3-aes-256-gcm key length"
    );

    let vless = generate_credentials("vless_encryption").expect("vless encryption");
    assert!(vless["encryption"].as_str().expect("encryption").contains('.'));
    assert!(vless["decryption"].as_str().expect("decryption").contains('.'));
}

#[test]
fn config_credentials_reality_short_id_differs_between_generations() {
    let first = generate_credentials("reality_keypair").expect("first keypair");
    let second = generate_credentials("reality_keypair").expect("second keypair");
    let first_short = first["short_id"].as_str().expect("first short_id");
    let second_short = second["short_id"].as_str().expect("second short_id");
    assert_ne!(
        first_short, second_short,
        "short_id must be unique per profile, not a shared literal"
    );
}

#[test]
fn config_schema_export_contains_no_fixed_reality_short_id() {
    // The documentation placeholder literal would give every generated profile
    // the same cleartext fingerprint in the Reality handshake.
    let raw = config_schema().to_string();
    assert!(
        !raw.contains("0123456789abcdef"),
        "fixed short_id literal leaked into the schema export"
    );
}

#[test]
fn config_credentials_unknown_kind_returns_structured_error() {
    assert!(generate_credentials("teleport").is_err());
    let json = generate_credentials_json("teleport");
    let parsed: Value = serde_json::from_str(&json).expect("error json parses");
    let message = parsed["error"].as_str().expect("error field");
    assert!(message.contains("teleport"), "error names the kind: {message}");
}

#[tokio::test]
async fn config_credentials_vless_reality_pair_validates_natively() {
    let schema = config_schema();
    // One generation supplies the whole keypair: private/public/short_id must
    // stay a matched set across the client and server fragments.
    let keypair = generate_credentials("reality_keypair").expect("keypair");
    let credentials = SampleCredentials {
        user_id: generate_credentials("vless_user_id")
            .expect("uuid")
            .get("user_id")
            .and_then(Value::as_str)
            .expect("user_id")
            .to_string(),
        password: String::new(),
        public_key: keypair
            .get("public_key")
            .and_then(Value::as_str)
            .expect("public_key")
            .to_string(),
        short_id: keypair
            .get("short_id")
            .and_then(Value::as_str)
            .expect("short_id")
            .to_string(),
    };
    let private_key = keypair
        .get("private_key")
        .and_then(Value::as_str)
        .expect("private_key")
        .to_string();

    let preset = schema["presets"]
        .as_array()
        .expect("presets")
        .iter()
        .find(|preset| preset["name"] == "vless_reality")
        .expect("vless_reality preset");
    let client_profile = substitute_placeholders(preset["yaml"].as_str().expect("yaml"), &credentials);

    let server_yaml = schema["server_pair_templates"]["vless_reality"]
        .as_str()
        .expect("server template")
        .replace("{{PORT}}", "443")
        .replace("{{PRIVATE_KEY}}", &private_key)
        .replace("{{USER_ID}}", &credentials.user_id)
        .replace("{{SHORT_ID}}", &credentials.short_id);

    // The pair validates as a set: client in both modes, server in proxy mode.
    for mode in [ValidationMode::Proxy, ValidationMode::Vpn] {
        let wrapped = match mode {
            ValidationMode::Proxy => wrap_proxy(&client_profile),
            ValidationMode::Vpn => wrap_vpn(&client_profile),
        };
        let report = validate_config(&wrapped, mode).await;
        assert!(
            report.valid,
            "vless_reality client invalid in {mode:?}: {:?}\n{}",
            report.diagnostics,
            wrapped
        );
    }
    let report = validate_config(&server_yaml, ValidationMode::Proxy).await;
    assert!(
        report.valid,
        "vless_reality server invalid: {:?}\n{}",
        report.diagnostics,
        server_yaml
    );

    // Private key material must never leak into the client fragment.
    assert!(
        !client_profile.contains(&private_key),
        "private key leaked into the client profile"
    );
    assert!(server_yaml.contains(&private_key), "server substitution failed");
    // The generated short_id pairs the fragments: client sends it, server lists it.
    assert!(
        client_profile.contains(&credentials.short_id),
        "client fragment lost the generated short_id"
    );
    assert!(
        server_yaml.contains(&credentials.short_id),
        "server fragment does not list the generated short_id"
    );
}

#[tokio::test]
async fn config_credentials_anytls_kcp_pair_validates_natively() {
    let schema = config_schema();
    let credentials = super::config_schema_tests::sample_credentials();

    let preset = schema["presets"]
        .as_array()
        .expect("presets")
        .iter()
        .find(|preset| preset["name"] == "anytls_kcp")
        .expect("anytls_kcp preset");
    let client_profile = substitute_placeholders(preset["yaml"].as_str().expect("yaml"), &credentials);

    let server_yaml = schema["server_pair_templates"]["anytls_kcp"]
        .as_str()
        .expect("server template")
        .replace("{{PORT}}", "19090")
        .replace("{{PASSWORD}}", &credentials.password);

    for mode in [ValidationMode::Proxy, ValidationMode::Vpn] {
        let wrapped = match mode {
            ValidationMode::Proxy => wrap_proxy(&client_profile),
            ValidationMode::Vpn => wrap_vpn(&client_profile),
        };
        let report = validate_config(&wrapped, mode).await;
        assert!(
            report.valid,
            "anytls_kcp client invalid in {mode:?}: {:?}\n{}",
            report.diagnostics,
            wrapped
        );
    }
    let report = validate_config(&server_yaml, ValidationMode::Proxy).await;
    assert!(
        report.valid,
        "anytls_kcp server invalid: {:?}\n{}",
        report.diagnostics,
        server_yaml
    );
}
