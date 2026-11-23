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
    let credentials = SampleCredentials {
        user_id: generate_credentials("vless_user_id")
            .expect("uuid")
            .get("user_id")
            .and_then(Value::as_str)
            .expect("user_id")
            .to_string(),
        password: String::new(),
        public_key: generate_credentials("reality_keypair")
            .expect("keypair")
            .get("public_key")
            .and_then(Value::as_str)
            .expect("public_key")
            .to_string(),
    };
    let private_key = generate_credentials("reality_keypair")
        .expect("keypair")
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
        .replace("{{USER_ID}}", &credentials.user_id);

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
