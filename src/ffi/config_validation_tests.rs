use super::config_validation::{
    DiagnosticCode, MAX_DIAGNOSTIC_MESSAGE_BYTES, MAX_DIAGNOSTICS, ValidationDiagnostic,
    ValidationMode, ValidationReport, validate_config,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use gotatun::x25519::{PublicKey, StaticSecret};
use std::{sync::Arc, time::Duration};

const PASSWORD_SENTINEL: &str = "PASSWORD_SECRET_SENTINEL";
const PRIVATE_KEY_SENTINEL: &str = "PRIVATE_KEY_SECRET_SENTINEL";

fn valid_proxy_yaml() -> &'static str {
    r#"
- address: "127.0.0.1:0"
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: direct
"#
}

fn valid_vpn_yaml() -> &'static str {
    r#"
- device_fd: -1
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: direct
"#
}

#[tokio::test]
async fn valid_proxy_report_has_version_one_and_no_diagnostics() {
    let report = validate_config(valid_proxy_yaml(), ValidationMode::Proxy).await;
    assert_eq!(report.schema_version, 1);
    assert!(report.valid);
    assert!(report.diagnostics.is_empty());
}

#[tokio::test]
async fn valid_vpn_report_accepts_android_fd_placeholder() {
    let report = validate_config(valid_vpn_yaml(), ValidationMode::Vpn).await;
    assert!(report.valid, "{report:?}");
}

#[tokio::test]
async fn empty_config_has_specific_code() {
    let report = validate_config("", ValidationMode::Proxy).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::EmptyConfig);
}

#[tokio::test]
async fn yaml_syntax_error_has_source_location_when_available() {
    let report = validate_config("- address: [\n", ValidationMode::Proxy).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::YamlSyntax);
    assert!(report.diagnostics[0].line.is_some());
    assert!(report.diagnostics[0].column.is_some());
}

#[tokio::test]
async fn unsupported_field_has_entry_and_path() {
    let yaml = r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  unsupported_policy: true
"#;
    let report = validate_config(yaml, ValidationMode::Proxy).await;
    assert!(!report.valid);
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, DiagnosticCode::ConfigSchema);
    assert_eq!(diagnostic.entry, Some(0));
    assert!(
        diagnostic
            .path
            .as_deref()
            .is_some_and(|path| path.contains("unsupported_policy")),
        "{diagnostic:?}"
    );
}

#[tokio::test]
async fn invalid_kcp_setting_has_semantic_code() {
    let yaml = r#"
- address: "127.0.0.1:0"
  transport: kcp
  kcp_settings:
    send_window: 128
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: direct
"#;
    let report = validate_config(yaml, ValidationMode::Proxy).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::ConfigSemantic);
}

#[tokio::test]
async fn proxy_rejects_tun_config() {
    let report = validate_config(valid_vpn_yaml(), ValidationMode::Proxy).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::ModeIncompatible);
}

#[tokio::test]
async fn vpn_rejects_missing_tun_config() {
    let report = validate_config(valid_proxy_yaml(), ValidationMode::Vpn).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::ModeIncompatible);
}

#[tokio::test]
async fn proxy_rejects_wireguard_config() {
    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }
    fn public(byte: u8) -> String {
        STANDARD.encode(PublicKey::from(&StaticSecret::from([byte; 32])).as_bytes())
    }
    let yaml = format!(
        r#"
- address: "127.0.0.1:51820"
  protocol:
    type: wireguard
    private_key: "{}"
    addresses: ["10.77.0.1/32"]
    peers:
      - public_key: "{}"
        allowed_ips: ["10.77.0.2/32"]
  rules: block-all
"#,
        key(41),
        public(42)
    );
    let report = validate_config(&yaml, ValidationMode::Proxy).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::ModeIncompatible);
}

#[tokio::test]
async fn missing_local_pem_has_local_io_code() {
    let yaml = r#"
- pem: missing-local-certificate
  path: "/definitely/not/present/certificate.pem"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rules: block-all
"#;
    let report = validate_config(yaml, ValidationMode::Proxy).await;
    assert!(!report.valid);
    assert_eq!(report.diagnostics[0].code, DiagnosticCode::LocalIo);
}

#[tokio::test]
async fn validation_does_not_bind_or_start_service() {
    let _lifecycle = super::common::SERVICE_LIFECYCLE.lock();
    let yaml = r#"
- address: "127.0.0.1:0"
  transport: kcp
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: direct
"#;

    // Seed the spy through the same Shoes server consumer used in production.
    crate::kcp_server::reset_test_bind_calls();
    let validated = super::common::compile_ffi_config(yaml)
        .await
        .expect("seed KCP config must validate");
    let resolved = validated
        .configs
        .into_iter()
        .next()
        .expect("seed config must contain one server");
    let crate::config::ResolvedConfig::Server(resolved) = resolved else {
        panic!("seed config must be a server");
    };
    let handles = crate::kcp_server::start_kcp_servers(
        resolved,
        Arc::new(crate::resolver::NativeResolver::new()),
    )
    .await
    .expect("seed server must bind");
    assert_eq!(crate::kcp_server::test_bind_calls(), 1);
    for handle in handles {
        handle.abort();
    }

    crate::kcp_server::reset_test_bind_calls();
    assert!(!super::common::is_service_running());
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        validate_config(yaml, ValidationMode::Proxy),
    )
    .await
    .expect("validation attempted an upstream connection");
    assert!(report.valid, "{report:?}");
    assert_eq!(crate::kcp_server::test_bind_calls(), 0);
    assert!(!super::common::is_service_running());
}

#[tokio::test]
async fn bare_socks_server_entry_without_rules_is_valid() {
    let yaml = r#"
- address: "127.0.0.1:19090"
  transport: kcp
  protocol:
    type: socks
"#;
    let report = validate_config(yaml, ValidationMode::Proxy).await;
    assert!(report.valid, "{report:?}");
}

#[tokio::test]
async fn validation_report_does_not_leak_secret_scalars() {
    let yaml = format!(
        r#"
- address: "127.0.0.1:1080"
  protocol:
    type: shadowsocks
    cipher: "{PASSWORD_SENTINEL} {PRIVATE_KEY_SENTINEL}"
    password: unused
  rules: block-all
"#
    );
    let report = validate_config(&yaml, ValidationMode::Proxy).await;
    assert!(!report.valid);
    let rendered = serde_json::to_string(&report).expect("validation report must serialize");
    assert!(
        !rendered.contains(PASSWORD_SENTINEL),
        "password sentinel leaked: {rendered}"
    );
    assert!(
        !rendered.contains(PRIVATE_KEY_SENTINEL),
        "private-key sentinel leaked: {rendered}"
    );
}

#[test]
fn diagnostic_message_is_bounded_at_utf8_boundaries() {
    let diagnostic = ValidationDiagnostic::new(
        DiagnosticCode::Internal,
        "я".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES * 2),
        None,
        None,
        None,
        None,
    );
    assert!(diagnostic.message.len() <= MAX_DIAGNOSTIC_MESSAGE_BYTES);
    assert!(!diagnostic.message.is_empty());
}

#[test]
fn diagnostic_count_is_bounded() {
    let diagnostics = (0..MAX_DIAGNOSTICS * 2)
        .map(|_| {
            ValidationDiagnostic::new(
                DiagnosticCode::ConfigSemantic,
                "error",
                None,
                None,
                None,
                None,
            )
        })
        .collect();
    let report = ValidationReport::from_diagnostics(diagnostics);
    assert!(!report.valid);
    assert!(report.diagnostics.len() <= MAX_DIAGNOSTICS);
}

