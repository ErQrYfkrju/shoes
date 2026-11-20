use super::{compile_configs, convert_cert_paths, load_configs, parse_config_yaml};

#[tokio::test]
async fn nested_parse_errors_include_source_and_field_context_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested.yaml");
    let prefix = r#"- clash_api_address: '127.0.0.1:9090'
  secret: CONTROLLER_SECRET_SENTINEL
- pem: private
  data: |
    -----BEGIN PRIVATE KEY-----
    PEM_SECRET_SENTINEL
    -----END PRIVATE KEY-----
"#;
    for (entry, context) in [
        (
            r#"- rule_source_group: imported
  rules:
    - path: [VALUE_SECRET_SENTINEL]
"#,
            "rules[0]",
        ),
        (
            r#"- rule_source_group: imported
  rules:
    - first.srs
    - path: second.srs
      unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "rules[1]",
        ),
        (
            r#"- rule_source_group: imported
  rules:
    path: second.srs
    unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "rules:",
        ),
        (
            r#"- rule_group: policy
  rules:
    - masks: example.com
    - action: [VALUE_SECRET_SENTINEL]
"#,
            "rules[1]",
        ),
        (
            r#"- rule_group: policy
  rules:
    action: [VALUE_SECRET_SENTINEL]
"#,
            "rules:",
        ),
        (
            r#"- global_settings:
    unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "unknown field `unsupported_policy`",
        ),
        (
            r#"- address: '127.0.0.1:1080'
  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}
  tcp_settings:
    no_delay: [VALUE_SECRET_SENTINEL]
"#,
            "tcp_settings",
        ),
        (
            r#"- address: '127.0.0.1:1080'
  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}
  tcp_settings:
    unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "unknown field `unsupported_policy`",
        ),
    ] {
        std::fs::write(&path, format!("{prefix}{entry}")).unwrap();
        let Err(error) = load_configs(&[path.to_str().unwrap().into()]).await else {
            panic!("invalid configuration must reject");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(path.to_str().unwrap()), "{diagnostic}");
        assert!(diagnostic.contains(context), "{diagnostic}");
        assert!(diagnostic.contains("config[2]"), "{diagnostic}");
        assert!(!diagnostic.contains("SECRET_SENTINEL"), "{diagnostic}");
        assert!(!diagnostic.contains("BEGIN PRIVATE KEY"), "{diagnostic}");
    }
}

#[test]
fn loader_preserves_strict_document_structure() {
    for invalid in [
        r#"address: '127.0.0.1:1080'
protocol: {type: socks}"#,
        r#"[]
---
[]"#,
        "- 42",
        r#"- global_settings: {}
  global_settings: {}"#,
        r#"- pem: private
  data: SECRET_SENTINEL
  unsupported_policy: true"#,
        r#"- pem: private
  path: private.pem
  unsupported_policy: true"#,
    ] {
        let Err(error) = parse_config_yaml(invalid) else {
            panic!("invalid document must reject");
        };
        let error = error.to_string();
        assert!(!error.contains("SECRET_SENTINEL"), "{error}");
    }
    assert!(parse_config_yaml("[]").unwrap().is_empty());
}

#[test]
fn loader_preserves_yaml_error_locations() {
    for prefix in ["# lead\n", "---\n", "\n", ""] {
        for invalid in [
            "- address: '127.0.0.1:1080'\n  tcp_settings: [\n",
            "- global_settings: {}\n  global_settings: {}\n",
            "- global_settings: {}\n- global_settings: {}\n  global_settings: {}\n",
        ] {
            let yaml = format!("{prefix}{invalid}");
            let Err(expected) = serde_yaml::from_str::<Vec<super::Config>>(&yaml) else {
                panic!("invalid YAML must reject");
            };
            let Err(error) = parse_config_yaml(&yaml) else {
                panic!("invalid YAML must reject");
            };
            assert_eq!(error.to_string(), expected.to_string());
            let expected = expected.location().unwrap();
            let actual = error.location().unwrap();
            assert_eq!(actual.line(), expected.line());
            assert_eq!(actual.column(), expected.column());
        }
    }
}

#[test]
fn loader_reports_first_invalid_entry_before_decoding_later_entries() {
    let yaml = r#"- global_settings: {unsupported_policy: true}
- global_settings: {}
  global_settings: {}
"#;
    let Err(error) = parse_config_yaml(yaml) else {
        panic!("invalid configuration must reject");
    };
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("config[0]"), "{diagnostic}");
    assert!(
        diagnostic.contains("unknown field `unsupported_policy`"),
        "{diagnostic}"
    );
}

#[test]
fn tcp_settings_reject_unknown_fields_for_servers_and_clients() {
    for yaml in [
        r#"- address: '127.0.0.1:1080'
  protocol: {type: socks}
  tcp_settings: {unsupported_policy: true}"#,
        r#"- client_group: proxy
  client_chains:
    address: '127.0.0.1:1080'
    protocol: {type: socks}
    tcp_settings: {unsupported_policy: true}"#,
    ] {
        assert!(parse_config_yaml(yaml).is_err());
        assert!(parse_config_yaml(&yaml.replace("unsupported_policy", "no_delay")).is_ok());
    }
}

#[tokio::test]
async fn representative_examples_pass_native_validation() {
    for example in [
        "quickstart_socks.yaml",
        "kcp.yaml",
        "socks_basic.yaml",
        "snell.yaml",
        "snell_forward_rules.yaml",
        "http_through_socks.yaml",
        "multi_hop_chain.yaml",
        "chain_groups.yaml",
        "clash_api.yaml",
        "url_test.yaml",
        "rule_sources.yaml",
        "rule_conditions.yaml",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(example);
        let configs = load_configs(&[path.to_str().unwrap().into()])
            .await
            .unwrap_or_else(|error| panic!("{example}: {error}"));
        let (configs, _) = convert_cert_paths(configs)
            .await
            .unwrap_or_else(|error| panic!("{example}: {error}"));
        let validated = compile_configs(configs)
            .await
            .unwrap_or_else(|error| panic!("{example}: {error}"));
        if validated.catalog.is_some() {
            crate::control::validation::validate_resources(&validated)
                .unwrap_or_else(|error| panic!("{example}: {error}"));
        }
        assert!(!validated.configs.is_empty(), "{example}");
    }
}

#[tokio::test]
async fn android_representative_assets_pass_native_validation() {
    for asset in ["android_vpn.yaml", "android_proxy_kcp.yaml"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(asset);
        let configs = load_configs(&[path.to_str().unwrap().into()])
            .await
            .unwrap_or_else(|error| panic!("{asset}: {error}"));
        let validated = compile_configs(configs)
            .await
            .unwrap_or_else(|error| panic!("{asset}: {error}"));
        validated
            .validate_ffi_support()
            .unwrap_or_else(|error| panic!("{asset}: {error}"));
        assert!(!validated.configs.is_empty(), "{asset}");
    }

    let vpn = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/android_vpn.yaml"),
    )
    .unwrap();
    assert!(vpn.contains("device_fd: -1"));
}

#[tokio::test]
async fn kcp_server_config_preserves_settings() {
    let configs = parse_config_yaml(
        r#"- address: '127.0.0.1:1080'
  transport: kcp
  kcp_settings:
    mode: file_transfer
    send_window: 128
    recv_window: 256
    mtu: 1400
    max_sessions: 32
  protocol: {type: socks}
"#,
    )
    .unwrap();
    let validated = compile_configs(configs).await.unwrap();
    let super::ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!("expected a resolved server config");
    };

    assert_eq!(server.transport, super::Transport::Kcp);
    let settings = server.kcp_settings.as_ref().unwrap();
    assert_eq!(settings.mode, super::KcpMode::FileTransfer);
    assert_eq!(settings.send_window, Some(128));
    assert_eq!(settings.recv_window, Some(256));
    assert_eq!(settings.mtu, Some(1400));
    assert_eq!(settings.max_sessions, 32);
}

#[tokio::test]
async fn kcp_client_config_preserves_settings() {
    let configs = parse_config_yaml(
        r#"- address: '127.0.0.1:1080'
  protocol: {type: socks}
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        - address: '192.0.2.1:1080'
          transport: kcp
          kcp_settings:
            mode: fast
            send_window: 64
            recv_window: 128
            mtu: 1300
            max_sessions: 16
          protocol: {type: socks}
"#,
    )
    .unwrap();
    let validated = compile_configs(configs).await.unwrap();
    let super::ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!("expected a resolved server config");
    };
    let rules = server.rules.clone().into_vec();
    let super::ResolvedRuleActionConfig::Allow { client_chains, .. } = &rules[0].action else {
        panic!("expected an allow rule with a client chain");
    };
    let chains = client_chains.clone().into_vec();
    let chain = chains.first().unwrap();
    let hop = chain.hops.iter().next().unwrap();
    let super::ResolvedClientHop::Single(client) = hop else {
        panic!("expected a single resolved client hop");
    };

    assert_eq!(client.transport, super::Transport::Kcp);
    let settings = client.kcp_settings.as_ref().unwrap();
    assert_eq!(settings.mode, super::KcpMode::Fast);
    assert_eq!(settings.send_window, Some(64));
    assert_eq!(settings.recv_window, Some(128));
    assert_eq!(settings.mtu, Some(1300));
    assert_eq!(settings.max_sessions, 16);
}

#[test]
fn kcp_file_transfer_mode_aliases_deserialize() {
    for name in ["file_transfer", "filetransfer"] {
        let settings: super::KcpSettings = serde_yaml::from_str(&format!("mode: {name}\n"))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(settings.mode, super::KcpMode::FileTransfer);
    }
}

fn reset_kcp_network_spies() {
    crate::kcp_server::reset_test_bind_calls();
    crate::tcp::socket_connector_impl::reset_test_dial_calls();
}

fn assert_kcp_network_unused() {
    assert_eq!(
        crate::kcp_server::test_bind_calls(),
        0,
        "KCP bind was called"
    );
    assert_eq!(
        crate::tcp::socket_connector_impl::test_dial_calls(),
        0,
        "KCP dial was called"
    );
}

async fn assert_kcp_rejected_without_network(yaml: &str, expected: &str) {
    reset_kcp_network_spies();
    let configs = match parse_config_yaml(yaml) {
        Ok(configs) => configs,
        Err(error) => {
            let diagnostic = error.to_string();
            assert!(diagnostic.contains(expected), "{diagnostic}");
            assert_kcp_network_unused();
            return;
        }
    };
    let error = match compile_configs(configs).await {
        Ok(_) => panic!("invalid KCP configuration must reject"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let diagnostic = error.to_string();
    assert!(diagnostic.contains(expected), "{diagnostic}");
    assert_kcp_network_unused();
}

#[tokio::test]
async fn kcp_settings_reject_unknown_fields() {
    let server_yaml = r#"- address: '127.0.0.1:1080'
  transport: kcp
  kcp_settings: {unsupported_policy: true}
  protocol: {type: socks}
"#;
    assert_kcp_rejected_without_network(server_yaml, "unknown field `unsupported_policy`").await;

    reset_kcp_network_spies();
    let error = serde_yaml::from_str::<super::ClientConfig>(
        r#"address: '192.0.2.1:1080'
transport: kcp
kcp_settings: {unsupported_policy: true}
protocol: {type: socks}
"#,
    )
    .unwrap_err();
    let diagnostic = error.to_string();
    assert!(
        diagnostic.contains("unknown field `unsupported_policy`"),
        "{diagnostic}"
    );
    assert_kcp_network_unused();
}

#[tokio::test]
async fn kcp_window_settings_reject_invalid_ranges() {
    for (settings, expected) in [
        ("send_window: 0\n    recv_window: 128", "send_window"),
        ("send_window: 65536\n    recv_window: 128", "send_window"),
        ("send_window: 128\n    recv_window: 65536", "recv_window"),
    ] {
        let yaml = format!(
            r#"- address: '127.0.0.1:1080'
  transport: kcp
  kcp_settings:
    {settings}
  protocol: {{type: socks}}
"#
        );
        assert_kcp_rejected_without_network(&yaml, expected).await;
    }
}

#[tokio::test]
async fn kcp_window_settings_require_a_complete_pair() {
    let yaml = r#"- address: '127.0.0.1:1080'
  transport: kcp
  kcp_settings:
    send_window: 128
  protocol: {type: socks}
"#;
    assert_kcp_rejected_without_network(yaml, "specified together").await;
}

#[tokio::test]
async fn kcp_mtu_rejects_unsupported_values() {
    for mtu in [24, 65_536] {
        let yaml = format!(
            r#"- address: '127.0.0.1:1080'
  transport: kcp
  kcp_settings:
    mtu: {mtu}
  protocol: {{type: socks}}
"#
        );
        assert_kcp_rejected_without_network(&yaml, "mtu").await;
    }
}

#[tokio::test]
async fn kcp_max_sessions_rejects_zero() {
    let yaml = r#"- address: '127.0.0.1:1080'
  transport: kcp
  kcp_settings:
    max_sessions: 0
  protocol: {type: socks}
"#;
    assert_kcp_rejected_without_network(yaml, "max_sessions").await;
}

#[tokio::test]
async fn kcp_client_requires_peer_address() {
    let yaml = r#"- address: '127.0.0.1:1080'
  protocol: {type: socks}
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        - transport: kcp
          kcp_settings: {mode: fast}
          protocol: {type: socks}
"#;
    assert_kcp_rejected_without_network(yaml, "address").await;
}

#[tokio::test]
async fn kcp_settings_require_kcp_transport() {
    let yaml = r#"- address: '127.0.0.1:1080'
  transport: tcp
  kcp_settings: {mode: fast}
  protocol: {type: socks}
"#;
    assert_kcp_rejected_without_network(yaml, "KCP transport is not selected").await;
}
