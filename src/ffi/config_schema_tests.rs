use super::config_schema::config_schema;
use super::config_credentials::generate_credentials;
use super::config_validation::{ValidationMode, validate_config};
use serde_json::Value;

const PASSWORD_SENTINEL: &str = "SUPER_SECRET_DEFAULT";

/// Test-time credentials for placeholder substitution, mirroring what the
/// Kotlin side obtains from `generateCredentials`.
pub(crate) struct SampleCredentials {
    pub user_id: String,
    pub password: String,
    pub public_key: String,
    pub short_id: String,
}

pub(crate) fn sample_credentials() -> SampleCredentials {
    let uuid = generate_credentials("vless_user_id")
        .expect("uuid generation")
        .get("user_id")
        .and_then(Value::as_str)
        .expect("user_id")
        .to_string();
    let password = generate_credentials("shadowsocks_2022_password")
        .expect("password generation")
        .get("password")
        .and_then(Value::as_str)
        .expect("password")
        .to_string();
    let keypair = generate_credentials("reality_keypair").expect("keypair generation");
    let public_key = keypair
        .get("public_key")
        .and_then(Value::as_str)
        .expect("public_key")
        .to_string();
    let short_id = keypair
        .get("short_id")
        .and_then(Value::as_str)
        .expect("short_id")
        .to_string();
    SampleCredentials {
        user_id: uuid,
        password,
        public_key,
        short_id,
    }
}

pub(crate) fn substitute_placeholders(yaml: &str, credentials: &SampleCredentials) -> String {
    yaml.replace("{{USER_ID}}", &credentials.user_id)
        .replace("{{PASSWORD}}", &credentials.password)
        .replace("{{PUBLIC_KEY}}", &credentials.public_key)
        .replace("{{SHORT_ID}}", &credentials.short_id)
}

/// Embed a profile mapping under `client_chain:` with the given indentation.
pub(crate) fn indent(yaml: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    yaml.lines()
        .map(|line| format!("{pad}{line}\n"))
        .collect()
}

/// Proxy wrapping of a profile preset: local listener + catch-all rule.
pub(crate) fn wrap_proxy(profile_yaml: &str) -> String {
    format!(
        concat!(
            "- address: \"127.0.0.1:1080\"\n",
            "  protocol:\n    type: socks\n",
            "  rules:\n",
            "    - masks: \"0.0.0.0/0\"\n",
            "      action: allow\n",
            "      client_chain:\n"
        ),
    ) + &indent(profile_yaml, 8)
}

/// VPN wrapping of a profile preset: minimal TUN entry (`device_fd: -1`
/// placeholder, no enabled flags, no mtu — shoes defaults apply).
pub(crate) fn wrap_vpn(profile_yaml: &str) -> String {
    concat!(
        "- device_fd: -1\n",
        "  rules:\n",
        "    - masks: \"0.0.0.0/0\"\n",
        "      action: allow\n",
        "      client_chain:\n",
    )
    .to_string()
        + &indent(profile_yaml, 8)
}

#[test]
fn export_is_versioned_with_components() {
    let schema = config_schema();
    assert_eq!(schema["schema_version"], 1);
    let components = schema["components"].as_object().expect("components");
    for key in [
        "server_protocols",
        "client_protocols",
        "transport",
        "kcp_settings",
        "rules",
        "dns",
    ] {
        assert!(components.contains_key(key), "missing component {key}");
    }
}

#[test]
fn profile_skeleton_references_existing_components() {
    let schema = config_schema();
    let components = schema["components"].as_object().expect("components");
    let fields = schema["profile_skeleton"]["fields"]
        .as_array()
        .expect("profile skeleton fields");
    assert!(fields.len() >= 6, "profile skeleton is too small");
    for field in fields {
        if let Some(component) = field["component"].as_str() {
            assert!(
                components.contains_key(component),
                "profile skeleton references unknown component {component}"
            );
        }
    }

    // DNS is one choice over the exported variant ids, with a default that exists.
    let dns_field = fields
        .iter()
        .find(|field| field["key"] == "dns")
        .expect("dns field");
    let ids: Vec<&str> = schema["dns_variants"]
        .as_array()
        .expect("dns variants")
        .iter()
        .filter_map(|variant| variant["id"].as_str())
        .collect();
    let dns_ids: Vec<&str> = dns_field["enum"]
        .as_array()
        .expect("dns enum")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert_eq!(dns_ids, ids, "dns enum must mirror dns_variants ids");
    assert_eq!(dns_field["default"], "via_server_1.1.1.1");
    assert!(
        dns_ids.contains(&"via_server_1.1.1.1"),
        "default dns variant must be in the enum"
    );

    // Conditional kcp defaults come from the documentation.
    let kcp = fields
        .iter()
        .find(|field| field["key"] == "kcp_settings")
        .expect("kcp_settings field");
    assert_eq!(kcp["visible_when"]["sibling"], "transport");
    assert_eq!(kcp["visible_when"]["equals"], "kcp");
    assert_eq!(kcp["defaults"]["mode"], "file_transfer");
    assert_eq!(kcp["defaults"]["mtu"], 1400);

    let custom_url = fields
        .iter()
        .find(|field| field["key"] == "dns_custom_url")
        .expect("dns_custom_url field");
    assert_eq!(custom_url["visible_when"]["sibling"], "dns");
    assert_eq!(custom_url["visible_when"]["equals"], "custom");
}

#[test]
fn presets_carry_stable_title_keys() {
    // title_key is the stable localization key resolved by Kotlin strings;
    // the export title stays for backward compatibility.
    let schema = config_schema();
    let presets = schema["presets"].as_array().expect("presets");
    assert_eq!(presets.len(), 9, "all nine presets carry title_key");
    for preset in presets {
        let name = preset["name"].as_str().expect("name");
        assert_eq!(
            preset["title_key"], format!("preset_{name}"),
            "{name} must expose a stable preset_<name> title_key"
        );
        assert!(
            !preset["title"].as_str().unwrap_or_default().is_empty(),
            "{name} keeps its export title for backward compatibility"
        );
    }
}

#[test]
fn preset_catalog_order_tags_and_scopes() {
    let schema = config_schema();
    let presets = schema["presets"].as_array().expect("presets");
    let names: Vec<&str> = presets
        .iter()
        .filter_map(|preset| preset["name"].as_str())
        .collect();
    assert_eq!(
        names,
        [
            "vless_reality",
            "trojan_tls",
            "vmess_wss",
            "shadowsocks",
            "socks",
            "anytls_kcp",
            "socks_kcp",
            "local_socks",
            "local_mixed",
        ]
    );
    let defaults: Vec<_> = presets
        .iter()
        .filter(|preset| preset["default"].as_bool().unwrap_or(false))
        .collect();
    assert_eq!(defaults.len(), 1, "exactly one default preset");
    assert_eq!(defaults[0]["name"], "vless_reality");
    assert!(
        defaults[0]["hints"]
            .as_array()
            .expect("vless_reality hints")
            .iter()
            .any(|hint| hint == "preset_hint_no_browser_fingerprint"),
        "vless_reality must carry the no-browser-fingerprint hint"
    );
    for preset in presets {
        let scope = preset["scope"].as_str().expect("scope");
        let modes = preset["modes"].as_array().expect("modes");
        match scope {
            "profile" => {
                assert_eq!(
                    serde_json::to_string(modes).unwrap(),
                    r#"["proxy","vpn"]"#,
                    "profile preset {} must be mode-agnostic",
                    preset["name"]
                );
            }
            "service" => {
                assert_eq!(
                    serde_json::to_string(modes).unwrap(),
                    r#"["proxy"]"#,
                    "service preset {} is proxy-only",
                    preset["name"]
                );
            }
            other => panic!("unknown scope {other}"),
        }
    }
    for name in ["anytls_kcp", "socks_kcp"] {
        let preset = presets
            .iter()
            .find(|preset| preset["name"] == name)
            .expect("kcp preset");
        assert_eq!(preset["stability"], "experimental", "{name} stability");
    }
}

#[test]
fn secret_fields_are_marked_from_the_shared_list() {
    let schema = config_schema();
    let marked = super::config_schema::secret_marked_keys(&schema);
    assert!(
        marked.contains(&"password".to_string()),
        "password not marked: {marked:?}"
    );
    assert!(
        marked.contains(&"private_key".to_string()),
        "private_key not marked: {marked:?}"
    );
}

#[test]
fn secret_fields_carry_no_default_values() {
    let schema = config_schema();
    let raw = schema.to_string();
    assert!(
        !raw.contains(PASSWORD_SENTINEL),
        "dummy secret default leaked into the schema"
    );
}

#[test]
fn schema_carries_no_configuration_values() {
    // Descriptions come from doc comments and may mention example hosts;
    // structural nodes must not carry addresses or other configuration values.
    fn structural_strings(value: &Value, parent_key: &str, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    structural_strings(item, key, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    structural_strings(item, parent_key, out);
                }
            }
            Value::String(text) if parent_key != "description" && parent_key != "$schema" => {
                out.push(text.clone())
            }
            _ => {}
        }
    }
    let schema = config_schema();
    let mut strings = Vec::new();
    // Presets, dns variants and pair templates are intentional template data
    // owned by the export (ADR-0005); the structure-only guarantee covers
    // components.
    structural_strings(&schema["components"], "", &mut strings);
    for text in &strings {
        assert!(
            text.parse::<std::net::IpAddr>().is_err(),
            "address value leaked into schema: {text}"
        );
        assert!(!text.contains("://"), "endpoint value leaked: {text}");
    }
}

#[test]
fn presets_secret_fields_carry_only_placeholders() {
    let schema = config_schema();
    for preset in schema["presets"].as_array().expect("presets") {
        let yaml = preset["yaml"].as_str().expect("yaml");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(yaml).expect("preset yaml must parse");
        fn walk(value: &serde_yaml::Value, out: &mut Vec<(String, String)>) {
            match value {
                serde_yaml::Value::Mapping(map) => {
                    for (key, item) in map {
                        if let (serde_yaml::Value::String(name), serde_yaml::Value::String(text)) =
                            (key, item)
                        {
                            out.push((name.clone(), text.clone()));
                        }
                        walk(item, out);
                    }
                }
                serde_yaml::Value::Sequence(items) => {
                    for item in items {
                        walk(item, out);
                    }
                }
                _ => {}
            }
        }
        let mut pairs = Vec::new();
        walk(&parsed, &mut pairs);
        for (key, value) in pairs {
            if super::config_validation::is_sensitive_key(&key) {
                assert!(
                    value.starts_with("{{") && value.ends_with("}}"),
                    "preset {} carries non-placeholder secret value for {key}",
                    preset["name"]
                );
            }
        }
    }
    // The same rule for server pair templates: private keys stay placeholders.
    for (name, template) in schema["server_pair_templates"]
        .as_object()
        .expect("server pair templates")
    {
        let text = template.as_str().expect("template text");
        assert!(
            text.contains("{{PRIVATE_KEY}}") || !text.contains("private_key"),
            "{name} must not carry private key material"
        );
    }
}

#[tokio::test]
async fn presets_validate_natively_in_every_applicable_mode() {
    let schema = config_schema();
    let presets = schema["presets"].as_array().expect("presets");
    assert!(presets.len() >= 9, "preset catalog too small");
    let credentials = sample_credentials();
    for preset in presets {
        let yaml = preset["yaml"].as_str().expect("yaml");
        let scope = preset["scope"].as_str().expect("scope");
        if scope == "service" {
            let report = validate_config(yaml, ValidationMode::Proxy).await;
            assert!(
                report.valid,
                "service preset {} invalid: {:?}",
                preset["name"],
                report.diagnostics
            );
            continue;
        }
        let profile = substitute_placeholders(yaml, &credentials);
        for mode in [ValidationMode::Proxy, ValidationMode::Vpn] {
            let wrapped = match mode {
                ValidationMode::Proxy => wrap_proxy(&profile),
                ValidationMode::Vpn => wrap_vpn(&profile),
            };
            let report = validate_config(&wrapped, mode).await;
            assert!(
                report.valid,
                "preset {} invalid in {:?}: {:?}\n{}",
                preset["name"],
                mode,
                report.diagnostics,
                wrapped
            );
        }
    }
}

/// Upstream-default coupling guard (design): the Kotlin wrapper writes
/// neither the enabled flags nor mtu, so an upstream default change must fail
/// this build, not the user's connection.
#[test]
fn tun_record_defaults_guard() {
    type HostTunRecord = crate::config::tun::TunRecord<serde_json::Value, serde_json::Value>;
    let record: HostTunRecord = serde_yaml::from_str("device_fd: -1").expect("minimal tun record");
    assert!(record.tcp_enabled, "tcp_enabled must default to true");
    assert!(record.udp_enabled, "udp_enabled must default to true");
    assert!(record.icmp_enabled, "icmp_enabled must default to true");
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    assert_eq!(record.mtu, 1500, "host mtu default changed");
    #[cfg(target_os = "android")]
    assert_eq!(record.mtu, 9000, "Android mtu default changed");

    // The Android branch is cfg'd out on the host test runner, so guard the
    // constant textually: the wrapper relies on the documented 9000 default.
    let source = include_str!("../config/types/tun.rs");
    let android_branch = source
        .split("#[cfg(target_os = \"android\")]")
        .nth(1)
        .expect("android cfg branch in tun.rs");
    assert!(
        android_branch
            .lines()
            .take(2)
            .any(|line| line.trim() == "return 9000;"),
        "Android mtu default is no longer 9000; the wrapper contract changed"
    );
}

#[tokio::test]
async fn dns_group_template_validates_with_sample_profile() {
    let schema = config_schema();
    let variant = schema["dns_variants"]
        .as_array()
        .expect("dns variants")
        .iter()
        .find(|variant| variant["id"] == "via_server_1.1.1.1")
        .expect("default dns variant");
    assert!(variant["via_profile"].as_bool().unwrap_or(false));

    let credentials = sample_credentials();
    let socks_profile = "address: server.example.com:1080\ntransport: tcp\nprotocol:\n  type: socks\n";
    let profile_json: serde_json::Value = serde_yaml::from_str(socks_profile).expect("profile");

    // Fill the template the way the Kotlin assembler does: variant values plus
    // the inline profile as the dns client_chain.
    let mut template = schema["dns_group_template"].clone();
    template["dns_servers"][0]["url"] = variant["upstream"].clone();
    template["dns_servers"][0]["server_name"] = variant["server_name"].clone();
    template["dns_servers"][0]["client_chain"] = profile_json.clone();

    let listener: serde_json::Value =
        serde_yaml::from_str::<Vec<serde_json::Value>>(&wrap_proxy(socks_profile))
            .expect("listener entry")
            .into_iter()
            .next()
            .expect("one listener entry");
    let config = serde_json::json!([listener, template]);
    let yaml = serde_yaml::to_string(&config).expect("dns config yaml");
    let report = validate_config(&yaml, ValidationMode::Proxy).await;
    assert!(
        report.valid,
        "dns group template config invalid: {:?}\n{}",
        report.diagnostics,
        yaml
    );

    // Sanity: the through-profile sample used real credentials without issue.
    let _ = credentials.user_id;
}

/// Task 4.4: the JVM test fixture (`app/src/test/resources/config_schema.json`)
/// must be generated from this export, never hand-transcribed. The non-write
/// mode fails when the committed fixture drifts; `make schema-fixture` reruns
/// this test with SHOES_SCHEMA_FIXTURE=write to regenerate it.
#[test]
fn config_schema_fixture_matches_committed() {
    let mut rendered = serde_json::to_string_pretty(&config_schema()).expect("pretty schema");
    rendered.push('\n');
    let fixture = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../test/resources/config_schema.json");
    if std::env::var("SHOES_SCHEMA_FIXTURE").ok().as_deref() == Some("write") {
        std::fs::write(&fixture, rendered).expect("write JVM fixture");
        eprintln!("fixture regenerated: {}", fixture.display());
        return;
    }
    let committed = std::fs::read_to_string(&fixture)
        .expect("committed JVM fixture (app/src/test/resources/config_schema.json)");
    assert_eq!(
        committed, rendered,
        "JVM fixture is stale: regenerate it with `make schema-fixture`"
    );
}
