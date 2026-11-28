//! Versioned configuration schema export assembled from the committed
//! snapshot artifact (see `tooling/shoes/dump_config_schema.py` and ADR-0004).

use serde_json::{Map, Value};

const SNAPSHOT: &str = include_str!("config_schema.json");

/// Assemble the versioned schema document from the snapshot artifact.
pub fn config_schema() -> Value {
    let mut root = Map::new();
    root.insert("schema_version".into(), Value::from(1));
    let mut components: Value =
        serde_json::from_str(SNAPSHOT).expect("committed schema artifact must parse");
    mark_secrets(&mut components);
    root.insert("components".into(), components);
    root.insert("profile_skeleton".into(), profile_skeleton());
    root.insert("dns_variants".into(), dns_variants());
    root.insert("dns_group_template".into(), dns_group_template());
    root.insert("presets".into(), presets());
    root.insert(
        "credential_kinds".into(),
        serde_json::json!(["reality_keypair", "vless_user_id", "shadowsocks_2022_password", "vless_encryption"]),
    );
    root.insert("server_pair_templates".into(), server_pair_templates());
    Value::Object(root)
}

/// KCP documentation-recommended initial values shared by the skeleton field
/// and the KCP presets (see `examples/kcp.yaml`).
fn kcp_defaults() -> Value {
    serde_json::json!({
        "mode": "file_transfer",
        "send_window": 256,
        "recv_window": 256,
        "mtu": 1400,
        "max_sessions": 128
    })
}

/// Simple-form field list (ADR-0005): one connection profile, mode-agnostic —
/// the operating mode lives in main settings and only affects the wrapping
/// assembled at service start. `component` references a snapshot component;
/// `visible_when` is a declarative sibling condition; `defaults` are the
/// documentation-recommended initial values.
fn profile_skeleton() -> Value {
    serde_json::json!({
        "fields": [
            { "key": "address", "kind": "text", "required": true },
            { "key": "protocol", "component": "client_protocols" },
            { "key": "transport", "enum": ["tcp", "quic", "kcp"], "default": "tcp" },
            {
                "key": "kcp_settings",
                "component": "kcp_settings",
                "visible_when": { "sibling": "transport", "equals": "kcp" },
                "defaults": kcp_defaults(),
            },
            {
                "key": "dns",
                "enum": dns_variant_ids(),
                "default": "via_server_1.1.1.1",
                // editor_only: выбор уровня формы; потребляется ассемблером,
                // в client_chain профиля не попадает
                "editor_only": true,
            },
            {
                "key": "dns_custom_url",
                "kind": "text",
                "visible_when": { "sibling": "dns", "equals": "custom" },
                "editor_only": true,
            },
        ]
    })
}

/// The single DNS choice of the simple form (design: DNS as one choice).
/// `via_profile` variants route the upstream through the profile's
/// client_chain using `dns_group_template`; `custom` carries a user URL.
fn dns_variants() -> Value {
    serde_json::json!([
        {
            "id": "via_server_1.1.1.1",
            "title": "Через сервер (DoT 1.1.1.1)",
            "upstream": "tls://1.1.1.1",
            "server_name": "cloudflare-dns.com",
            "via_profile": true
        },
        {
            "id": "via_server_8.8.8.8",
            "title": "Через сервер (DoT 8.8.8.8)",
            "upstream": "tls://8.8.8.8",
            "server_name": "dns.google",
            "via_profile": true
        },
        { "id": "system", "title": "Системный DNS" },
        { "id": "custom", "title": "Свой DNS (URL)", "custom": true }
    ])
}

fn dns_variant_ids() -> Value {
    dns_variants()
        .as_array()
        .expect("dns variants are an array")
        .iter()
        .map(|variant| variant["id"].clone())
        .collect::<Vec<_>>()
        .into()
}

/// DNS-group template for "via server" variants (shape from
/// `examples/dns_tuning.yaml`): the upstream is an IP-based DoT resolver
/// routed through the profile. `{{UPSTREAM}}`/`{{SERVER_NAME}}` come from the
/// chosen dns variant; `{{PROFILE_CHAIN}}` is replaced by the profile's
/// inline client_chain (or a client_group reference wrapping it).
fn dns_group_template() -> Value {
    serde_json::json!({
        "dns_group": "via-profile",
        "dns_servers": [
            {
                "url": "{{UPSTREAM}}",
                "server_name": "{{SERVER_NAME}}",
                "client_chain": "{{PROFILE_CHAIN}}"
            }
        ]
    })
}

/// Documentation-sourced preset catalog (ADR-0005). Profile presets carry a
/// client_chain-shaped fragment the assembler wraps per mode; service presets
/// (`scope: "service"` + `modes: ["proxy"]`) are complete local listeners.
/// Secret fields carry only `{{TOKEN}}` placeholders filled by
/// `generate_credentials` — no real key material lives here, asserted by tests.
fn presets() -> Value {
    let kcp_settings = concat!(
        "kcp_settings:\n",
        "  mode: file_transfer\n",
        "  send_window: 256\n",
        "  recv_window: 256\n",
        "  mtu: 1400\n",
        "  max_sessions: 128\n",
    );
    // Profile preset: mode-agnostic client_chain fragment wrapped per mode.
    // `title_key` is the stable localization key resolved by Kotlin strings;
    // `title` stays for backward compatibility (pre-title_key consumers).
    let profile = |name: &str,
                       title: &str,
                       description: &str,
                       address: &str,
                       body: &str,
                       extra: &[(&str, Value)]| {
        let mut preset = Map::new();
        preset.insert("name".into(), name.into());
        preset.insert(
            "title_key".into(),
            format!("preset_{name}").into(),
        );
        preset.insert("title".into(), title.into());
        preset.insert("description".into(), description.into());
        preset.insert("scope".into(), "profile".into());
        preset.insert("modes".into(), serde_json::json!(["proxy", "vpn"]));
        preset.insert("yaml".into(), format!("address: {address}\n{body}").into());
        for (key, value) in extra {
            preset.insert((*key).into(), value.clone());
        }
        preset.into()
    };
    let mut catalog: Vec<Value> = vec![
        profile(
            "vless_reality",
            "VLESS + Reality",
            "Reality-обёртка поверх VLESS: устойчивость к активному зондированию",
            "server.example.com:443",
            concat!(
                "transport: tcp\n",
                "protocol:\n",
                "  type: reality\n",
                "  public_key: \"{{PUBLIC_KEY}}\"\n",
                "  short_id: \"{{SHORT_ID}}\"\n",
                "  sni_hostname: www.cloudflare.com\n",
                "  protocol:\n",
                "    type: vless\n",
                "    user_id: \"{{USER_ID}}\"\n",
            ),
            &[
                ("default", Value::Bool(true)),
                ("hints", serde_json::json!(["preset_hint_no_browser_fingerprint"])),
                ("placeholders", serde_json::json!(["PUBLIC_KEY", "USER_ID", "SHORT_ID"])),
            ],
        ),
        profile(
            "trojan_tls",
            "Trojan + TLS",
            "Trojan внутри TLS: парольная аутентификация без заметных признаков",
            "server.example.com:443",
            concat!(
                "transport: tcp\n",
                "protocol:\n",
                "  type: tls\n",
                "  sni_hostname: server.example.com\n",
                "  protocol:\n",
                "    type: trojan\n",
                "    password: \"{{PASSWORD}}\"\n",
            ),
            &[("placeholders", serde_json::json!(["PASSWORD"]))],
        ),
        profile(
            "vmess_wss",
            "VMess + WS + TLS",
            "VMess внутри WebSocket внутри TLS (форма examples/socks_through_wss_vmess.yaml)",
            "server.example.com:443",
            concat!(
                "transport: tcp\n",
                "protocol:\n",
                "  type: tls\n",
                "  sni_hostname: server.example.com\n",
                "  protocol:\n",
                "    type: ws\n",
                "    matching_path: /ws\n",
                "    protocol:\n",
                "      type: vmess\n",
                "      cipher: aes-128-gcm\n",
                "      user_id: \"{{USER_ID}}\"\n",
            ),
            &[("placeholders", serde_json::json!(["USER_ID"]))],
        ),
        profile(
            "shadowsocks",
            "Shadowsocks",
            "Классический Shadowsocks (aes-128-gcm)",
            "server.example.com:8388",
            concat!(
                "transport: tcp\n",
                "protocol:\n",
                "  type: shadowsocks\n",
                "  cipher: aes-128-gcm\n",
                "  password: \"{{PASSWORD}}\"\n",
            ),
            &[("placeholders", serde_json::json!(["PASSWORD"]))],
        ),
        profile(
            "socks",
            "SOCKS5",
            "Проксирование через удалённый SOCKS5-сервер",
            "server.example.com:1080",
            concat!("transport: tcp\n", "protocol:\n  type: socks\n"),
            &[],
        ),
        profile(
            "anytls_kcp",
            "AnyTLS + KCP (экспериментально)",
            "AnyTLS поверх KCP-транспорта; транспорт помечен как экспериментальный",
            "server.example.com:443",
            concat!(
                "transport: kcp\n",
                "{kcp_settings}",
                "protocol:\n",
                "  type: anytls\n",
                "  password: \"{{PASSWORD}}\"\n",
            )
            .replace("{kcp_settings}", kcp_settings)
            .as_str(),
            &[
                ("stability", Value::String("experimental".into())),
                ("placeholders", serde_json::json!(["PASSWORD"])),
            ],
        ),
        profile(
            "socks_kcp",
            "SOCKS5 + KCP (экспериментально)",
            "Удалённый SOCKS5-сервер через KCP-транспорт (форма examples/kcp.yaml)",
            "server.example.com:19090",
            concat!(
                "transport: kcp\n",
                "{kcp_settings}",
                "protocol:\n",
                "  type: socks\n",
            )
            .replace("{kcp_settings}", kcp_settings)
            .as_str(),
            &[("stability", Value::String("experimental".into()))],
        ),
    ];
    // Service presets are complete proxy-mode listener entries.
    let service = |name: &str, title: &str, description: &str, yaml: &str| {
        let mut preset = Map::new();
        preset.insert("name".into(), name.into());
        preset.insert(
            "title_key".into(),
            format!("preset_{name}").into(),
        );
        preset.insert("title".into(), title.into());
        preset.insert("description".into(), description.into());
        preset.insert("scope".into(), "service".into());
        preset.insert("modes".into(), serde_json::json!(["proxy"]));
        preset.insert("yaml".into(), yaml.into());
        preset.into()
    };
    catalog.push(service(
        "local_socks",
        "Локальный SOCKS",
        "SOCKS5-слушатель на 127.0.0.1:1080 без внешнего сервера",
        "- address: \"127.0.0.1:1080\"\n  protocol:\n    type: socks\n",
    ));
    catalog.push(service(
        "local_mixed",
        "Локальный Mixed (без аутентификации)",
        "HTTP+SOCKS5 автоопределение на 127.0.0.1:7890; без пароля",
        "- address: \"127.0.0.1:7890\"\n  protocol:\n    type: mixed\n",
    ));
    Value::Array(catalog)
}

/// Server-side counterparts for presets that need paired key material
/// (ADR-0005). Placeholders: `{{PORT}}`, `{{PRIVATE_KEY}}` (server only),
/// `{{USER_ID}}`, `{{PASSWORD}}`, `{{SHORT_ID}}`. Validated by substituting
/// generated credentials in Rust tests.
fn server_pair_templates() -> Value {
    let vless_reality = concat!(
        "# Paired server for the vless_reality preset (examples/reality_basic.yaml).\n",
        "- address: \"0.0.0.0:{{PORT}}\"\n",
        "  protocol:\n",
        "    type: tls\n",
        "    reality_targets:\n",
        "      www.cloudflare.com:\n",
        "        private_key: \"{{PRIVATE_KEY}}\"\n",
        "        short_ids: [\"{{SHORT_ID}}\", \"\"]\n",
        "        dest: www.cloudflare.com:443\n",
        "        protocol:\n",
        "          type: vless\n",
        "          user_id: \"{{USER_ID}}\"\n",
        "          udp_enabled: true\n",
    );
    let anytls_kcp = concat!(
        "# Paired server for the anytls_kcp preset (examples/kcp.yaml + anytls.yaml).\n",
        "- address: \"0.0.0.0:{{PORT}}\"\n",
        "  transport: kcp\n",
        "  kcp_settings:\n",
        "    mode: file_transfer\n",
        "    send_window: 256\n",
        "    recv_window: 256\n",
        "    mtu: 1400\n",
        "    max_sessions: 128\n",
        "  protocol:\n",
        "    type: anytls\n",
        "    users:\n",
        "      - name: user1\n",
        "        password: \"{{PASSWORD}}\"\n",
    );
    serde_json::json!({
        "vless_reality": vless_reality,
        "anytls_kcp": anytls_kcp,
    })
}

fn walk(value: &mut Value, key_hint: Option<&str>, marked: &mut Option<&mut Vec<String>>) {
    match value {
        Value::Object(map) => {
            if let Some(name) = key_hint {
                if super::config_validation::is_sensitive_key(name) {
                    map.insert("shoes_secret".into(), Value::Bool(true));
                    if let Some(marked) = marked.as_deref_mut() {
                        marked.push(name.to_string());
                    }
                }
            }
            for (key, item) in map.iter_mut() {
                walk(item, Some(key), marked);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                walk(item, key_hint, marked);
            }
        }
        _ => {}
    }
}

fn mark_secrets(components: &mut Value) {
    let mut marked = Vec::new();
    let mut slot: Option<&mut Vec<String>> = Some(&mut marked);
    walk(components, None, &mut slot);
}

/// Test helper: names of keys that received the secret designation.
pub(crate) fn secret_marked_keys(schema: &Value) -> Vec<String> {
    fn collect(value: &Value, key_hint: Option<&str>, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(name) = key_hint {
                    if map.get("shoes_secret") == Some(&Value::Bool(true)) {
                        out.push(name.to_string());
                    }
                }
                for (key, item) in map {
                    collect(item, Some(key), out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect(item, key_hint, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    collect(schema, None, &mut out);
    out.sort();
    out.dedup();
    out
}
