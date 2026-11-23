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
    root.insert("mode_skeletons".into(), mode_skeletons());
    root.insert("presets".into(), presets());
    Value::Object(root)
}

/// Per-mode editing skeletons (ADR-0005): declarative field lists the Kotlin
/// renderer consumes as data. `component` references a snapshot component;
/// `visible_when` is a declarative sibling condition; `defaults` are the
/// documentation-recommended initial values.
fn mode_skeletons() -> Value {
    let kcp_field = |prefix: &str| {
        serde_json::json!({
            "key": format!("{prefix}kcp_settings"),
            "component": "kcp_settings",
            "visible_when": { "sibling": "transport", "equals": "kcp" },
            "defaults": {
                "mode": "file_transfer",
                "send_window": 256,
                "recv_window": 256,
                "mtu": 1400,
                "max_sessions": 128
            },
        })
    };
    serde_json::json!({
        "proxy": {
            "fields": [
                { "key": "address", "kind": "text", "required": true },
                { "key": "protocol", "component": "server_protocols" },
                { "key": "transport", "enum": ["tcp", "quic", "kcp"], "default": "tcp" },
                kcp_field(""),
            ]
        },
        "vpn": {
            "fields": [
                { "key": "device_fd", "kind": "integer", "required": true, "default": -1 },
                { "key": "mtu", "kind": "integer", "default": 9000 },
                { "key": "rules.0.masks", "kind": "text", "default": "0.0.0.0/0" },
                { "key": "rules.0.action", "enum": ["allow"], "default": "allow" },
                { "key": "rules.0.client_chain.address", "kind": "text", "required": true },
                { "key": "rules.0.client_chain.protocol", "component": "client_protocols" },
                { "key": "rules.0.client_chain.transport", "enum": ["tcp", "quic", "kcp"], "default": "kcp" },
                kcp_field("rules.0.client_chain."),
            ]
        }
    })
}

/// Documentation-sourced preset catalog (ADR-0005). Templates are trimmed
/// copies of upstream `examples/` files; the Kotlin side renders them as
/// data and contains no preset content. No secret-marked keys allowed —
/// asserted by tests.
fn presets() -> Value {
    const QUICKSTART: &str = "- address: \"127.0.0.1:1080\"\n  protocol:\n    type: socks\n";
    const KCP_CHAIN: &str = concat!(
        "        transport: kcp\n",
        "        kcp_settings:\n",
        "          mode: file_transfer\n",
        "          send_window: 256\n",
        "          recv_window: 256\n",
        "          mtu: 1400\n",
        "          max_sessions: 128\n",
        "        protocol:\n          type: socks\n",
    );
    let kcp_proxy = format!(
        concat!(
            "- address: \"127.0.0.1:1080\"\n",
            "  protocol:\n    type: socks\n",
            "  rules:\n",
            "    - masks: \"0.0.0.0/0\"\n",
            "      action: allow\n",
            "      client_chain:\n",
            "        address: \"server.example.com:19090\"\n{}"
        ),
        KCP_CHAIN
    );
    let kcp_vpn = format!(
        concat!(
            "- device_fd: -1\n",
            "  mtu: 9000\n",
            "  tcp_enabled: true\n",
            "  udp_enabled: true\n",
            "  rules:\n",
            "    - masks: \"0.0.0.0/0\"\n",
            "      action: allow\n",
            "      client_chain:\n",
            "        address: \"server.example.com:19090\"\n{}"
        ),
        KCP_CHAIN
    );
    let mixed = "- address: \"127.0.0.1:7890\"\n  protocol:\n    type: mixed\n";
    serde_json::json!([
        {
            "name": "quickstart_socks",
            "title": "Локальный SOCKS",
            "description": "SOCKS5-слушатель на 127.0.0.1:1080 без внешнего сервера",
            "mode": "proxy",
            "yaml": QUICKSTART,
        },
        {
            "name": "kcp_proxy_client",
            "title": "Через сервер (KCP), режим Proxy",
            "description": "Локальный SOCKS + правило на удалённый сервер через KCP",
            "mode": "proxy",
            "yaml": kcp_proxy,
        },
        {
            "name": "kcp_vpn_client",
            "title": "Через сервер (KCP), режим VPN",
            "description": "TUN-режим: весь трафик через удалённый сервер по KCP",
            "mode": "vpn",
            "yaml": kcp_vpn,
        },
        {
            "name": "mixed_no_auth",
            "title": "Локальный Mixed",
            "description": "HTTP+SOCKS5 автоопределение на 127.0.0.1:7890",
            "mode": "proxy",
            "yaml": mixed,
        },
    ])
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
