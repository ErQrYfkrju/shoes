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
    Value::Object(root)
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
