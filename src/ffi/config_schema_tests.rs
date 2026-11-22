use super::config_schema::config_schema;
use serde_json::Value;

const PASSWORD_SENTINEL: &str = "SUPER_SECRET_DEFAULT";

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
fn skeleton_fields_carry_enum_constraints() {
    let schema = config_schema();
    let transport = schema["components"]["transport"]
        .as_array()
        .or_else(|| schema["components"]["transport"]["enum"].as_array())
        .expect("transport enum");
    let values: Vec<&str> = transport
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert!(values.contains(&"tcp"), "{values:?}");
    assert!(values.contains(&"kcp"), "{values:?}");

    let kcp = schema["components"]["kcp_settings"].to_string();
    assert!(kcp.contains("\"mode\""), "kcp mode field missing");
    assert!(
        kcp.contains("file_transfer") || kcp.contains("fast"),
        "kcp mode enum values missing"
    );
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
    structural_strings(&schema, "", &mut strings);
    for text in &strings {
        assert!(
            text.parse::<std::net::IpAddr>().is_err(),
            "address value leaked into schema: {text}"
        );
        assert!(!text.contains("://"), "endpoint value leaked: {text}");
    }
}
