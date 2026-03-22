use aip_core::crypto::KeyPair;
use aip_core::document::IdentityDocument;
use chrono::Utc;
use serde_json::{json, Value};

/// Helper: build a valid, signed identity document JSON string.
fn create_signed_document(kp: &KeyPair) -> String {
    let multibase = kp.public_key_multibase();
    let id = format!("aip:key:ed25519:{multibase}");

    // Build document JSON without document_signature
    let mut doc = json!({
        "aip": "1.0",
        "id": id,
        "public_keys": [
            {
                "id": format!("{id}#key-1"),
                "type": "Ed25519",
                "public_key_multibase": multibase,
            }
        ],
        "name": "Test Agent"
    });

    // Compute canonical JSON (sorted keys, no whitespace, no null values)
    let canonical = canonical_json_from_value(&doc);

    // Sign canonical JSON
    let sig_bytes = kp.sign(canonical.as_bytes());
    let sig_hex = hex::encode(&sig_bytes);

    // Add document_signature to the document
    doc.as_object_mut()
        .unwrap()
        .insert("document_signature".to_string(), Value::String(sig_hex));

    serde_json::to_string(&doc).unwrap()
}

/// Produce canonical JSON from a serde_json::Value: sorted keys, no whitespace, no null values.
fn canonical_json_from_value(val: &Value) -> String {
    let cleaned = strip_nulls(val);
    serde_json::to_string(&cleaned).unwrap()
}

/// Recursively remove keys with null values from a JSON Value.
fn strip_nulls(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                if !v.is_null() {
                    new_map.insert(k.clone(), strip_nulls(v));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_nulls).collect()),
        other => other.clone(),
    }
}

#[test]
fn test_parse_valid_document() {
    let kp = KeyPair::generate();
    let doc_json = create_signed_document(&kp);

    let doc = IdentityDocument::from_json(&doc_json).expect("should parse valid document");
    assert_eq!(doc.aip, "1.0");
    assert!(doc.id.starts_with("aip:key:ed25519:"));
    assert_eq!(doc.public_keys.len(), 1);
    assert_eq!(doc.public_keys[0].key_type, "Ed25519");
    assert_eq!(doc.name, Some("Test Agent".to_string()));
    assert!(!doc.document_signature.is_empty());
}

#[test]
fn test_verify_signature() {
    let kp = KeyPair::generate();
    let doc_json = create_signed_document(&kp);

    let doc = IdentityDocument::from_json(&doc_json).expect("should parse");
    doc.verify_signature().expect("signature should be valid");
}

#[test]
fn test_reject_tampered_signature() {
    let kp = KeyPair::generate();
    let doc_json = create_signed_document(&kp);

    // Parse to Value, tamper with the name, re-serialize
    let mut val: Value = serde_json::from_str(&doc_json).unwrap();
    val.as_object_mut()
        .unwrap()
        .insert("name".to_string(), Value::String("Tampered Agent".to_string()));
    let tampered_json = serde_json::to_string(&val).unwrap();

    let doc = IdentityDocument::from_json(&tampered_json).expect("should parse");
    let result = doc.verify_signature();
    assert!(result.is_err(), "verification must fail for tampered document");
}

#[test]
fn test_reject_expired_document() {
    let kp = KeyPair::generate();
    let multibase = kp.public_key_multibase();
    let id = format!("aip:key:ed25519:{multibase}");

    // Build document with an already-expired date
    let mut doc = json!({
        "aip": "1.0",
        "id": id,
        "public_keys": [
            {
                "id": format!("{id}#key-1"),
                "type": "Ed25519",
                "public_key_multibase": multibase,
            }
        ],
        "expires": "2020-01-01T00:00:00Z"
    });

    let canonical = canonical_json_from_value(&doc);
    let sig_bytes = kp.sign(canonical.as_bytes());
    let sig_hex = hex::encode(&sig_bytes);
    doc.as_object_mut()
        .unwrap()
        .insert("document_signature".to_string(), Value::String(sig_hex));

    let doc_json = serde_json::to_string(&doc).unwrap();
    let parsed = IdentityDocument::from_json(&doc_json).expect("should parse");

    assert!(parsed.is_expired(Utc::now()), "document with past expires date should be expired");
}

#[test]
fn test_find_valid_key() {
    let kp = KeyPair::generate();
    let multibase = kp.public_key_multibase();
    let id = format!("aip:key:ed25519:{multibase}");

    let mut doc = json!({
        "aip": "1.0",
        "id": id,
        "public_keys": [
            {
                "id": format!("{id}#key-1"),
                "type": "Ed25519",
                "public_key_multibase": multibase,
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z"
            }
        ]
    });

    let canonical = canonical_json_from_value(&doc);
    let sig_bytes = kp.sign(canonical.as_bytes());
    let sig_hex = hex::encode(&sig_bytes);
    doc.as_object_mut()
        .unwrap()
        .insert("document_signature".to_string(), Value::String(sig_hex));

    let doc_json = serde_json::to_string(&doc).unwrap();
    let parsed = IdentityDocument::from_json(&doc_json).expect("should parse");

    // Date inside validity range
    let inside = chrono::DateTime::parse_from_rfc3339("2026-06-15T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        parsed.find_valid_key(inside).is_some(),
        "should find key for date inside validity range"
    );

    // Date outside validity range (after valid_until)
    let outside = chrono::DateTime::parse_from_rfc3339("2028-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        parsed.find_valid_key(outside).is_none(),
        "should not find key for date outside validity range"
    );
}

#[test]
fn test_reject_unsupported_version() {
    let kp = KeyPair::generate();
    let multibase = kp.public_key_multibase();
    let id = format!("aip:key:ed25519:{multibase}");

    let mut doc = json!({
        "aip": "2.0",
        "id": id,
        "public_keys": [
            {
                "id": format!("{id}#key-1"),
                "type": "Ed25519",
                "public_key_multibase": multibase,
            }
        ]
    });

    let canonical = canonical_json_from_value(&doc);
    let sig_bytes = kp.sign(canonical.as_bytes());
    let sig_hex = hex::encode(&sig_bytes);
    doc.as_object_mut()
        .unwrap()
        .insert("document_signature".to_string(), Value::String(sig_hex));

    let doc_json = serde_json::to_string(&doc).unwrap();
    let parsed = IdentityDocument::from_json(&doc_json).expect("should parse");

    let result = parsed.check_version();
    assert!(result.is_err(), "version 2.0 should be rejected");
}

#[test]
fn test_ignore_unknown_fields() {
    let kp = KeyPair::generate();
    let multibase = kp.public_key_multibase();
    let id = format!("aip:key:ed25519:{multibase}");

    // Build document with extra unknown fields
    let mut doc = json!({
        "aip": "1.0",
        "id": id,
        "public_keys": [
            {
                "id": format!("{id}#key-1"),
                "type": "Ed25519",
                "public_key_multibase": multibase,
            }
        ],
        "future_field": "some value",
        "another_unknown": 42
    });

    let canonical = canonical_json_from_value(&doc);
    let sig_bytes = kp.sign(canonical.as_bytes());
    let sig_hex = hex::encode(&sig_bytes);
    doc.as_object_mut()
        .unwrap()
        .insert("document_signature".to_string(), Value::String(sig_hex));

    let doc_json = serde_json::to_string(&doc).unwrap();

    // Parsing should succeed even with unknown fields (forward compatibility)
    let parsed = IdentityDocument::from_json(&doc_json);
    assert!(parsed.is_ok(), "parsing should succeed with unknown fields for forward compatibility");
}
