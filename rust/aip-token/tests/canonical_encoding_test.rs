//! Canonical block encoding and the V4 attenuation walk (draft-prakash-aip-01).
//!
//! Section 3.4.1 fixes the exact Datalog each implementation emits, and
//! Section 4 step V4 requires a structural walk confirming every hop narrows
//! its parent. These tests pin both. The Python implementation has the same
//! set, and `tests/conformance/` checks the two agree on the wire.

use aip_core::crypto::KeyPair;
use aip_token::chained::ChainedToken;
use biscuit_auth::{builder::BlockBuilder, Algorithm, Biscuit, PublicKey};

/// Append a raw block to a serialized token, bypassing this crate entirely.
///
/// This is the adversary's position: they hold a valid token and append
/// whatever Datalog they like. The crate's mint-time checks are not in their
/// path, so only the verifier can catch them.
fn forge(token: &ChainedToken, root_public_key: &[u8; 32], datalog: &str) -> ChainedToken {
    let pubkey = PublicKey::from_bytes(root_public_key, Algorithm::Ed25519).unwrap();
    let biscuit = Biscuit::from_base64(token.to_base64().unwrap(), pubkey).unwrap();
    let block = BlockBuilder::new().code(datalog).unwrap();
    let forged = biscuit.append(block).unwrap();
    ChainedToken::from_base64(&forged.to_base64().unwrap(), root_public_key).unwrap()
}

fn authority(scopes: &[&str], budget: Option<i64>) -> (ChainedToken, KeyPair) {
    let kp = KeyPair::generate();
    let token =
        ChainedToken::create_authority("aip:web:example.com/root", scopes, budget, 3, 3600, &kp)
            .expect("authority creation must succeed");
    (token, kp)
}

// --- Canonical encoding ---------------------------------------------------

#[test]
fn authority_block_emits_tool_check() {
    let (token, _) = authority(&["tool:search", "tool:browse"], Some(500));
    let src = token.block_source(0).unwrap();
    assert!(src.contains(r#"check if tool($t), ["tool:search", "tool:browse"].contains($t)"#));
}

#[test]
fn authority_block_emits_budget_ceiling_fact() {
    let (token, _) = authority(&["tool:search"], Some(500));
    assert!(token.block_source(0).unwrap().contains("budget_ceiling(500)"));
}

#[test]
fn no_block_emits_a_budget_check() {
    let (token, _) = authority(&["tool:search"], Some(500));
    let delegated = token
        .delegate(
            "aip:web:example.com/root",
            "aip:web:example.com/sub",
            &["tool:search"],
            Some(100),
            "test",
        )
        .unwrap();
    for i in 0..delegated.block_count() {
        assert!(!delegated.block_source(i).unwrap().contains("check if budget"));
    }
}

#[test]
fn delegation_block_emits_canonical_facts_and_check() {
    let (token, _) = authority(&["tool:search", "tool:browse"], Some(500));
    let delegated = token
        .delegate(
            "aip:web:example.com/root",
            "aip:web:example.com/sub",
            &["tool:search"],
            Some(100),
            "quarterly report",
        )
        .unwrap();
    let src = delegated.block_source(1).unwrap();
    assert!(src.contains(r#"delegator("aip:web:example.com/root")"#));
    assert!(src.contains(r#"delegate("aip:web:example.com/sub")"#));
    assert!(src.contains(r#"context("quarterly report")"#));
    assert!(src.contains("budget_ceiling(100)"));
    assert!(src.contains(r#"check if tool($t), ["tool:search"].contains($t)"#));
}

// --- Mint-time attenuation ------------------------------------------------

#[test]
fn delegating_a_scope_the_parent_lacks_is_refused() {
    let (token, _) = authority(&["tool:search"], Some(500));
    let result = token.delegate(
        "aip:web:example.com/root",
        "aip:web:example.com/sub",
        &["tool:email"],
        Some(100),
        "test",
    );
    assert!(result.is_err(), "delegating an unheld scope must fail");
}

#[test]
fn raising_the_budget_ceiling_is_refused() {
    let (token, _) = authority(&["tool:search"], Some(100));
    let result = token.delegate(
        "aip:web:example.com/root",
        "aip:web:example.com/sub",
        &["tool:search"],
        Some(500),
        "test",
    );
    assert!(result.is_err(), "raising the ceiling must fail");
}

#[test]
fn empty_context_is_refused() {
    let (token, _) = authority(&["tool:search"], Some(100));
    let result = token.delegate(
        "aip:web:example.com/root",
        "aip:web:example.com/sub",
        &["tool:search"],
        Some(50),
        "",
    );
    assert!(result.is_err(), "empty context must fail");
}

// --- Verifier-side attenuation walk ---------------------------------------

#[test]
fn verifier_rejects_a_chain_whose_scope_widened() {
    let (token, kp) = authority(&["tool:search"], Some(500));
    let forged = forge(
        &token,
        &kp.public_key_bytes(),
            "delegator(\"aip:web:example.com/root\");\n\
             delegate(\"aip:web:example.com/sub\");\n\
             context(\"forged\");\n\
             check if tool($t), [\"tool:search\", \"tool:email\"].contains($t);\n",
    );
    let result = forged.authorize("tool:search", &kp.public_key_bytes());
    assert!(result.is_err(), "a widened chain must not authorize");
}

#[test]
fn verifier_rejects_a_chain_whose_budget_ceiling_widened() {
    let (token, kp) = authority(&["tool:search"], Some(100));
    let forged = forge(
        &token,
        &kp.public_key_bytes(),
            "delegator(\"aip:web:example.com/root\");\n\
             delegate(\"aip:web:example.com/sub\");\n\
             context(\"forged\");\n\
             budget_ceiling(500);\n\
             check if tool($t), [\"tool:search\"].contains($t);\n",
    );
    let result = forged.authorize("tool:search", &kp.public_key_bytes());
    assert!(result.is_err(), "a raised ceiling must not authorize");
}

#[test]
fn verifier_rejects_a_delegation_block_without_context() {
    let (token, kp) = authority(&["tool:search"], Some(100));
    let forged = forge(
        &token,
        &kp.public_key_bytes(),
            "delegator(\"aip:web:example.com/root\");\n\
             delegate(\"aip:web:example.com/sub\");\n\
             check if tool($t), [\"tool:search\"].contains($t);\n",
    );
    let result = forged.authorize("tool:search", &kp.public_key_bytes());
    assert!(result.is_err(), "a delegation without context must not authorize");
}

// --- Wildcard scopes ------------------------------------------------------

#[test]
fn wildcard_authority_authorizes_a_specific_tool() {
    let (token, kp) = authority(&["tool:*"], Some(500));
    token
        .authorize("tool:search", &kp.public_key_bytes())
        .expect("tool:* must authorize tool:search");
}

#[test]
fn wildcard_authority_refuses_a_tool_outside_the_prefix() {
    let (token, kp) = authority(&["tool:*"], Some(500));
    assert!(token.authorize("admin:delete", &kp.public_key_bytes()).is_err());
}

#[test]
fn wildcard_narrows_to_specific_across_hops() {
    let (token, kp) = authority(&["tool:*"], Some(500));
    let delegated = token
        .delegate(
            "aip:web:example.com/root",
            "aip:web:example.com/sub",
            &["tool:search"],
            Some(100),
            "narrow the wildcard",
        )
        .unwrap();
    delegated
        .authorize("tool:search", &kp.public_key_bytes())
        .expect("narrowed scope must still authorize");
    assert!(delegated.authorize("tool:browse", &kp.public_key_bytes()).is_err());
}

#[test]
fn specific_parent_cannot_widen_to_a_wildcard_child() {
    let (token, _) = authority(&["tool:search"], Some(500));
    let result = token.delegate(
        "aip:web:example.com/root",
        "aip:web:example.com/sub",
        &["tool:*"],
        Some(100),
        "attempted widening",
    );
    assert!(result.is_err(), "a specific parent must not widen to a wildcard");
}

#[test]
fn mixed_exact_and_wildcard_scopes_both_authorize() {
    let (token, kp) = authority(&["report:daily", "tool:*"], Some(500));
    token.authorize("report:daily", &kp.public_key_bytes()).unwrap();
    token.authorize("tool:search", &kp.public_key_bytes()).unwrap();
    assert!(token.authorize("report:weekly", &kp.public_key_bytes()).is_err());
}
