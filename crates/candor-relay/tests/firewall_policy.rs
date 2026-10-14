// SPDX-License-Identifier: AGPL-3.0-or-later

const POLICY: &str = include_str!("../policy/core-relay.nft");

#[test]
fn relay_link_is_default_deny_both_directions() {
    assert_eq!(POLICY.matches("policy drop;").count(), 2);
}

#[test]
fn only_relay_uid_can_open_new_intake_connection() {
    assert!(POLICY.contains("meta skuid candor-relay"));
    assert!(POLICY.contains("tcp dport 7443 ct state new accept"));
    assert!(POLICY.contains("ip daddr $intake_relay"));
}

#[test]
fn inbound_chain_has_no_new_connection_accept_rule() {
    let Some(input) = POLICY.split("chain input").nth(1) else {
        assert!(false, "input chain must exist");
        return;
    };
    assert!(!input.contains("ct state new accept"));
    assert!(input.contains("ct state established,related accept"));
}
