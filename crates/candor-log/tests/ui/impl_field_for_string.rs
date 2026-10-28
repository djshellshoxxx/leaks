// SPDX-License-Identifier: AGPL-3.0-or-later
// AuditField is sealed: downstream crates cannot make arbitrary types loggable.
use candor_log::AuditField;
use candor_log::cbor::Value;

struct ClientAddr(String);

impl AuditField for ClientAddr {
    fn to_value(&self) -> Value {
        Value::Text(self.0.clone())
    }
}

fn main() {}
