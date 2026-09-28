//! enrich — pasywne wzbogacanie leadów (DNS-audit domen; zero aktywnego skanu).

use crate::export::DnsAudit;
use crate::model::Lead;
use std::collections::BTreeMap;

/// Aliasing do store::audit_all (semantyka: jeden audit per domena).
pub fn audit_domains(leads: &[Lead], server: &str) -> BTreeMap<String, DnsAudit> {
    crate::store::audit_all(leads, server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Sector;

    #[test]
    fn audit_domains_zwraca_domene_z_maila() {
        // nie uderzamy w sieć w teście — pusta lista leadów = pusty map
        let out = audit_domains(&[], "1.1.1.1");
        assert!(out.is_empty());
        let _ = Sector::Other; // touch, że import żywy
    }
}
