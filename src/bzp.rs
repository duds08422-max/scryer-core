//! bzp — ingest ogłoszeń przetargowych (BZP) i scoring dopasowania do Talusa.
//!
//! Filozofia "own your stack": rdzeń deterministyczny (parsowanie + scoring
//! na zamrożonych fixtures), fetch opcjonalny. Kupujący już mają budżet —
//! to jest kanał sprzedaży z najwyższą konwersją.
//!
//! Format wejścia: JSON array lub {"items":[...]} z tolerowanymi kluczami
//! (title/tytul, org/organizator, url, published, deadline, cpv, city).
//! Scoring: dopasowanie słów kluczowych przedmiotu do portfela Talus
//! (SIEM/SOC/monitoring zdarzeń/eBPF/EDR/detekcja incydentów) + waga sektora.

use serde::{Deserialize, Serialize};

/// Jedno ogłoszenie przetargowe po normalizacji.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Tender {
    #[serde(default, alias = "tytul", alias = "nazwa")]
    pub title: String,
    #[serde(default, alias = "organizator", alias = "zamawiajacy")]
    pub org: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub published: String,
    #[serde(alias = "termin", default)]
    pub deadline: String,
    /// Kod CPV (wspólny słownik zamówień UE) — 72xxxxx usługi IT.
    #[serde(default)]
    pub cpv: String,
    #[serde(default, alias = "miejscowosc")]
    pub city: String,
}

/// Wczytanie wsadu: array albo {"items":[...]}.
pub fn load(raw: &str) -> Result<Vec<Tender>, serde_json::Error> {
    #[derive(Deserialize)]
    struct Wrap {
        #[serde(default = "Vec::new", alias = "ogloszenia")]
        items: Vec<Tender>,
    }
    if let Ok(v) = serde_json::from_str::<Vec<Tender>>(raw) {
        return Ok(v);
    }
    serde_json::from_str::<Wrap>(raw).map(|w| w.items)
}

/// Wynik dopasowania ogłoszenia do oferty Talus.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub score: u32,
    pub reasons: Vec<String>,
}

/// Słowa kluczowe przedmiotu zamówienia → punkty. Audit-ready: każdy punkt ma powód.
const SIGNALS: &[(&str, u32, &str)] = &[
    ("siem", 8, "SIEM w przedmiocie"),
    ("soc", 8, "SOC w przedmiocie"),
    ("monitoring zdarzen", 8, "monitoring zdarzeń bezpieczeństwa"),
    ("monitoring bezpieczen", 8, "monitoring bezpieczeństwa"),
    ("zarzadzanie incident", 8, "zarządzanie incydentami"),
    ("detekcja incydent", 8, "detekcja incydentów"),
    ("edr", 6, "EDR w przedmiocie"),
    ("xdr", 6, "XDR w przedmiocie"),
    ("ids", 5, "IDS/IPS"),
    ("ips", 4, "IPS"),
    ("logi", 3, "logi/zbieranie logów"),
    (" zbieranie log", 3, "zbieranie logów"),
    ("analyz", 3, "analiza zdarzeń"),
    (
        "ibpl",
        4,
        "IBPL/ustawa o krajowym systemie cyberbezpieczeństwa",
    ),
    ("ksc", 4, "KSC w przedmiocie"),
    ("nis2", 4, "NIS2"),
    ("hsm", 2, "HSM (otoczenie bezpieczeństwa)"),
    ("soc ", 8, "SOC"),
];

/// Sektory podwyższone (KSC kluczowe) — w nazwie organizatora.
const SECTORS: &[(&str, u32, &str)] = &[
    ("szpital", 3, "sektor zdrowie"),
    ("medyczn", 3, "sektor zdrowie"),
    ("zdrowotn", 3, "sektor zdrowie"),
    ("opieki zdrowotnej", 3, "sektor zdrowie"),
    ("wodociag", 3, "wod-kan"),
    ("zwik", 3, "wod-kan"),
    ("mpwik", 3, "wod-kan"),
    ("energety", 3, "energetyka"),
    ("dystrybucj", 2, "dystrybucja energii"),
    ("elektrociep", 2, "ciepłownictwo"),
    ("gaz", 2, "gazownictwo"),
    ("kolej", 2, "transport kolejowy"),
    ("lotnisko", 2, "transport lotniczy"),
    ("urzad", 1, "administracja"),
    ("miast", 1, "samorząd"),
    ("gmin", 1, "samorząd"),
    ("bank", 2, "finanse"),
];

/// Kod CPV 72 = usługi IT/software → bonus.
fn cpv_bonus(cpv: &str) -> Option<(u32, String)> {
    let c: String = cpv
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .take(2)
        .collect();
    match c.as_str() {
        "72" => Some((4, "CPV 72xxx: usługi IT".into())),
        "64" => Some((2, "CPV 64xxx: usługi telekomunikacyjne".into())),
        _ => None,
    }
}

/// Scoring jednego ogłoszenia: 0..=~30. Progi: >=15 hot, >=8 warm.
pub fn score(t: &Tender) -> Match {
    let mut s = 0u32;
    let mut reasons = Vec::new();
    let hay = format!(
        "{} {} {}",
        t.title,
        t.title.to_lowercase(),
        t.org.to_lowercase()
    )
    .to_lowercase();

    for (kw, pts, why) in SIGNALS {
        if hay.contains(kw) {
            s += pts;
            reasons.push((*why).to_string());
        }
    }
    for (kw, pts, why) in SECTORS {
        let org_low = t.org.to_lowercase();
        if org_low.contains(kw) {
            s += *pts;
            reasons.push((*why).to_string());
        }
    }
    if let Some((pts, why)) = cpv_bonus(&t.cpv) {
        s += pts;
        reasons.push(why);
    }
    Match { score: s, reasons }
}

/// Ranga kampanijna: HOT (odpowiedź priorytetowa), WARM, COLD (ignoruj).
pub fn tier(m: &Match) -> &'static str {
    match m.score {
        15..=u32::MAX => "HOT",
        8..=14 => "WARM",
        _ => "COLD",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_toleruje_array_i_items() {
        let a = load(r#"[{"title":"Dostawa SIEM","org":"ZWiK X"}]"#).unwrap();
        assert_eq!(a.len(), 1);
        let b = load(r#"{"items":[{"tytul":"Dostawa SIEM","organizator":"ZWiK X"}]}"#).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].title, b[0].title);
    }

    #[test]
    fn siem_dla_wodkanu_jest_hot() {
        let t = Tender {
            title: "Zakup i wdrozenie systemu SIEM z obsluga monitoringu zdarzen bezpieczenstwa"
                .into(),
            org: "Miejskie Przedsiebiorstwo Wodociagow i Kanalizacji".into(),
            url: "https://bip.example/1".into(),
            published: "2026-09-29".into(),
            deadline: "2026-10-20".into(),
            cpv: "72260000-6".into(),
            city: "X".into(),
        };
        let m = score(&t);
        assert!(m.score >= 15, "score={} reasons={:?}", m.score, m.reasons);
        assert_eq!(tier(&m), "HOT");
        assert!(m.reasons.iter().any(|r| r.contains("SIEM")));
        assert!(m.reasons.iter().any(|r| r.contains("wod-kan")));
        assert!(m.reasons.iter().any(|r| r.contains("CPV 72")));
    }

    #[test]
    fn remont_parkingow_jest_cold() {
        let t = Tender {
            title: "Remont parkingu przy urzedzie miasta".into(),
            org: "Urzad Miasta".into(),
            url: String::new(),
            published: String::new(),
            deadline: String::new(),
            cpv: "45210000".into(),
            city: String::new(),
        };
        let m = score(&t);
        assert_eq!(tier(&m), "COLD");
    }

    #[test]
    fn edr_szpital_warm_plus() {
        let t = Tender {
            title: "Dostawa systemu EDR z wdrozeniem i szkoleniem".into(),
            org: "Samodzielny Publiczny Zaklad Opieki Zdrowotnej".into(),
            url: String::new(),
            published: String::new(),
            deadline: String::new(),
            cpv: String::new(),
            city: String::new(),
        };
        let m = score(&t);
        assert!(m.score >= 8);
        assert_ne!(tier(&m), "COLD");
    }
}
