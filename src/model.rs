//! model — typy domenowe Scryera (Lead, Sector, Hook).
//!
//! Wydzielone z main.rs przy refaktorze na moduły; semantyka bez zmian
//! (scoring + parsowanie polskich nazw sektorów z BIP/BZP).

use serde::{Deserialize, Serialize};

use std::fmt;

/// Sektor wg wrażliwości KSC/NIS2 — wyższy = mocniejszy hook prawny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sector {
    /// Zdrowie (szpitale = USK, zalecenia CSIRT CeZ)
    Health,
    /// Wodociągi / komunalne (ZWiK — pattern seryjny z linii 1)
    Water,
    /// Energetyka / przemysł OT
    Energy,
    /// Administracja publiczna (urzędy, GPK)
    PublicAdmin,
    /// Medi-tech / dostawcy (Medsoft-like)
    Medtech,
    /// Pozostałe
    Other,
}

impl Sector {
    pub fn weight(self) -> u32 {
        match self {
            Sector::Health => 10,
            Sector::Water => 9,
            Sector::Energy => 9,
            Sector::PublicAdmin => 6,
            Sector::Medtech => 7,
            Sector::Other => 3,
        }
    }

    /// Parsuje polskie i angielskie nazwy (BIP/BZP piszą po ludzku).
    pub fn parse(s: &str) -> Sector {
        match s.trim().to_lowercase().as_str() {
            "zdrowie" | "health" | "szpital" | "szpitale" => Sector::Health,
            "woda" | "water" | "zwik" | "wodociagi" | "wodociągi" => Sector::Water,
            "energia" | "energy" | "ot" | "energetyka" => Sector::Energy,
            "admin" | "public" | "urzad" | "urząd" | "gmina" => Sector::PublicAdmin,
            "medtech" | "medsoft" | "med" => Sector::Medtech,
            _ => Sector::Other,
        }
    }
}

// Deserializacja toleruje snake_case EN i polskie nazwy — wsady przychodzą
// z BIP/BZP/seedów pisanych po ludzku (test loader_json_dwoch_ksztaltow).
impl<'de> Deserialize<'de> for Sector {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Ok(Sector::parse(&s))
    }
}

impl fmt::Display for Sector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Sector::Health => "zdrowie",
            Sector::Water => "wodociagi",
            Sector::Energy => "energetyka",
            Sector::PublicAdmin => "admin-publiczna",
            Sector::Medtech => "medtech",
            Sector::Other => "inne",
        };
        write!(f, "{s}")
    }
}

/// Hook kampanijny — co mówi się w mailu (wiadomość czasowa = siła maila).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    /// Samorejestracja KSC do 3.10.2026 — hook twardy, termin minie
    KscDeadline(u32),
    /// Środki techniczne NIS2/UKSC 3.04.2027 — okno planowania
    Nis2Window,
    /// Aktywne przetargi (BZP) — kupują teraz
    TenderActive,
    /// Zalecenia CSIRT CeZ dla sektora (16.09) — sektor medyczny
    CezRecommendation,
}

impl Hook {
    pub fn label(&self) -> &'static str {
        match self {
            Hook::KscDeadline(_) => "KSC: samorejestracja do 3.10",
            Hook::Nis2Window => "NIS2: środki do 3.04.2027",
            Hook::TenderActive => "BZP: aktywny przetarg",
            Hook::CezRecommendation => "Zalecenia CSIRT CeZ",
        }
    }
}

/// Pojedynczy lead (wiersz z seeda / eksportu BIP / scrapu).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lead {
    pub org: String,
    #[serde(default)]
    pub domain: String,
    pub email: String,
    pub sector: Sector,
    #[serde(default)]
    pub voivodeship: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub hooks: Vec<Hook>,
    #[serde(default)]
    pub source: String,
    /// Liczba mieszkańców miasta (harvester TERYT/Wikipedia) — proxy budżetu.
    #[serde(default)]
    pub pop: u32,
    /// Miasto (jeśli znane) — do raportów i lokalnego boosta.
    #[serde(default)]
    pub city: String,
}

impl Lead {
    /// Stabilny identyfikator dedupe: sha256(lowercase(email))[:16].
    pub fn id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.email.trim().to_lowercase().as_bytes());
        let out = h.finalize();
        out.iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_string()
    }

    /// Wynik (0..=30+): sektor + hooki + jakość kontaktu. Przezroczysty, audit-ready.
    ///
    /// v0.2: sygnały instytucjonalne (kliniczne/wojskowe/MSWiA = zamożniejsze
    /// i bardziej narażone), boost lokalny (zachodniopomorskie = nasz region,
    /// pilotaż face-to-face), kara za freemail (prywatne skrzynki nie grają w B2B).
    pub fn score(&self) -> u32 {
        let mut s = self.sector.weight();
        for hook in &self.hooks {
            s += match hook {
                Hook::KscDeadline(days) if *days <= 7 => 5,
                Hook::KscDeadline(_) => 3,
                Hook::Nis2Window => 2,
                Hook::TenderActive => 4,
                Hook::CezRecommendation => 2,
            };
        }
        if self.email_verified {
            s += 3;
        }
        // instytucjonalne = najwyższy priorytet kampanii (v0.2)
        if self.is_institutional() {
            s += 3;
        }
        // lokalny boost — nasz region, kontakt osobisty realny (v0.2)
        if self.voivodeship.trim().eq_ignore_ascii_case("zachodniopomorskie") {
            s += 2;
        }
        // freemail = prywatna skrzynka, martwy tor w outreachu B2B (v0.2)
        if Self::is_freemail(&self.email) {
            s = s.saturating_sub(4);
        }
        s
    }

    /// Klasyczny domena-koniec jest freemailem (wp/op/onet/gmail/...).
    pub fn is_freemail(email: &str) -> bool {
        let dom = email.split('@').nth(1).unwrap_or("").to_lowercase();
        const FREE: [&str; 14] = [
            "wp.pl", "op.pl", "onet.pl", "interia.pl", "gmail.com", "o2.pl", "vp.pl",
            "poczta.onet.pl", "poczta.fm", "tlen.pl", "go2.pl", "hotmail.com",
            "yahoo.com", "neostrada.pl",
        ];
        FREE.contains(&dom.as_str())
    }

    /// Sygnały dużej instytucji (kliniczna/uniwersytecka/wojskowa/MSWiA/
    /// wojewódzka/onkologia/instytut) — rozróżnia szpital powiatowy od USK.
    pub fn is_institutional(&self) -> bool {
        let n = self.org.to_lowercase();
        ["klinicz", "uniwersyteck", "wojewódzk", "wojewodzk", "wojskow", "mswia", "onkolog", "instytut"]
            .iter()
            .any(|k| n.contains(k))
    }

    /// Tier kampanijny: HOT = 1. fala, WARM = 2. fala, COLD = nurture.
    pub fn tier(&self) -> &'static str {
        match self.score() {
            15..=u32::MAX => "HOT",
            10..=14 => "WARM",
            _ => "COLD",
        }
    }

    /// Domena z pola domain (fallback: z maila; else None).
    pub fn effective_domain(&self) -> Option<String> {
        let from_field = self.domain.trim();
        if !from_field.is_empty() {
            return Some(from_field.trim_end_matches('.').to_lowercase());
        }
        let e = self.email.trim();
        let (_, dom) = e.split_once('@')?;
        let dom = dom.trim();
        if dom.is_empty() || !dom.contains('.') {
            return None;
        }
        Some(dom.trim_end_matches('.').to_lowercase())
    }
}
