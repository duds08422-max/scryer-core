//! ontology — warstwa decyzyjna Scryera (wzorzec: Palantir Ontology).
//!
//! Semantyka (obiekty + linki) i kinetyka (akcje z audytem) na jednym
//! pliku SQLite. Deterministyczna, audytowalna, air-gap friendly:
//! jeden plik = cała wiedza; wszystko da się wyeksportować z powrotem
//! do JSONL + manifest sha256.
//!
//! Zasady:
//! 1. Każdy obiekt niesie źródła[] (pochodzenie danych).
//! 2. Każda akcja (wysłany mail, suppression) = wiersz Interakcji/Audyt.
//! 3. LLM/agent pisze WYŁĄCZNIE przez akcje — nigdy prosto do tabel.

use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;

pub struct Ontology {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct Podmiot {
    pub id: i64,
    pub nazwa: String,
    pub nip: String,
    pub sektor: String,
    pub wojewodztwo: String,
    pub miasto: String,
    pub pop: i64,
    pub ksc_status: String, // nieznany|wpisany|wysoki
    pub tier_score: i64,
}

#[derive(Debug, Clone)]
pub struct Domena {
    pub id: i64,
    pub nazwa: String,
    pub mx: bool,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub podmiot_id: i64,
}

#[derive(Debug, Clone)]
pub struct Interakcja {
    pub id: i64,
    pub typ: String,       // email_sent|email_recv|call|odpowiedz|notatka
    pub kierunek: String,  // out|in|-
    pub email: String,
    pub podmiot_id: Option<i64>,
    pub temat: String,
    pub ts: i64,
    pub wynik: String,     // odpowiedziano|brak|optout|pilot|-
    pub ref_id: String,    // message-id / identyfikator w outbox.jsonl
}

impl Ontology {
    /// Rejestruj funkcje SQL (fold_search: ascii-fold + lower dla wyszukiwania
    /// odpornego na polskie znaki — "krakow" znajdzie "Kraków").
    pub fn register_sql_functions(&self) {
        use rusqlite::functions::FunctionFlags;
        self.conn
            .create_scalar_function(
                "fold_search",
                2,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
                |ctx| {
                    // NULL (np. pusty NIP) traktujemy jako pusty string — błąd tutaj
                    // wywaliłby cały STEP zapytania i po cichu zerował wyniki.
                    let a: Option<String> = ctx.get(0).unwrap_or(None);
                    let b: Option<String> = ctx.get(1).unwrap_or(None);
                    Ok(fold_search(&a.unwrap_or_default())
                        .contains(&fold_search(&b.unwrap_or_default())))
                },
            )
            .ok(); // idempotentne; kolizja = trudno, LIKE nadal działa
    }

    /// Otwórz (lub utwórz) bazę ontologii i zasiguruj schemat.
    pub fn open(path: &Path) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_memory() -> SqlResult<Self> {
        Self::open(Path::new(":memory:"))
    }

    /// Dostęp do połączenia (dla modułu zapytań).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Upsert podmiotu po NIP (fallback: nazwa+miasto). Zwraca id.
    pub fn upsert_podmiot(&self, p: &NewPodmiot) -> SqlResult<i64> {
        // pusty NIP = NULL (inaczej UNIQUE(nip) kolizja wszystkich "bez NIP")
        let nip: Option<String> = if p.nip.trim().is_empty() {
            None
        } else {
            Some(p.nip.trim().to_string())
        };
        let id: i64 = if let Some(n) = &nip {
            let mut stmt = self.conn.prepare_cached(
                "INSERT INTO podmiot (nazwa, nip, sektor, wojewodztwo, miasto, pop, zrodla)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(nip) DO UPDATE SET
                   nazwa=excluded.nazwa, sektor=excluded.sektor,
                   wojewodztwo=excluded.wojewodztwo, miasto=excluded.miasto,
                   pop=MAX(pop, excluded.pop)
                 RETURNING id",
            )?;
            stmt.query_row(
                params![p.nazwa, n, p.sektor, p.wojewodztwo, p.miasto, p.pop, p.zrodla],
                |r| r.get(0),
            )?
        } else {
            self.conn.execute(
                "INSERT INTO podmiot (nazwa, nip, sektor, wojewodztwo, miasto, pop, zrodla)
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6)",
                params![p.nazwa, p.sektor, p.wojewodztwo, p.miasto, p.pop, p.zrodla],
            )?;
            self.conn.last_insert_rowid()
        };
        Ok(id)
    }

    /// Upsert domeny (klucz: nazwa) i podlinkowanie do podmiotu.
    pub fn upsert_domena(&self, nazwa: &str, mx: bool, podmiot_id: i64) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO domena (nazwa, mx, podmiot_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(nazwa) DO UPDATE SET mx=excluded.mx",
            params![nazwa, mx, podmiot_id],
        )?;
        self.conn.query_row("SELECT id FROM domena WHERE nazwa=?1", params![nazwa], |r| r.get(0))
    }

    /// Zapis interakcji (kinetyka: wysłany/odebrany mail, notatka).
    pub fn log_interakcja(&self, i: &NewInterakcja) -> SqlResult<i64> {
        let podmiot_id = self.podmiot_by_email(&i.email)?;
        self.conn.execute(
            "INSERT INTO interakcja (typ, kierunek, email, podmiot_id, temat, ts, wynik, ref_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![i.typ, i.kierunek, i.email, podmiot_id, i.temat, i.ts, i.wynik, i.ref_id],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Podmiot po emailu (przez domena->podmiot fallback: dopasowanie po domenie maila).
    pub fn podmiot_by_email(&self, email: &str) -> SqlResult<Option<i64>> {
        let dom = email.split('@').nth(1).unwrap_or("").to_lowercase();
        if dom.is_empty() {
            return Ok(None);
        }
        let mut stmt = self.conn.prepare_cached(
            "SELECT p.id FROM podmiot p
             JOIN domena d ON d.podmiot_id = p.id
             WHERE ?1 LIKE '%' || d.nazwa
             ORDER BY LENGTH(d.nazwa) DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![format!("@{dom}")])?;
        if let Some(r) = rows.next()? {
            Ok(Some(r.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Suppression z grafu: czy wysłaliśmy już kampanijny mail na ten adres?
    pub fn is_suppressed(&self, email: &str) -> SqlResult<bool> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT COUNT(*) FROM interakcja WHERE email=?1 AND typ='email_sent'",
        )?;
        let n: i64 = stmt.query_row(params![email.to_lowercase()], |r| r.get(0))?;
        Ok(n > 0)
    }

    /// Migracja: wczytaj leady z seeda JSON do ontologii. Zwraca liczbę wstawionych.
    pub fn import_leads_json(&self, raw: &str) -> Result<usize, String> {
        #[derive(serde::Deserialize)]
        struct L {
            org: String,
            email: String,
            #[serde(default)]
            domain: String,
            #[serde(default)]
            sector: String,
            #[serde(default)]
            voivodeship: String,
            #[serde(default, alias = "miejscowosc")]
            city: String,
            #[serde(default)]
            pop: i64,
            #[serde(default)]
            nip: String,
            #[serde(default)]
            source: String,
        }
        #[derive(serde::Deserialize)]
        struct W {
            #[serde(default)]
            leads: Vec<L>,
        }
        let leads: Vec<L> = if let Ok(v) = serde_json::from_str::<Vec<L>>(raw) {
            v
        } else {
            serde_json::from_str::<W>(raw)
                .map_err(|e| format!("JSON: {e}"))?
                .leads
        };
        let mut n = 0usize;
        let mut skipped = 0usize;
        for l in leads {
            let dom = if l.domain.is_empty() {
                l.email.split('@').nth(1).unwrap_or("").to_string()
            } else {
                l.domain.clone()
            };
            let pid = match self.upsert_podmiot(&NewPodmiot {
                nazwa: l.org.clone(),
                nip: l.nip.clone(),
                sektor: l.sector.clone(),
                wojewodztwo: l.voivodeship.clone(),
                miasto: l.city.clone(),
                pop: l.pop,
                zrodla: l.source.clone(),
            }) {
                Ok(id) => id,
                Err(rusqlite::Error::SqliteFailure(_, _)) => {
                    skipped += 1;
                    continue;
                }
                Err(e) => return Err(e.to_string()),
            };
            if !dom.is_empty() {
                self.upsert_domena(&dom, true, pid).map_err(|e| e.to_string())?;
            }
            self.upsert_osoba_email(&l.email, "kontakt", pid)
                .map_err(|e| e.to_string())?;
            n += 1;
        }
        if skipped > 0 {
            println!("  (pominięte duplikaty: {skipped})");
        }
        Ok(n)
    }

    /// Kontakt (osoba) upsert po emailu.
    pub fn upsert_osoba_email(&self, email: &str, rola: &str, podmiot_id: i64) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO osoba (email, rola, podmiot_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(email) DO UPDATE SET rola=excluded.rola",
            params![email.to_lowercase(), rola, podmiot_id],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Przetarg upsert + link do podmiotu (po nazwie organizatora, jeśli znamy).
    pub fn upsert_przetarg(
        &self,
        tytul: &str,
        org: &str,
        url: &str,
        deadline: &str,
        cpv: &str,
        match_score: i64,
    ) -> SqlResult<i64> {
        self.conn.execute(
            "INSERT INTO przetarg (tytul, org, url, deadline, cpv, match_score)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(url) DO UPDATE SET match_score=excluded.match_score",
            params![tytul, org, url, deadline, cpv, match_score],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Liczba wierszy w tabeli (do `ask stats`).
    pub fn count_table(&self, table: &str) -> SqlResult<i64> {
        // biała lista — bez interpolacji z wejścia użytkownika
        let allowed = ["podmiot", "domena", "osoba", "przetarg", "interakcja", "audyt"];
        if !allowed.contains(&table) {
            return Err(rusqlite::Error::InvalidParameterName("bad table".into()));
        }
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
    }

    /// HOT podmioty z brakiem DMARC (przykładowe zapytanie decyzyjne v0.4).
    pub fn hot_bez_dmarc(&self) -> SqlResult<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.nazwa, d.nazwa FROM podmiot p
             JOIN domena d ON d.podmiot_id = p.id
             WHERE p.tier_score >= 15 AND (d.dmarc IS NULL OR d.dmarc = '')
             ORDER BY p.tier_score DESC",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    /// Podmioty bez kontaktu w ostatnich `days` dni (do kampanii follow-up).
    pub fn bez_kontaktu_od(&self, days: i64) -> SqlResult<Vec<String>> {
        let cutoff = now_secs() - days * 86400;
        let mut stmt = self.conn.prepare(
            "SELECT o.email FROM osoba o
             WHERE NOT EXISTS (
               SELECT 1 FROM interakcja i
               WHERE i.email = o.email AND i.ts >= ?1
             )",
        )?;
        let rows = stmt.query_map(params![cutoff], |r| r.get(0))?;
        rows.collect()
    }
}

#[derive(Debug, Clone)]
pub struct NewPodmiot {
    pub nazwa: String,
    pub nip: String,
    pub sektor: String,
    pub wojewodztwo: String,
    pub miasto: String,
    pub pop: i64,
    pub zrodla: String,
}

#[derive(Debug, Clone)]
pub struct NewInterakcja {
    pub typ: String,
    pub kierunek: String,
    pub email: String,
    pub temat: String,
    pub ts: i64,
    pub wynik: String,
    pub ref_id: String,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS podmiot (
  id INTEGER PRIMARY KEY,
  nazwa TEXT NOT NULL,
  nip TEXT UNIQUE,
  sektor TEXT,
  wojewodztwo TEXT,
  miasto TEXT,
  pop INTEGER DEFAULT 0,
  ksc_status TEXT DEFAULT 'nieznany',
  tier_score INTEGER DEFAULT 0,
  zrodla TEXT,
  created_ts INTEGER DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_podmiot_nazwa_miasto
  ON podmiot(nazwa, miasto) WHERE nip IS NULL OR nip = '';

CREATE TABLE IF NOT EXISTS domena (
  id INTEGER PRIMARY KEY,
  nazwa TEXT UNIQUE NOT NULL,
  mx INTEGER DEFAULT 0,
  spf TEXT,
  dmarc TEXT,
  audyt_ts INTEGER,
  podmiot_id INTEGER NOT NULL REFERENCES podmiot(id)
);

CREATE TABLE IF NOT EXISTS osoba (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  rola TEXT,
  telefon TEXT,
  podmiot_id INTEGER NOT NULL REFERENCES podmiot(id)
);

CREATE TABLE IF NOT EXISTS przetarg (
  id INTEGER PRIMARY KEY,
  tytul TEXT NOT NULL,
  org TEXT,
  url TEXT UNIQUE,
  deadline TEXT,
  cpv TEXT,
  match_score INTEGER DEFAULT 0,
  status TEXT DEFAULT 'nowy',
  created_ts INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS interakcja (
  id INTEGER PRIMARY KEY,
  typ TEXT NOT NULL,
  kierunek TEXT,
  email TEXT,
  podmiot_id INTEGER REFERENCES podmiot(id),
  temat TEXT,
  ts INTEGER NOT NULL,
  wynik TEXT DEFAULT '-',
  ref_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_interakcja_email ON interakcja(email);

CREATE TABLE IF NOT EXISTS audyt (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  aktor TEXT,
  akcja TEXT NOT NULL,
  szczegoly TEXT
);
"#;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ASCII-fold + lowercase: ł→l, ó→o itd. Dla wyszukiwania bez diakrytyków.
fn fold_search(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ą' | 'Ą' => 'a',
            'ć' | 'Ć' => 'c',
            'ę' | 'Ę' => 'e',
            'ł' | 'Ł' => 'l',
            'ń' | 'Ń' => 'n',
            'ó' | 'Ó' => 'o',
            'ś' | 'Ś' => 's',
            'ź' | 'Ź' | 'ż' | 'Ż' => 'z',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_search_folduje_polskie_znaki() {
        let o = Ontology::open_memory().unwrap();
        o.register_sql_functions();
        let v: bool = o
            .conn
            .query_row("SELECT fold_search('Kraków', 'krakow')", [], |r| r.get(0))
            .unwrap();
        assert!(v, "krakow ma znalezc Kraków");
    }

    #[test]
    fn open_memory_tworzy_schemat() {
        let o = Ontology::open_memory().unwrap();
        let n: i64 = o
            .conn
            .query_row("SELECT COUNT(*) FROM podmiot", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn upsert_podmiot_nip_idempotentny() {
        let o = Ontology::open_memory().unwrap();
        let p = NewPodmiot {
            nazwa: "ZWiK Szczecin".into(),
            nip: "8512624854".into(),
            sektor: "water".into(),
            wojewodztwo: "zachodniopomorskie".into(),
            miasto: "Szczecin".into(),
            pop: 391_000,
            zrodla: "test".into(),
        };
        let a = o.upsert_podmiot(&p).unwrap();
        let b = o.upsert_podmiot(&p).unwrap();
        assert_eq!(a, b, "ten sam NIP = ten sam podmiot");
    }

    #[test]
    fn interakcja_suppression_i_bez_kontaktu() {
        let o = Ontology::open_memory().unwrap();
        let pid = o
            .upsert_podmiot(&NewPodmiot {
                nazwa: "USK Opole".into(),
                nip: String::new(),
                sektor: "health".into(),
                wojewodztwo: "opolskie".into(),
                miasto: "Opole".into(),
                pop: 120_000,
                zrodla: "test".into(),
            })
            .unwrap();
        o.upsert_domena("usk.opole.pl", true, pid).unwrap();
        o.upsert_osoba_email("centrum@usk.opole.pl", "kontakt", pid)
            .unwrap();

        assert!(!o.is_suppressed("centrum@usk.opole.pl").unwrap());
        o.log_interakcja(&NewInterakcja {
            typ: "email_sent".into(),
            kierunek: "out".into(),
            email: "centrum@usk.opole.pl".into(),
            temat: "KSC".into(),
            ts: now_secs(),
            wynik: "-".into(),
            ref_id: "resend:abc".into(),
        })
        .unwrap();
        assert!(o.is_suppressed("centrum@usk.opole.pl").unwrap());

        let bez = o.bez_kontaktu_od(30).unwrap();
        assert!(!bez.iter().any(|e| e == "centrum@usk.opole.pl"));
    }

    #[test]
    fn podmiot_by_email_dopasowuje_subdomene() {
        let o = Ontology::open_memory().unwrap();
        let pid = o
            .upsert_podmiot(&NewPodmiot {
                nazwa: "Wodociagi Krakow".into(),
                nip: String::new(),
                sektor: "water".into(),
                wojewodztwo: "malopolskie".into(),
                miasto: "Krakow".into(),
                pop: 800_000,
                zrodla: "test".into(),
            })
            .unwrap();
        o.upsert_domena("wodociagi.krakow.pl", true, pid).unwrap();
        let got = o.podmiot_by_email("biuro@wodociagi.krakow.pl").unwrap();
        assert_eq!(got, Some(pid));
    }

    #[test]
    fn import_leads_json_wczytuje_seed() {
        let o = Ontology::open_memory().unwrap();
        let raw = r#"{"leads":[
            {"org":"ZWiK Lodz","email":"bok@zwik.lodz.pl","domain":"zwik.lodz.pl",
             "sector":"wodociagi","voivodeship":"lodzkie","city":"Lodz","pop":650000,"source":"test"}
        ]}"#;
        let n = o.import_leads_json(raw).unwrap();
        assert_eq!(n, 1);
        let got = o.podmiot_by_email("bok@zwik.lodz.pl").unwrap();
        assert!(got.is_some());
    }
}
