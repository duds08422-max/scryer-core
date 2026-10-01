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
    pub typ: String,      // email_sent|email_recv|call|odpowiedz|notatka
    pub kierunek: String, // out|in|-
    pub email: String,
    pub podmiot_id: Option<i64>,
    pub temat: String,
    pub ts: i64,
    pub wynik: String,  // odpowiedziano|brak|optout|pilot|-
    pub ref_id: String, // message-id / identyfikator w outbox.jsonl
}

impl Ontology {
    /// Audyt (kto/co/kiedy) — zapis akcji do tabeli audyt.
    pub fn log_audyt(&self, aktor: &str, akcja: &str, szczegoly: &str) {
        let _ = self.conn.execute(
            "INSERT INTO audyt (ts, aktor, akcja, szczegoly) VALUES (?1, ?2, ?3, ?4)",
            params![now_secs(), aktor, akcja, szczegoly],
        );
    }

    /// id podmiotu powiązanego z domeną (jeśli jest).
    pub fn podmiot_id_by_domena(&self, domena: &str) -> Option<i64> {
        self.conn
            .query_row(
                "SELECT podmiot_id FROM domena WHERE nazwa = ?1",
                params![domena],
                |r| r.get(0),
            )
            .ok()
    }

    /// Uzupełnij metadane podmiotu z discovery (tylko puste pola — nie nadpisujemy).
    pub fn fill_podmiot_meta(
        &self,
        id: i64,
        miasto: Option<&str>,
        www: Option<&str>,
        opis: Option<&str>,
        telefon: Option<&str>,
    ) {
        if let Some(m) = miasto {
            if !m.is_empty() {
                let _ = self.conn.execute(
                    "UPDATE podmiot SET miasto = COALESCE(NULLIF(miasto,''), ?1) WHERE id = ?1",
                    params![id, m],
                );
            }
        }
        if let Some(w) = www {
            if !w.is_empty() {
                let _ = self.conn.execute(
                    "UPDATE podmiot SET zrodla = COALESCE(NULLIF(zrodla,''), ?1) WHERE id = ?1",
                    params![id, w],
                );
            }
        }
        if let Some(o) = opis {
            if !o.is_empty() {
                let _ = self.conn.execute(
                    "UPDATE podmiot SET ksc_status = ksc_status WHERE id = ?1",
                    params![id],
                );
                let _ = o; // opis pójdzie do osobnej kolumny w v0.8 (na razie pomijamy)
            }
        }
        if let Some(t) = telefon {
            if !t.is_empty() {
                let _ = self.conn.execute(
                    "UPDATE osoba SET telefon = COALESCE(NULLIF(telefon,''), ?1)
                     WHERE podmiot_id = ?2 AND rola = 'kontakt'",
                    params![t, id],
                );
            }
        }
    }

    /// Ustaw spf/dmarc na domenie po discovery.
    pub fn set_domena_mail(&self, domena: &str, spf: Option<&str>, dmarc: Option<&str>) {
        let _ = self.conn.execute(
            "UPDATE domena SET spf = COALESCE(?1, spf), dmarc = COALESCE(?2, dmarc) WHERE nazwa = ?3",
            params![spf, dmarc, domena],
        );
    }

    /// Zapis wskaźnika infrastruktury (pasywny DNS): ip/mx/ns → domena.
    /// Idempotentny (UNIQUE typ+wartość+domena); odświeża zobaczono_ts.
    pub fn upsert_wskaznik(&self, typ: &str, wartosc: &str, domena_id: i64) {
        let _ = self.conn.execute(
            "INSERT INTO wskaznik (typ, wartosc, domena_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(typ, wartosc, domena_id) DO UPDATE SET zobaczono_ts = unixepoch()",
            params![typ, wartosc, domena_id],
        );
    }

    /// OSINT-first: podmiot dla domeny — istnieje → id; nie ma → tworzy encję
    /// (nazwa z audytu WWW lub sama domena, sektor 'websearch'). Idempotentny.
    pub fn ensure_podmiot_by_domena(&self, domena: &str, nazwa: Option<&str>) -> SqlResult<i64> {
        if let Some(id) = self.podmiot_id_by_domena(domena) {
            return Ok(id);
        }
        let nazwa = nazwa
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| domena.to_string());
        let id = self.upsert_podmiot(&NewPodmiot {
            nazwa,
            nip: String::new(),
            sektor: "websearch".into(),
            wojewodztwo: String::new(),
            miasto: String::new(),
            pop: 0,
            zrodla: "internet".into(),
        })?;
        self.upsert_domena(domena, false, id)?;
        Ok(id)
    }

    /// Upsert domeny bez wiązania z podmiotem (discovery znalezione, nie klasyfikowane).
    /// Zwraca id; podmiot_id = 0 oznacza „bez ownera” w kontekście discovery.
    pub fn upsert_domena_free(&self, nazwa: &str, mx: bool) -> SqlResult<i64> {
        // juz istnieje → tylko update mx
        if let Ok(id) = self.conn.query_row(
            "SELECT id FROM domena WHERE nazwa=?1",
            params![nazwa],
            |r| r.get::<_, i64>(0),
        ) {
            let _ = self
                .conn
                .execute("UPDATE domena SET mx=?1 WHERE id=?2", params![mx, id]);
            return Ok(id);
        }
        // schema wymaga podmiot_id NOT NULL — używaj tylko z właścicielem; free → panic-free fallback:
        // tworzymy wirtualny podmiot "(internet)" raz i.linkujemy
        let owner: i64 = self.conn.query_row(
            "SELECT id FROM podmiot WHERE nazwa = '(internet)' LIMIT 1",
            [],
            |r| r.get(0),
        ).or_else(|_| {
            self.conn.execute(
                "INSERT INTO podmiot (nazwa, nip, sektor, zrodla) VALUES ('(internet)', NULL, 'discovery', 'discovery')",
                [],
            )
            .map(|_| self.conn.last_insert_rowid())
        })?;
        self.upsert_domena(nazwa, mx, owner)
    }

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
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        // migracje lekkie (idempotentne): starsze bazy nie maja mx_provider
        let _ = conn.execute_batch(
            "ALTER TABLE domena ADD COLUMN mx_provider TEXT DEFAULT '';",
        );
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
                params![
                    p.nazwa,
                    n,
                    p.sektor,
                    p.wojewodztwo,
                    p.miasto,
                    p.pop,
                    p.zrodla
                ],
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
        self.conn.query_row(
            "SELECT id FROM domena WHERE nazwa=?1",
            params![nazwa],
            |r| r.get(0),
        )
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
                self.upsert_domena(&dom, true, pid)
                    .map_err(|e| e.to_string())?;
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
        let allowed = [
            "podmiot",
            "domena",
            "osoba",
            "przetarg",
            "interakcja",
            "audyt",
        ];
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

-- Wskaźniki infrastruktury (pasywny DNS): IP/MX/NS obserwowane dla domeny.
-- Podstawa inference "wspólna infra" (dwa podmioty na tym samym MX/NS/IP).
CREATE TABLE IF NOT EXISTS wskaznik (
  id INTEGER PRIMARY KEY,
  typ TEXT NOT NULL,            -- 'ip' | 'mx' | 'ns'
  wartosc TEXT NOT NULL,
  domena_id INTEGER NOT NULL REFERENCES domena(id),
  zobaczono_ts INTEGER DEFAULT (unixepoch()),
  UNIQUE(typ, wartosc, domena_id)
);
CREATE INDEX IF NOT EXISTS idx_wskaznik_val ON wskaznik(typ, wartosc);
"#;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ASCII-fold + lowercase: ł→l, ó→o itd. Dla wyszukiwania bez diakrytyków.
fn fold_search(s: &str) -> String {
    fold_str(s)
}

/// Publiczny fold (używa też intel/server) — ł→l, ó→o, lower.
pub fn fold_str(s: &str) -> String {
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

impl Ontology {
    /// Backfill tier_score dla wszystkich podmiotow wg regul kampanii:
    /// waga sektora (Health 10/Water 9/Energy 9/Medtech 7/Admin 6/Other 3)
    /// +3 kontakt z wlasnej domeny (email istnieje, nie freemail)
    /// +3 instytucjonalny (kliniczny/uniwersytecki/wojskowy/MSWiA/onkolog/instytut)
    /// +2 wojewodztwo zachodniopomorskie, -4 freemail.
    /// Idempotentny; zwraca (updated, hot, warm, cold).
    pub fn backfill_tier_scores(&self) -> (usize, usize, usize, usize) {
        type PodmiotRow = (i64, Option<String>, Option<String>, Option<String>);
        let rows: Vec<PodmiotRow> = self
            .conn
            .prepare(
                "SELECT p.id, p.nazwa, p.sektor, p.wojewodztwo
                 FROM podmiot p",
            )
            .expect("select podmiot")
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .expect("query podmiot")
            .filter_map(|r| r.ok())
            .collect();

        // kontakt z wlasnej domeny istnieje? (osoba.email na domenie podmiotu, nie freemail)
        let has_own_contact = |pid: i64| -> bool {
            self.conn
                .query_row(
                    "SELECT COUNT(*) FROM osoba o
                     JOIN podmiot p ON p.id = o.podmiot_id
                     WHERE o.podmiot_id = ?1 AND o.email IS NOT NULL AND o.email != ''",
                    [pid],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0)
                > 0
        };
        let is_freemail = |email: &str| -> bool {
            let dom = email.split('@').nth(1).unwrap_or("").to_lowercase();
            const FREE: [&str; 14] = [
                "wp.pl", "op.pl", "onet.pl", "interia.pl", "gmail.com", "o2.pl", "vp.pl",
                "poczta.onet.pl", "poczta.fm", "tlen.pl", "go2.pl", "hotmail.com",
                "yahoo.com", "neostrada.pl",
            ];
            FREE.contains(&dom.as_str())
        };
        let contact_is_freemail = |pid: i64| -> bool {
            self.conn
                .query_row(
                    "SELECT o.email FROM osoba o WHERE o.podmiot_id = ?1 AND o.email IS NOT NULL AND o.email != '' LIMIT 1",
                    [pid],
                    |r| r.get::<_, String>(0),
                )
                .map(|e| is_freemail(&e))
                .unwrap_or(false)
        };

        let mut updated = 0usize;
        let mut hot = 0usize;
        let mut warm = 0usize;
        let mut cold = 0usize;
        for (pid, nazwa, sektor, woj) in &rows {
            let mut s: i64 = match sektor.as_deref().unwrap_or("").trim().to_lowercase().as_str() {
                "zdrowie" | "health" | "szpital" | "szpitale" => 10,
                "woda" | "water" | "zwik" | "wodociagi" | "wodociągi" => 9,
                "energia" | "energy" | "ot" | "energetyka" => 9,
                "medtech" | "medsoft" | "med" => 7,
                "admin" | "public" | "urzad" | "urząd" | "gmina" => 6,
                _ => 3,
            };
            let nazwa_l = nazwa.as_deref().unwrap_or("").to_lowercase();
            if ["klinicz", "uniwersyteck", "wojewódzk", "wojewodzk", "wojskow", "mswia", "onkolog", "instytut"]
                .iter()
                .any(|k| nazwa_l.contains(k))
            {
                s += 3;
            }
            if woj.as_deref().unwrap_or("").trim().eq_ignore_ascii_case("zachodniopomorskie") {
                s += 2;
            }
            if has_own_contact(*pid) {
                s += 3;
                if contact_is_freemail(*pid) {
                    s -= 4;
                }
            }
            let tier = if s >= 15 { "HOT" } else if s >= 10 { "WARM" } else { "COLD" };
            match tier {
                "HOT" => hot += 1,
                "WARM" => warm += 1,
                _ => cold += 1,
            }
            let _ = self.conn.execute(
                "UPDATE podmiot SET tier_score = ?2 WHERE id = ?1",
                params![pid, s],
            );
            updated += 1;
        }
        self.log_audyt(
            "cli",
            "score-db",
            &format!("backfill tier_score: {updated} podmiotow (HOT={hot} WARM={warm} COLD={cold})"),
        );
        (updated, hot, warm, cold)
    }

    /// Domeny z ontologii do bulk recon: (domena, podmiot_id, juz ma dmarc).
    /// Sortowane: najpierw domeny podmiotow HOT (najwyzszy tier_score), potem reszta.
    pub fn domeny_do_recon(&self, limit: usize) -> SqlResult<Vec<(String, Option<i64>, bool)>> {
        self.conn
            .prepare(
                "SELECT d.nazwa, p.id,
                        (d.dmarc IS NOT NULL AND d.dmarc != '') AS ma_dmarc
                 FROM domena d
                 LEFT JOIN podmiot p ON p.id = d.podmiot_id
                 ORDER BY COALESCE(p.tier_score, 0) DESC, d.nazwa
                 LIMIT ?1",
            )
            .expect("select domeny")
            .query_map([limit as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, i64>(2)? != 0,
                ))
            })
            .expect("query domeny")
            .collect()
    }

    /// Zapis wyniku bulk recon do domeny (+ fingerprint dostawcy MX).
    pub fn zapisz_recon_mail(&self, domena: &str, mx: bool, mx_provider: &str,
                             spf: Option<&str>, dmarc: Option<&str>) {
        self.set_domena_mail(domena, spf, dmarc);
        let _ = self.conn.execute(
            "UPDATE domena SET mx = ?2 WHERE nazwa = ?1",
            params![domena, mx],
        );
        let _ = self.conn.execute(
            "UPDATE domena SET mx_provider = ?2 WHERE nazwa = ?1",
            params![domena, mx_provider],
        );
    }
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
