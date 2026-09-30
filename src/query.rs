//! query — v0.7: mini-język zapytań decyzyjnych po ontologii.
//!
//! Gramatyka (deterministyczna, bez LLM; audit-ready):
//!   <obiekt>[filtr1,filtr2...] [!<obiekt2>[...]] [limit N]
//! Obiekty: podmioty | domeny | przetargi | interakcje
//! Filtry:  klucz=wartość | klucz>liczba | klucz<liczba | klucz~fragment
//! Negacja: !interakcje[email_sent]  = "bez żadnej takiej interakcji"
//!
//! Przykłady:
//!   podmioty[sektor=water,pop>100000] !interakcje[email_sent]
//!   podmioty[tier=HOT] domeny[dmarc=brak] limit 30
//!   przetargi[cpv~72,status=nowy]

use crate::ontology::Ontology;

#[derive(Debug, PartialEq)]
pub struct Filter {
    pub key: String,
    pub op: char, // '=', '>', '<', '~'
    pub val: String,
}

#[derive(Debug, PartialEq)]
pub struct Term {
    pub negated: bool,
    pub object: String, // podmioty|domeny|przetargi|interakcje
    pub filters: Vec<Filter>,
}

#[derive(Debug, PartialEq)]
pub struct Query {
    pub terms: Vec<Term>,
    pub limit: usize,
}

pub fn parse(q: &str) -> Result<Query, String> {
    let q = q.trim();
    let mut limit = 30usize;
    let mut body = q;
    if let Some(pos) = q.to_lowercase().rfind("limit ") {
        let num = q[pos + 6..].trim();
        limit = num.parse().map_err(|_| format!("zły limit: {num}"))?;
        body = &q[..pos];
    }

    let mut terms = Vec::new();
    for raw in body.split_whitespace() {
        let (negated, raw) = if let Some(r) = raw.strip_prefix('!') {
            (true, r)
        } else {
            (false, raw)
        };
        let (obj, filters_str) = match raw.split_once('[') {
            Some((o, rest)) => {
                let f = rest
                    .strip_suffix(']')
                    .ok_or_else(|| format!("brak ] w: {raw}"))?;
                (o, f)
            }
            None => (raw, ""),
        };
        let mut filters = Vec::new();
        if !filters_str.is_empty() {
            for f in filters_str.split(',') {
                let (key, op, val) = if let Some((k, v)) = f.split_once(">=") {
                    (k, '>', v)
                } else if let Some((k, v)) = f.split_once("<=") {
                    (k, '<', v)
                } else if let Some((k, v)) = f.split_once('~') {
                    (k, '~', v)
                } else if let Some((k, v)) = f.split_once('=') {
                    (k, '=', v)
                } else if let Some((k, v)) = f.split_once('>') {
                    (k, '>', v)
                } else if let Some((k, v)) = f.split_once('<') {
                    (k, '<', v)
                } else {
                    // filtr bez operatora: "email_sent" == typ=email_sent (skrót)
                    filters.push(Filter {
                        key: "typ".into(),
                        op: '=',
                        val: f.trim().to_string(),
                    });
                    continue;
                };
                filters.push(Filter {
                    key: key.trim().to_lowercase(),
                    op,
                    val: val.trim().to_string(),
                });
            }
        }
        terms.push(Term {
            negated,
            object: obj.to_lowercase(),
            filters,
        });
    }
    if terms.is_empty() {
        return Err("puste zapytanie".into());
    }
    Ok(Query { terms, limit })
}

/// Mapowanie filtrów na warunki SQL per obiekt (biała lista kolumn!).
fn where_for(
    object: &str,
    filters: &[Filter],
    offset: usize,
) -> Result<(String, Vec<String>), String> {
    let mut conds: Vec<String> = Vec::new();
    let mut vals: Vec<String> = Vec::new();
    for (i, f) in filters.iter().enumerate() {
        let p = format!("?{}", i + 1 + offset);
        let (col, sql_op) = match (object, f.key.as_str(), f.op) {
            ("podmioty", "sektor", '=') => ("p.sektor", "="),
            ("podmioty", "sektor", '~') => ("p.sektor", "LIKE"),
            ("podmioty", "wojewodztwo", '=') => ("p.wojewodztwo", "="),
            ("podmioty", "wojewodztwo", '~') => ("p.wojewodztwo", "LIKE"),
            ("podmioty", "miasto", '~') => ("p.miasto", "LIKE"),
            ("podmioty", "nazwa", '~') => ("p.nazwa", "LIKE"),
            ("podmioty", "pop", '>') | ("podmioty", "pop", '<') | ("podmioty", "pop", '=') => (
                "p.pop",
                match f.op {
                    '>' => ">",
                    '<' => "<",
                    _ => "=",
                },
            ),
            ("podmioty", "ksc", '=') => ("p.ksc_status", "="),
            ("przetargi", "status", '=') => ("t.status", "="),
            ("przetargi", "cpv", '~') => ("t.cpv", "LIKE"),
            ("interakcje", "typ", '=') => ("i.typ", "="),
            ("interakcje", "wynik", '=') => ("i.wynik", "="),
            _ => return Err(format!("nieznany filtr {}{} dla {}", f.key, f.op, object)),
        };
        let v = if sql_op == "LIKE" {
            format!("%{}%", f.val)
        } else {
            f.val.clone()
        };
        conds.push(format!("{col} {sql_op} {p}"));
        vals.push(v);
    }
    Ok((conds.join(" AND "), vals))
}

/// Wykonaj zapytanie; zwraca wiersze jako stringi gotowe do wydruku.
pub fn run(o: &Ontology, q: &Query) -> Result<Vec<String>, String> {
    let first = q.terms.first().ok_or("brak warunków")?;
    if first.negated {
        return Err("pierwszy człon nie może być negacją".into());
    }
    let (mut sql, mut vals) = match first.object.as_str() {
        "podmioty" => {
            let (w, v) = where_for("podmioty", &first.filters, 0)?;
            (
                format!("SELECT p.nazwa, p.sektor, p.miasto, p.pop FROM podmiot p WHERE {w}"),
                v,
            )
        }
        "przetargi" => {
            let (w, v) = where_for("przetargi", &first.filters, 0)?;
            (
                format!(
                    "SELECT t.tytul, t.org, t.deadline, t.match_score FROM przetarg t WHERE {w}"
                ),
                v,
            )
        }
        "interakcje" => {
            let (w, v) = where_for("interakcje", &first.filters, 0)?;
            (
                format!("SELECT i.ts, i.typ, i.email, i.temat FROM interakcja i WHERE {w}"),
                v,
            )
        }
        other => return Err(format!("nieznany obiekt: {other}")),
    };

    // negacje: EXCLUDE podmioty które mają jakąkolwiek interakcję pasującą
    for term in &q.terms[1..] {
        if !term.negated {
            return Err("na razie tylko negacje po pierwszym członie (!...)".into());
        }
        if term.object == "interakcje" {
            let (w, v) = where_for("interakcje", &term.filters, vals.len())?;
            sql.push_str(&format!(
                " AND p.id NOT IN (
                   SELECT COALESCE(i.podmiot_id, -1) FROM interakcja i WHERE {w}
                 )"
            ));
            vals.extend(v);
        } else {
            return Err(format!("negacja {} jeszcze nieobsługiwana", term.object));
        }
    }
    sql.push_str(&format!(" LIMIT {}", q.limit));

    let conn = o.conn();
    let mut stmt = conn.prepare(&sql).map_err(|e| format!("SQL: {e}"))?;
    let ncols = stmt.column_count();
    let pv: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(pv), move |r| {
            let mut cells = Vec::with_capacity(ncols);
            for i in 0..ncols {
                let v: String = r
                    .get_ref(i)
                    .ok()
                    .map(|vr| match vr {
                        rusqlite::types::ValueRef::Text(t) => {
                            String::from_utf8_lossy(t).to_string()
                        }
                        rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                        _ => String::new(),
                    })
                    .unwrap_or_default();
                cells.push(v);
            }
            Ok(cells.join(" | "))
        })
        .map_err(|e| format!("SQL: {e}"))?;
    rows.collect::<rusqlite::Result<Vec<String>>>()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rozpoznaje_filtry_i_negacje() {
        let q =
            parse("podmioty[sektor=water,pop>100000] !interakcje[email_sent] limit 10").unwrap();
        assert_eq!(q.limit, 10);
        assert_eq!(q.terms.len(), 2);
        assert_eq!(q.terms[0].object, "podmioty");
        assert_eq!(q.terms[0].filters[0].key, "sektor");
        assert_eq!(q.terms[0].filters[1].op, '>');
        assert!(q.terms[1].negated);
        assert_eq!(q.terms[1].object, "interakcje");
    }

    #[test]
    fn parser_lapie_bledy() {
        assert!(parse("").is_err());
        assert!(parse("podmioty[sektor water]").is_err());
        assert!(parse("podmioty[sektor=water").is_err());
        assert!(parse("limit 10").is_err());
    }

    #[test]
    fn run_filtruje_podmioty_po_sektorze() {
        let o = Ontology::open_memory().unwrap();
        o.import_leads_json(
            r#"{"leads":[
              {"org":"ZWiK A","email":"a@a.pl","sector":"wodociagi","pop":500000,"source":"t"},
              {"org":"Gabinet B","email":"b@b.pl","sector":"szpital","pop":1000,"source":"t"}
            ]}"#,
        )
        .unwrap();
        let q = parse("podmioty[sektor=wodociagi] limit 10").unwrap();
        let rows = run(&o, &q).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("ZWiK A"));
    }

    #[test]
    fn run_negacja_wylacza_kontaktowanych() {
        let o = Ontology::open_memory().unwrap();
        o.import_leads_json(
            r#"{"leads":[
              {"org":"A","email":"a@a.pl","sector":"wodociagi","source":"t"},
              {"org":"B","email":"b@b.pl","sector":"wodociagi","source":"t"}
            ]}"#,
        )
        .unwrap();
        let _ = o.log_interakcja(&crate::ontology::NewInterakcja {
            typ: "email_sent".into(),
            kierunek: "out".into(),
            email: "a@a.pl".into(),
            temat: "x".into(),
            ts: 0,
            wynik: "-".into(),
            ref_id: "r".into(),
        });
        let q = parse("podmioty[sektor=wodociagi] !interakcje[email_sent] limit 50").unwrap();
        let rows = run(&o, &q).unwrap();
        assert_eq!(rows.len(), 1, "tylko B bez kontaktu");
        assert!(rows[0].contains("B"));
    }
}
