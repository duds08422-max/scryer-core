//! server — `scryer-core serve`: żywe API + konsola na ontologii.
//!
//! Wszystko na żywym SQLite: wyszukiwanie, filtry, profil podmiotu,
//! zapytania (query::parse/run), przetargi, statystyki, wektory ataku.
//! Bind domyślnie na 127.0.0.1 — wystawienie na świat to świadoma decyzja
//! operatora (SCRYER_HOST=0.0.0.0).

use crate::ontology::Ontology;
use crate::query;
use axum::{
    extract::{Path as AxPath, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// Ścieżka DB dla spawn_blocking (discovery otwiera własne połączenie).
static DB_PATH: OnceLock<PathBuf> = OnceLock::new();

pub struct AppState {
    /// rusqlite Connection nie jest Sync — trzymamy za Mutexem.
    pub onto: Mutex<Ontology>,
}

type S = Arc<AppState>;

/// Zgodny format błędu JSON zamiast panik w handlerach.
struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, AppError>;

fn err500<E: std::fmt::Display>(e: E) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn err400<E: std::fmt::Display>(e: E) -> AppError {
    AppError(StatusCode::BAD_REQUEST, e.to_string())
}

fn lock_onto(s: &S) -> MutexGuard<'_, Ontology> {
    // zatruty mutex (panik w środku sekcji) nie może położyć całej konsoli
    s.onto.lock().unwrap_or_else(|p| p.into_inner())
}

/// Token auth (opcjonalny): `SCRYER_TOKEN` z env.
fn auth_token() -> Option<String> {
    let t = std::env::var("SCRYER_TOKEN").unwrap_or_default();
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

/// Bearer-token middleware na /api/*.
async fn auth_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let expected = auth_token();
    if !request_authorized(&path, auth_header.as_deref(), expected.as_deref()) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("www-authenticate", "Bearer realm=\"scryer\"")
            .body(axum::body::Body::from(
                "{\"error\":\"missing/invalid bearer token\"}",
            ))
            .unwrap();
    }
    next.run(req).await
}

/// Czysta logika decyzji auth (testowalna bez spawnowania serwera).
/// `token = None` → auth wyłączona, wszystko przepuszczone.
/// Chronione są tylko ścieżki pod "/api/" (konsola i assety zostają publiczne).
fn request_authorized(path: &str, auth_header: Option<&str>, token: Option<&str>) -> bool {
    let Some(expected) = token else {
        return true;
    };
    if !path.starts_with("/api/") {
        return true;
    }
    let Some(provided) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) else {
        return false;
    };
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

/// Stałoczasowe porównanie bajtów (odporne na timing attacks przy równych
/// długościach; różnica długości i tak jest jawnie widoczna w nagłówku).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

pub async fn serve(db: PathBuf, host: &str, port: u16) -> Result<(), String> {
    let onto = Ontology::open(&db).map_err(|e| e.to_string())?;
    onto.register_sql_functions();
    let _ = DB_PATH.set(db.clone());
    let state = Arc::new(AppState {
        onto: Mutex::new(onto),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/assets/graph-engine.js", get(asset_engine_js))
        .route("/api/stats", get(api_stats))
        .route("/api/podmioty", get(api_podmioty))
        .route("/api/podmiot/:id", get(api_podmiot))
        .route("/api/query", post(api_query))
        .route("/api/tenders", get(api_tenders))
        .route("/api/graph", get(api_graph))
        .route("/api/discover", post(api_discover))
        .route("/api/ai", post(api_ai))
        .route("/api/attack-surface", get(api_attack_surface))
        .with_state(state)
        // Auth na /api/* (SCRYER_TOKEN); / i assets zostają publiczne,
        // by konsola mogła się załadować i poprosić o token.
        .layer(middleware::from_fn(auth_middleware));

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    println!("scryer-core serve: http://{addr}  (db: {})", db.display());
    println!(
        "  auth: {}",
        if auth_token().is_some() {
            "WŁĄCZONA (SCRYER_TOKEN) — /api/* wymaga Authorization: Bearer"
        } else {
            "WYŁĄCZONA — ustaw SCRYER_TOKEN, by chronić API (obowiązkowe przy SCRYER_HOST=0.0.0.0)"
        }
    );
    println!("  endpointy: /api/stats /api/podmioty /api/podmiot/:id /api/query /api/tenders /api/graph /api/ai /api/discover /api/attack-surface");
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}

async fn index() -> Html<&'static str> {
    Html(CONSOLE_HTML)
}

/// własny silnik grafu WebGL vendored w binarce — zero zależności (air-gap OK)
async fn asset_engine_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        ASSET_ENGINE_JS,
    )
}

// ---------------------------------------------------------------- stats ---

async fn api_stats(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();
    let cnt = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };

    let contacted: i64 = cnt("SELECT COUNT(DISTINCT podmiot_id) FROM interakcja
         WHERE typ='email_sent' AND podmiot_id IS NOT NULL");
    let nodmarc: i64 =
        cnt("SELECT COUNT(*) FROM domena WHERE mx=1 AND (dmarc IS NULL OR dmarc='')");
    let hot: i64 = cnt("SELECT COUNT(*) FROM podmiot WHERE tier_score >= 15");
    let warm: i64 = cnt("SELECT COUNT(*) FROM podmiot WHERE tier_score >= 8 AND tier_score < 15");

    // rozkład sektorów (do selecta filtrów w konsoli)
    let mut st = c
        .prepare("SELECT COALESCE(sektor,''), COUNT(*) FROM podmiot GROUP BY sektor ORDER BY COUNT(*) DESC")
        .map_err(err500)?;
    let sektors: Vec<Value> = st
        .query_map([], |r| {
            Ok(json!({ "sektor": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)? }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({
        "podmioty": cnt("SELECT COUNT(*) FROM podmiot"),
        "domeny": cnt("SELECT COUNT(*) FROM domena"),
        "osoby": cnt("SELECT COUNT(*) FROM osoba"),
        "przetargi": cnt("SELECT COUNT(*) FROM przetarg"),
        "interakcje": cnt("SELECT COUNT(*) FROM interakcja"),
        "skontaktowani": contacted,
        "bez_dmarc": nodmarc,
        "hot": hot,
        "warm": warm,
        "sektors": sektors,
    })))
}

// ------------------------------------------------------------- podmioty ---

#[derive(Deserialize)]
struct PodmiotyQ {
    #[serde(default)]
    q: String,
    #[serde(default)]
    sektor: String,
    #[serde(default)]
    kontakt: String, // all|yes|no
    #[serde(default)]
    sort: String, // score|pop|nazwa
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}
fn default_limit() -> i64 {
    100
}

async fn api_podmioty(State(s): State<S>, Query(q): Query<PodmiotyQ>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();

    let mut sql = String::from(
        "SELECT p.id, p.nazwa, p.nip, p.sektor, p.wojewodztwo, p.miasto, p.pop,
                p.tier_score,
                (SELECT COUNT(*) FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent') AS maile,
                (SELECT GROUP_CONCAT(d.nazwa) FROM domena d WHERE d.podmiot_id=p.id) AS domeny
         FROM podmiot p WHERE 1=1",
    );
    let mut vals: Vec<String> = Vec::new();
    let mut n = |v: &str| -> usize {
        vals.push(v.to_string());
        vals.len()
    };

    if !q.q.is_empty() {
        let needle = q.q.trim();
        sql.push_str(&format!(
            " AND (fold_search(p.nazwa, ?{n}) OR fold_search(p.miasto, ?{n}) OR fold_search(p.nip, ?{n})
                 OR p.id IN (SELECT podmiot_id FROM osoba WHERE fold_search(email, ?{n}))
                 OR p.id IN (SELECT podmiot_id FROM domena WHERE fold_search(nazwa, ?{n})))",
            n = n(needle)
        ));
    }
    if !q.sektor.is_empty() {
        sql.push_str(&format!(" AND p.sektor = ?{}", n(&q.sektor)));
    }
    if q.kontakt == "yes" {
        sql.push_str(" AND EXISTS (SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent')");
    } else if q.kontakt == "no" {
        sql.push_str(" AND NOT EXISTS (SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent')");
    }

    sql.push_str(match q.sort.as_str() {
        "pop" => " ORDER BY p.pop DESC, p.tier_score DESC",
        "nazwa" => " ORDER BY p.nazwa",
        "maile" => " ORDER BY maile DESC, p.tier_score DESC",
        _ => " ORDER BY p.tier_score DESC, p.pop DESC",
    });

    let total: i64 = {
        // szybki licznik bez LIMIT/OFFSET do paginacji
        let count_sql = format!("SELECT COUNT(*) FROM ({sql})");
        c.query_row(&count_sql, rusqlite::params_from_iter(vals.iter()), |r| {
            r.get(0)
        })
        .unwrap_or(0)
    };

    let limit = q.limit.clamp(1, 1000);
    let offset = q.offset.max(0);
    sql.push_str(&format!(" LIMIT {limit} OFFSET {offset}"));

    let mut stmt = c.prepare(&sql).map_err(err500)?;
    let pv: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(pv), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "nazwa": r.get::<_, String>(1)?,
                "nip": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "sektor": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                "wojewodztwo": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "miasto": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "pop": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                "tier_score": r.get::<_, Option<i64>>(7)?.unwrap_or(0),
                "maile": r.get::<_, i64>(8)?,
                "domeny": r.get::<_, Option<String>>(9)?.unwrap_or_default(),
            }))
        })
        .map_err(err500)?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!({
        "count": items.len(),
        "total": total,
        "offset": offset,
        "items": items,
    })))
}

// ------------------------------------------------------- profil podmiotu ---

async fn api_podmiot(State(s): State<S>, AxPath(id): AxPath<i64>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();

    let pod = c
        .query_row(
            "SELECT id, nazwa, nip, sektor, wojewodztwo, miasto, pop, ksc_status, tier_score, COALESCE(zrodla,'')
             FROM podmiot WHERE id=?1",
            rusqlite::params![id],
            |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "nazwa": r.get::<_, String>(1)?,
                    "nip": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    "sektor": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    "wojewodztwo": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    "miasto": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    "pop": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                    "ksc_status": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    "tier_score": r.get::<_, Option<i64>>(8)?.unwrap_or(0),
                    "zrodla": r.get::<_, String>(9)?,
                }))
            },
        )
        .map_err(|_| AppError(StatusCode::NOT_FOUND, format!("podmiot {id}: brak")))?;

    let doms: Vec<Value> = {
        let mut st = c
            .prepare("SELECT nazwa, mx, COALESCE(spf,''), COALESCE(dmarc,'') FROM domena WHERE podmiot_id=?1 ORDER BY nazwa")
            .map_err(err500)?;
        let rows = st
            .query_map(rusqlite::params![id], |r| {
                Ok(json!({
                    "nazwa": r.get::<_, String>(0)?,
                    "mx": r.get::<_, i64>(1)?,
                    "spf": r.get::<_, String>(2)?,
                    "dmarc": r.get::<_, String>(3)?,
                }))
            })
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    let osoby: Vec<Value> = {
        let mut st = c
            .prepare("SELECT email, COALESCE(rola,''), COALESCE(telefon,'') FROM osoba WHERE podmiot_id=?1 ORDER BY email")
            .map_err(err500)?;
        let rows = st
            .query_map(rusqlite::params![id], |r| {
                Ok(json!({
                    "email": r.get::<_, String>(0)?,
                    "rola": r.get::<_, String>(1)?,
                    "telefon": r.get::<_, String>(2)?,
                }))
            })
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    let inter: Vec<Value> = {
        let mut st = c
            .prepare(
                "SELECT typ, COALESCE(kierunek,'-'), COALESCE(email,''), COALESCE(temat,''), ts,
                        COALESCE(wynik,'-'), COALESCE(ref_id,'')
                 FROM interakcja WHERE podmiot_id=?1 ORDER BY ts DESC LIMIT 200",
            )
            .map_err(err500)?;
        let rows = st
            .query_map(rusqlite::params![id], |r| {
                Ok(json!({
                    "typ": r.get::<_, String>(0)?,
                    "kierunek": r.get::<_, String>(1)?,
                    "email": r.get::<_, String>(2)?,
                    "temat": r.get::<_, String>(3)?,
                    "ts": r.get::<_, i64>(4)?,
                    "wynik": r.get::<_, String>(5)?,
                    "ref": r.get::<_, String>(6)?,
                }))
            })
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    Ok(Json(
        json!({ "podmiot": pod, "domeny": doms, "osoby": osoby, "interakcje": inter }),
    ))
}

// ---------------------------------------------------------------- query ---

#[derive(Deserialize)]
struct QueryBody {
    q: String,
}

async fn api_query(State(s): State<S>, Json(body): Json<QueryBody>) -> ApiResult {
    let onto = lock_onto(&s);
    let parsed = query::parse(&body.q).map_err(err400)?;
    let rows = query::run(&onto, &parsed).map_err(err400)?;
    Ok(Json(json!({ "count": rows.len(), "rows": rows })))
}

// -------------------------------------------------------------- tenders ---

async fn api_tenders(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();
    let mut st = c
        .prepare(
            "SELECT tytul, COALESCE(org,''), COALESCE(url,''), COALESCE(deadline,''),
                    COALESCE(cpv,''), match_score, COALESCE(status,'nowy')
             FROM przetarg ORDER BY match_score DESC, deadline LIMIT 500",
        )
        .map_err(err500)?;
    let rows = st
        .query_map([], |r| {
            Ok(json!({
                "tytul": r.get::<_, String>(0)?,
                "org": r.get::<_, String>(1)?,
                "url": r.get::<_, String>(2)?,
                "deadline": r.get::<_, String>(3)?,
                "cpv": r.get::<_, String>(4)?,
                "match_score": r.get::<_, i64>(5)?,
                "status": r.get::<_, String>(6)?,
            }))
        })
        .map_err(err500)?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "count": items.len(), "items": items })))
}

// ---------------------------------------------------------------- graph ---

async fn api_graph(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();

    let pods: Vec<Value> = {
        let mut sp = c
            .prepare(
                "SELECT p.id, p.nazwa, COALESCE(p.sektor,''), COALESCE(p.miasto,''), p.pop, p.tier_score,
                        EXISTS(SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent')
                 FROM podmiot p",
            )
            .map_err(err500)?;
        let rows = sp
            .query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "nazwa": r.get::<_, String>(1)?,
                    "sektor": r.get::<_, String>(2)?,
                    "miasto": r.get::<_, String>(3)?,
                    "pop": r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    "score": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    "kontakt": r.get::<_, i64>(6)?,
                }))
            })
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    let doms: Vec<Value> = {
        let mut sd = c
            .prepare("SELECT id, nazwa, mx, COALESCE(dmarc,''), podmiot_id FROM domena")
            .map_err(err500)?;
        let rows = sd
            .query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "nazwa": r.get::<_, String>(1)?,
                    "mx": r.get::<_, i64>(2)?,
                    "dmarc": r.get::<_, String>(3)?,
                    "podmiot_id": r.get::<_, i64>(4)?,
                }))
            })
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    let osoby: Vec<Value> = {
        let mut so = c
            .prepare("SELECT id, email, podmiot_id FROM osoba")
            .map_err(err500)?;
        let rows = so
            .query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "email": r.get::<_, String>(1)?,
                    "podmiot_id": r.get::<_, i64>(2)?,
                }))
            })
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    // którzy kontenci dostali maila (do podświetlenia węzłów/osób)
    let emailed: Vec<String> = {
        let mut se = c
            .prepare("SELECT DISTINCT email FROM interakcja WHERE typ='email_sent' AND email IS NOT NULL")
            .map_err(err500)?;
        let rows = se
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    Ok(Json(
        json!({ "podmioty": pods, "domeny": doms, "osoby": osoby, "emailed": emailed }),
    ))
}

// ------------------------------------------------------------------- ai ---

#[derive(Deserialize)]
struct AiBody {
    q: String,
    /// execute=false → tylko plan ("rozumiem jako"), bez SQL/sieci
    #[serde(default)]
    dry: bool,
    /// wymuś tryb: "internet" (OSINT-first) — domyślnie hybryda
    #[serde(default)]
    mode: Option<String>,
}

async fn api_ai(State(s): State<S>, Json(body): Json<AiBody>) -> ApiResult {
    use crate::intel::{self, Target};

    let plan = intel::plan(&body.q);
    // "internet <frazа>" = jawne wymuszenie OSINT (jak przycisk net)
    let foldq = crate::ontology::fold_str(&body.q);
    let strip_prefix = foldq.starts_with("internet ");
    let search_phrase: &str = if strip_prefix {
        body.q["internet ".len()..].trim()
    } else {
        body.q.as_str()
    };
    let force_internet = body.mode.as_deref() == Some("internet") || strip_prefix;
    let is_external = plan.target == Target::External;
    // HYBRID: fraza bez predykatorów (albo wymuszona) → internet;
    // fraza z predykatorami → LOKAL + INTERNET równolegle
    let local_worth = !is_external && !plan.preds.is_empty();
    let internet_worth = !local_worth
        || plan
            .preds
            .iter()
            .any(|p| matches!(p, crate::intel::Pred::Text(_)));

    if !is_external && !local_worth && !force_internet && !internet_worth {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "nie rozumiem zapytania — spróbuj: 'wodociągi bez kontaktu', 'hot bez dmarc', 'recon <domena>', 'internet <firma>'".to_string(),
        ));
    }

    if body.dry {
        return Ok(Json(json!({
            "mode": if is_external { "external" } else if local_worth { "hybrid" } else { "internet" },
            "said": plan.said,
            "conf": plan.conf,
            "dry": true,
        })));
    }

    if is_external {
        // localization + recon poza async-ctx (sieć w spawn_blocking, osobny conn)
        let q = plan.external_q.clone().unwrap_or_default();
        let s2 = s.clone();
        let target_name = q.clone();
        let localized = tokio::task::spawn_blocking(move || {
            let onto = lock_onto(&s2);
            intel_localize(&onto, &target_name)
        })
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let rep = run_external_recon(&localized).await?;

        // persist na głównym conn + audyt
        {
            let onto = lock_onto(&s);
            persist_discovery(&onto, &rep);
            onto.log_audyt(
                "ai",
                "recon",
                &format!("{} → {}", body.q, rep["domain"].as_str().unwrap_or("-")),
            );
        }
        return Ok(Json(json!({
            "mode": "external",
            "said": plan.said,
            "conf": plan.conf,
            "q": q,
            "report": rep,
        })));
    }

    // ── HYBRID: lokal natychmiast, internet równolegle (spawn_blocking) ──
    let local_res = if local_worth {
        let out = {
            let onto = lock_onto(&s);
            intel::execute(&onto, &plan).map_err(err500)?
        };
        lock_onto(&s).log_audyt(
            "ai",
            "local",
            &format!("{} → {}", body.q, out["said"].as_str().unwrap_or("")),
        );
        Some(out)
    } else {
        None
    };

    let internet_res = if internet_worth || force_internet {
        let phrase = plan
            .external_q
            .clone()
            .unwrap_or_else(|| search_phrase.to_string());
        let db = DB_PATH
            .get()
            .cloned()
            .ok_or_else(|| AppError(StatusCode::INTERNAL_SERVER_ERROR, "brak ścieżki DB".into()))?;
        // OSINT w tle — osobne połączenie, nie trzymamy Mutexa podczas sieci
        let int_res = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
            let onto = crate::ontology::Ontology::open(&db).map_err(|e| e.to_string())?;
            onto.register_sql_functions();
            crate::intel::internet_search(&onto, &phrase)
        })
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(err500)?;
        lock_onto(&s).log_audyt(
            "ai",
            "internet",
            &format!(
                "{} → {} wyników",
                body.q,
                int_res["count"].as_i64().unwrap_or(0)
            ),
        );
        Some(int_res)
    } else {
        None
    };

    match (local_res, internet_res) {
        (Some(l), Some(i)) => Ok(Json(json!({
            "mode": "hybrid",
            "said": format!("{} · {}", l["said"].as_str().unwrap_or(""), i["said"].as_str().unwrap_or("")),
            "local": l,
            "internet": i,
            "count": l["count"].as_i64().unwrap_or(0) + i["count"].as_i64().unwrap_or(0),
        }))),
        (Some(l), None) => Ok(Json(l)),
        (None, Some(i)) => Ok(Json(i)),
        (None, None) => Err(AppError(
            StatusCode::BAD_REQUEST,
            "nie rozumiem zapytania — spróbuj: 'wodociągi bez kontaktu', 'internet <firma>', 'recon <domena>'".to_string(),
        )),
    }
}

/// Jeśli celem jest podmiot z bazy, użyj jego domeny zamiast zgadywania DDG.
fn intel_localize(onto: &crate::ontology::Ontology, target: &str) -> String {
    let c = onto.conn();
    let fold = crate::ontology::fold_str(target);
    // domena/e-mail → ustaw domenę wprost (jak discovery::normalize)
    if fold.contains('.') && !fold.contains(' ') {
        let dom = fold
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("www.")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        if dom.contains('.') {
            return dom;
        }
    }
    if fold.contains('@') {
        if let Some(dom) = fold.split('@').nth(1) {
            if !dom.is_empty() {
                return dom.to_string();
            }
        }
    }
    // fraza → podmiot z bazy? fold_search po nazwie, weź jego domenę
    let Ok(mut stmt) = c.prepare(
        "SELECT COALESCE((SELECT nazwa FROM domena WHERE podmiot_id = p.id AND nazwa LIKE '%.%' LIMIT 1), '') \
         FROM podmiot p WHERE fold_search(p.nazwa, ?1) LIMIT 1")
    else {
        return target.to_string();
    };
    match stmt.query_row([fold.as_str()], |r| r.get::<_, String>(0)) {
        Ok(dom) if !dom.is_empty() => dom,
        _ => target.to_string(),
    }
}

/// recon zewnętrzny (discovery pipeline) — spawn_blocking, osobne połączenie.
async fn run_external_recon(query: &str) -> Result<serde_json::Value, AppError> {
    use crate::discovery;
    let q = query.to_string();
    let db = DB_PATH
        .get()
        .cloned()
        .ok_or_else(|| AppError(StatusCode::INTERNAL_SERVER_ERROR, "brak ścieżki DB".into()))?;
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
        let onto = crate::ontology::Ontology::open(&db).map_err(|e| e.to_string())?;
        onto.register_sql_functions();
        let nq = discovery::normalize(&q);
        Ok(discovery::discover(&nq))
    })
    .await
    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(err500)
}

// ------------------------------------------------------- attack surface ---

async fn api_attack_surface(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let rows = onto.hot_bez_dmarc().map_err(err500)?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(nazwa, domena)| json!({ "nazwa": nazwa, "domena": domena }))
        .collect();
    Ok(Json(json!({ "count": items.len(), "items": items })))
}

// ------------------------------------------------------------- discover ---

#[derive(Deserialize)]
struct DiscoverBody {
    q: String,
}

async fn api_discover(State(s): State<S>, Json(body): Json<DiscoverBody>) -> ApiResult {
    use crate::discovery;

    let q = discovery::normalize(&body.q);
    if q.domain.is_empty() && q.phrase.is_empty() {
        return Err(AppError(StatusCode::BAD_REQUEST, "puste zapytanie".into()));
    }

    let db = DB_PATH
        .get()
        .cloned()
        .ok_or_else(|| AppError(StatusCode::INTERNAL_SERVER_ERROR, "brak ścieżki DB".into()))?;

    // sieciowe wołania poza async-ctx: osobne połączenie + spawn_blocking;
    // serwer ma Mutex na głównym conn — discovery pisze przez własny handle
    let res = tokio::task::spawn_blocking(move || {
        let onto = crate::ontology::Ontology::open(&db).map_err(|e| e.to_string())?;
        onto.register_sql_functions();
        let report = discovery::discover(&q);
        persist_discovery(&onto, &report);
        Ok::<_, String>(report)
    })
    .await
    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    lock_onto(&s).log_audyt(
        "console",
        "discover",
        &format!("{} → {}", body.q, res["domain"].as_str().unwrap_or("-")),
    );

    Ok(Json(res))
}

/// Zapis wyników discovery do ontologii (idempotentny).
fn persist_discovery(onto: &crate::ontology::Ontology, rep: &Value) {
    let dom = rep["domain"].as_str().unwrap_or("");
    if dom.is_empty() {
        return;
    }
    let dns = &rep["dns"];
    let has_mail = dns["has_mail"].as_bool().unwrap_or(false);
    let first = |k: &str| -> Option<&str> {
        dns[k]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
    };
    let spf = first("spf");
    let dmarc = first("dmarc");
    let pid = onto.podmiot_id_by_domena(dom);

    let dom_id = match pid {
        Some(p) => onto.upsert_domena(dom, has_mail, p).unwrap_or(0),
        None => onto.upsert_domena_free(dom, has_mail).unwrap_or(0),
    };
    let _ = dom_id;
    onto.set_domena_mail(dom, spf, dmarc);

    let www = &rep["www"];
    if www["ok"].as_bool().unwrap_or(false) {
        let title = www["title"].as_str().unwrap_or("");
        let url = www["url"].as_str().unwrap_or("");
        let desc = www["description"].as_str().unwrap_or("");
        let phones = www["phones"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|x| x.as_str());
        if let Some(p) = pid {
            onto.fill_podmiot_meta(
                p,
                None,
                Some(url),
                Some(if desc.is_empty() { title } else { desc }),
                phones,
            );
        }
        // osoby z www tylko gdy znamy ownera (FK na podmiot_id)
        if let Some(persons) = www["persons"].as_array() {
            if let Some(p) = pid {
                for em in persons.iter().filter_map(|x| x.as_str()) {
                    let _ = onto.upsert_osoba_email(em, "web", p);
                }
            }
        }
        if let Some(emails) = www["emails"].as_array() {
            if let Some(p) = pid {
                for em in emails.iter().filter_map(|x| x.as_str()) {
                    let _ = onto.upsert_osoba_email(em, "web", p);
                }
            }
        }
    }

    // subdomeny z crt.sh → domeny w grafie (bez MX-checku — to by długo trwało)
    if let Some(subs) = rep["subdomains"].as_array() {
        for sd in subs.iter().filter_map(|x| x.as_str()).take(30) {
            if sd != dom {
                let _ = match pid {
                    Some(p) => onto.upsert_domena(sd, false, p),
                    None => onto.upsert_domena_free(sd, false),
                };
            }
        }
    }

    onto.log_audyt("discovery", "recon", dom);
}

// -------------------------------------------------------------- konsola ---

const CONSOLE_HTML: &str = include_str!("console.html");

const ASSET_ENGINE_JS: &str = include_str!("graph-engine.js");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_off_allows_everything() {
        assert!(request_authorized("/api/stats", None, None));
        assert!(request_authorized("/api/stats", Some("Bearer zły"), None));
        assert!(request_authorized("/", None, None));
    }

    #[test]
    fn api_paths_require_bearer_when_token_set() {
        let tok = Some("sekret");
        assert!(!request_authorized("/api/stats", None, tok));
        assert!(!request_authorized("/api/stats", Some("Bearer zły"), tok));
        assert!(!request_authorized("/api/stats", Some("Basic sekret"), tok));
        assert!(request_authorized("/api/stats", Some("Bearer sekret"), tok));
    }

    #[test]
    fn console_and_assets_stay_public() {
        let tok = Some("sekret");
        assert!(request_authorized("/", None, tok));
        assert!(request_authorized("/assets/graph-engine.js", None, tok));
    }

    #[test]
    fn prefix_lookalike_paths_are_protected() {
        // "/api" bez ukośnika to nie endpoint API — ale też nie konsola;
        // middleware chroni wyłącznie "/api/*", co testujemy wprost.
        let tok = Some("sekret");
        assert!(!request_authorized("/api/query", None, tok));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
