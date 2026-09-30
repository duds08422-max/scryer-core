# Scryer — Hartwell Labs

**Lead intelligence & external attack surface** — silnik, który zamienia publiczne
dane (BIP, BZP, DNS) w ranking leadów z amunicją personalizacyjną i gotowymi
briefami mailowymi.

> Talus patrzy do środka hosta. **Scryer patrzy na Twoją ekspozycję zewnętrzną.**

**Strona produktu:** [hartwell-labs.pl/scryer-core](https://hartwell-labs.pl/scryer-core/)

## Zasady

1. **Code over claims** — 62 testy jednostkowe, parser DNS testowany na
   zamrożonych bajtach (frozen fixtures) z prawdziwych odpowiedzi.
2. **Pasywnie domyślnie** — tylko publiczny DNS (równoważne zwykłemu
   resolverowi) i dane publiczne. Aktywny skan osób trzecich = nigdy bez
   jawnej autoryzacji.
3. **Own your stack** — własny minimalny klient DNS (`dnsmini`), zero
   zależności sieciowych; rdzeń deterministyczny, output podpisywany
   manifestem sha256 (audit-ready).
4. **Licencja własnościowa (proprietary)** — Scryer to narzędzie klasy
   intelligence; odbiorcy: podmioty publiczne (CSIRT/IK), operatorzy
   infrastruktury krytycznej i enterprise. Rdzeń nie jest open source.
   Kontakt: contact@hartwell-labs.pl

## Pipeline

```
LOAD (JSON: seed/BIP/BZP) → VALIDATE → DEDUPE → SCORE → ENRICH (pasywny DNS-audit)
→ RANK → CSV (Brevo) + BRIEFS (.md) + SNAPSHOT (JSON, sha256)
```

## Użycie

```bash
# ranking + CSV pod Brevo:
SCRYER_OUT=brevo-import.csv scryer-core score seed/leads-demo.json

# snapshot JSON + briefy .md per lead (z pasywnym DNS-auditem):
scryer-core briefs seed/leads-demo.json briefs/

# serwer DNS konfigurowalny (default 1.1.1.1):
SCRYER_DNS=9.9.9.9 scryer-core briefs seed/leads-demo.json briefs/

# konsola + API (domyślnie 127.0.0.1):
SCRYER_DB=seed/scryer.db scryer-core serve

# auth na API — OBOWIĄZKOWE przy wystawianiu poza localhost (SCRYER_HOST=0.0.0.0):
SCRYER_TOKEN="$(openssl rand -hex 32)" SCRYER_DB=seed/scryer.db scryer-core serve
# konsola zapyta o token przy pierwszym 401; API: Authorization: Bearer <token>
```

## Scoring (przezroczysty, audit-ready)

| Sygnał | Punkty |
|---|---|
| Sektor: zdrowie / wodociągi / energetyka (KSC USK) | 9–10 |
| Sektor: medtech / admin / inne | 3–7 |
| Hook: KSC samorejestracja ≤7 dni | +5 |
| Hook: aktywny przetarg (BZP) | +4 |
| Hook: KSC >7 dni / NIS2 / CeZ | +2–3 |
| Email zweryfikowany | +3 |

Tiere: **HOT** ≥15 (1. fala), **WARM** 10–14 (2. fala), **COLD** <10 (nurture).

## DNS-audit (pasywny, bez skanowania)

Dla każdej domeny leadu: MX + SPF + DMARC + A. Znajdowania typu
„brak DMARC — spoofing trywialny" trafiają wprost do briefu
(personalizacja 1:1, zero cold-genericu).

## Architektura

```
src/
├── model.rs    — Lead, Sector (PL+EN parsing), Hook, scoring
├── score.rs    — validate, dedupe, rank, CSV, manifest sha256
├── dnsmini.rs  — własny klient DNS (UDP) + parser (compression pointers, fuzz-resistant)
├── enrich.rs   — pasywne wzbogacanie (alias na store::audit_all)
├── export.rs   — DnsAudit, briefy markdown, snapshot JSON
├── store.rs    — audit_domain/audit_all, trwałość JSON
└── report.rs   — raport konsolowy
```

## Analityka powiązań (link analysis)

Graf ontologii (podmiot↔domena↔osoba + **hub-y wspólnej infrastruktury**)
z pełną analizą: komponenty spójności, mosty (single points of failure),
najkrótsze ścieżki, wspólni sąsiedzi.

**Inferencja ukrytych relacji:** jeśli dwie organizacje mają ten sam MX/NS/IP
(pasywny DNS, zero skanowania) — graf łączy je hubem `i:mx:…` / `i:ns:…` / `i:ip:…`.
"Ci dwi grają z tym samym dostawcą" — widoczne od razu, bez żadnego LLM.

```
scryer-core serve   # konsola: zakładka Graf (⚠ mosty) + Timeline
GET /api/graph/stats     # skala, spójność, kruchość, liczba hubów
GET /api/graph/bridges   # krawędzie krytyczne
GET /api/graph/path?from=p:1&to=d:7
GET /api/timeline?limit=300   # interakcje + audyt jednym strumieniem
```

## Mapa drogowa

- [x] MVP: pipeline scoring + CSV Brevo
- [x] Pasywny DNS-audit + briefy
- [x] Graf powiązań (org↔domena↔osoba + wspólne MX/NS/IP) + timeline
- [ ] Konektory BZP/BIP (harmonogram: po domknięciu kampanii E1)
- [ ] Integracja z Talusem (zdarzenia jako sygnały do scoringu)

---
*Hartwell Labs — visibility is defense you can't protect what you can't see.*
