# SCRYER ONTOLOGY — projekt warstwy decyzyjnej KSC
**Wersja:** 0.1 (design) · 29.09.2026 · Hartwell Labs
**Wzorzec:** Palantir Ontology (Gotham/Foundry) — dostosowany do polskiego rynku KSC/NIS2 i skali 1-osobowej + AI.
**Zasada nadrzędna:** own your stack — deterministyczny rdzeń, audytowalny, bez chmury, podpisywane manifesty.

---

## 1. Czym jest Palantir i co kopiujemy (a czego nie)

Palantir to **nie** baza danych i **nie** BI. To warstwa operacyjna:

| Element Palantira | Co robi | Odpowiednik w Scryerze |
|---|---|---|
| **Objects + Links** (semantyka) | dane z wielu źródeł mapują na byty rzeczywiste i relacje: `Osoba—pracuje_w→Firma—wygrała→Kontrakt` | `Podmiot`, `Osoba`, `Domena`, `Przetarg`, `Interakcja` + te same relacje |
| **Actions** (kinetyka) | zapisywanie/decyzje z governance i pełnym audytem: "zleć inspekcję", "zablokuj konto" | `send_email` (już jest), `mark_suppressed`, `create_lead_from_tender`, `schedule_pilot` |
| **Dynamic security** | kto widzi co | kwestia później (1 user + role agenta) |
| **Foundry pipelines** | ETL z dowolnych źródeł do obiektów | harvester ZOZ/TERYT + BZP fetcher (cz. gotowa) |
| **AIP** | LLM operujący na ontologii | nasz agentic workflow (Freebuff) NA OTWARTEJ ontologii |

**Nie kopiujemy:** platformy (klikaczka, wdrożenie za miliony), black-boxu, chmury. Nasz brzuch: **jeden plik SQLite = cała ontologia, CSV/JSONL in/out, wszystko z sha256 manifestami.** Sprzedajemy to, czego Palantir nie zrobi: za darmo dla MAPE (mikro i małe) / self-hosted / air-gap — dokładnie tam gdzie KSC boli.

## 2. Obiekty (semantic layer) — schemat v1

```
Podmiot   {id, nazwa, nip, regon, sektor(health/water/energy/admin/...),
           wojewodztwo, miasto, pop, ksc_status(nieznany/wpisany/wisso),
           tier_score, źródła[rpwdl2, TERYT, BZP, ręczne]}
Domena    {id, nazwa, mx, spf, dmarc, nxdomain, findings[], audyt_ts}
Osoba     {id, imie_nazwisko?, rola(sekretariat/IT/CISO/prezes), email,
           telefon?, zweryfikowany(kanał)}
Przetarg  {id, tytul, zamawiajcy→Podmiot, cpv, deadline, url,
           match_score, match_reasons[], status(nowy/odpowiedziano/oferta)}
Interakcja{id, typ(email_sent/email_recv/call/odpowiedz), ts, kierunek,
           osoba→Osoba, podmiot→Podmiot, temat, treść_ref(outbox.jsonl),
           wynik(odpowiedziano/brak/optout/pilot)}
Notatka   {id, treść, podmiot→Podmiot, ts}          (wolna pola na rozmowy)
```

**Relacje (links):**
- `Domena —należy_do→ Podmiot` (1..n: podmiot może mieć kilka domen)
- `Osoba —reprezentuje→ Podmiot`
- `Przetarg —dotyczy→ Podmiot` (organizator)
- `Interakcja —dotyczy→ Podmiot` + `—z→ Osoba`
- Pochodzenie: każdy obiekt niesie `źródła[]` (który harvester/wiersz) — audit trail od śmietnika do maila.

## 3. Warstwa akcji (kinetics) — każdy zapis = wiersz audytu

| Akcja | Gate'y (obowiązkowe) | Audyt |
|---|---|---|
| `send_campaign_email` | suppression list, MX-check, limit dzienny, SCRYER_CONFIRM | JSONL + Interakcja w ontologii |
| `mark_suppressed` | powód wymagany | JSONL |
| `create_lead_from_tender` | match_score >= 8, brak duplikatu | manifest |
| `log_interaction` | — | JSONL |
| `generate_brief` | — | plik + sha256 |

Różnica vs dziś: akcje zapisują się **do grafu**, nie tylko do logów — więc "kto dostał maila" to zapytanie, nie grep.

## 4. Zapytania decyzyjne (cel v1)

Przykłady, które muszą działać z wiersza poleceń:

```
# HOT leady z brakiem DMARC i aktywnym przetargiem IT:
scryer-core ask "podmioty[tier=HOT] -domeny[dmarc=brak] -przetargi[cpv=72*,status=nowy]"

# Wszystkie interakcje z ZWiK Szczecin (timeline):
scryer-core ask "interakcje[org~'zwik.szczecin']"

#_podmioty wod-kan z pop>100k, do których nie pisaliśmy 30 dni:
scryer-core ask "podmioty[sektor=water,pop>100000] !interakcje[email_sent,since=30d]"
```

Implementacja: mały parser (parser combinator własny albo klek z `nom`-like bez zależności) → zapytanie SQL po SQLite. Rdzeń asystenta: te same zapytania zdaje się LLM-owi w dwóch formach (intencja → zapytanie deterministyczne → wynik). **LLM nie zapisuje nigdy bezpośrednio — tylko przez akcje.**

## 5. Migracja z obecnego stanu (bez wielkiego bang)

| Krok | Co | Status |
|---|---|---|
| v0.4 | `store_v2`: SQLite (podmioty/domeny/osoby/przetargi/interakcje) + import z istniejących JSONL/seedów; scoring bez zmian | do zrobienia |
| v0.5 | akcje zapisują Interakcje do grafu; suppression czytana z grafu | do zrobienia |
| v0.6 | BZP fetcher (przetargi.gov.pl/BZP API) → Przetargi + `create_lead_from_tender` | moduł scoringu GOTOWY (bzp.rs) |
| v0.7 | `ask` — parser zapytań + raporty decyzyjne | do zrobienia |
| v1.0 | manifesty per-export, tryb air-gap (sync przez plik), dokument "Ontology jako karta produktu" | wizja |

## 6. Dlaczego to wygrywa (teza)

Palantir sprzedaje **decyzje, nie dane**. My na rynku KSC mamy dane, których nikt inny nie spina: rejestr ZOZ + TERYT + BZP + pasywny DNS-audit + własna historia mailowa. Ontologia zmienia to z "lista mailowa" w **system decyzyjny**: który podmiot, dlaczego teraz, jakim kanałem, z jakim wynikiem — z pełnym audytem (KSC to rynek, który kupi od firmy, która sama trzyma dyscyplinę). I to jest dokładnie story dla Grantów (NLnet/OpenSats): *deterministic, auditable, air-gapped intelligence layer for critical-infrastructure outreach and risk assessment*.

## 7. Otwarte pytania
1. SQLite vs czysty JSONL-per-obiekt (SQLite: query, JSONL: zero zależności). Rekomendacja: SQLite, bo zapytania v0.7.
2. Czy Przetarg dostaje relację do Osoby (osoba kontaktowa przetargu)? Tak, opcjonalnie.
3. dedupe podmiotów między źródłami (NIP = klucz główny, fallback nazwa+miasto).
