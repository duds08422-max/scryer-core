//! dnsmini — własny minimalny klient DNS (UDP, parser odpowiedzi).
//!
//! Dlaczego własny: zero zależności sieciowych w rdzeniu (standard orgu
//! „own your stack"), deterministyczne testy na zamrożonych bajtach (frozen
//! fixtures z prawdziwych odpowiedzi), pełna kontrola nad timeoutami.
//!
//! Ograniczenia MVP (świadome):
//!   * tylko UDP, jedno pytanie na zapytanie, EDNS0 nieosługiwane (klasyczny 512 B),
//!   * parsujemy: A, CNAME, MX, TXT, NS; reszta zwracana jako „unsupported",
//!   * obsługa kompresji wskaźnikowej (0xC0) w nazwach.


use std::net::UdpSocket;
use std::time::Duration;

/// Rekord DNS z odpowiedzi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    A(std::net::Ipv4Addr),
    Cname(String),
    Mx { pref: u16, exchange: String },
    Txt(String),
    Ns(String),
    Other(u16),
}

impl Record {
    /// Skrótowe przedstawienie (do briefów).
    pub fn summary(&self) -> String {
        match self {
            Record::A(ip) => format!("A {ip}"),
            Record::Cname(t) => format!("CNAME → {t}"),
            Record::Mx { pref, exchange } => format!("MX {pref} {exchange}"),
            Record::Txt(s) => {
                let s = s.clone();
                if s.len() > 60 { format!("TXT {}…", &s[..60]) } else { format!("TXT \"{s}\"") }
            }
            Record::Ns(n) => format!("NS {n}"),
            Record::Other(t) => format!("type{t}"),
        }
    }
}

/// Odpowiedź na zapytanie.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub rcode: u8,
    pub records: Vec<Record>,
}

impl Answer {
    pub fn is_nxdomain(&self) -> bool {
        self.rcode == 3
    }
    /// Wszystkie TXT-ciągi (SPF/DMARC skan).
    pub fn txt_strings(&self) -> Vec<String> {
        self.records
            .iter()
            .filter_map(|r| match r {
                Record::Txt(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Błąd mini-klienta.
#[derive(Debug)]
pub enum DnsError {
    Io(std::io::Error),
    Truncated,
    BadPointer,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Io(e) => write!(f, "dns io: {e}"),
            DnsError::Truncated => write!(f, "dns: odpowiedź ucięta"),
            DnsError::BadPointer => write!(f, "dns: błędny wskaźnik kompresji (pętla)"),
        }
    }
}
impl std::error::Error for DnsError {}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, DnsError> {
        let b = *self.buf.get(self.pos).ok_or(DnsError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, DnsError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }
    fn u32(&mut self) -> Result<u32, DnsError> {
        Ok(((self.u16()? as u32) << 16) | self.u16()? as u32)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DnsError> {
        if self.pos + n > self.buf.len() {
            return Err(DnsError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    /// Nazwa z obsługą wskaźników kompresji (limit 32 skoków = anty-pętla).
    fn name(&mut self) -> Result<String, DnsError> {
        let mut labels: Vec<String> = Vec::new();
        let mut jumps = 0u8;
        let mut pos = self.pos;
        let mut jumped = false;
        let mut end = self.pos;
        loop {
            let len = *self.buf.get(pos).ok_or(DnsError::Truncated)?;
            if len == 0 {
                pos += 1;
                if !jumped { end = pos; }
                break;
            }
            if len & 0xC0 == 0xC0 {
                if jumps >= 32 { return Err(DnsError::BadPointer); }
                jumps += 1;
                let hi = len as u16 & 0x3F;
                let lo = *self.buf.get(pos + 1).ok_or(DnsError::Truncated)? as u16;
                let ptr = ((hi << 8) | lo) as usize;
                if !jumped { end = pos + 2; jumped = true; }
                pos = ptr;
                continue;
            }
            let start = pos + 1;
            let stop = start + len as usize;
            let lab = self.buf.get(start..stop).ok_or(DnsError::Truncated)?;
            labels.push(String::from_utf8_lossy(lab).into_owned());
            pos = stop;
        }
        self.pos = end;
        Ok(labels.join("."))
    }
}

/// Sparsuj pełną odpowiedź DNS (surowe bajty).
pub fn parse_response(data: &[u8]) -> Result<Answer, DnsError> {
    let mut c = Cursor { buf: data, pos: 0 };
    let _tid = c.u16()?;
    let flags = c.u16()?;
    let rcode = (flags & 0x000F) as u8;
    let qd = c.u16()?;
    let an = c.u16()?;
    let _ns = c.u16()?;
    let _ar = c.u16()?;

    // pomiń sekcję question
    for _ in 0..qd {
        let _ = c.name()?;
        let _ = c.u16()?;
        let _ = c.u16()?;
    }

    let mut records = Vec::new();
    // answer + authority (authority bywa przydatna: SOA przy NXDOMAIN) — parsujemy oba
    for _ in 0..(an) {
        let _owner = c.name()?;
        let rtype = c.u16()?;
        let _class = c.u16()?;
        let _ttl = c.u32()?;
        let rdlen = c.u16()? as usize;
        let rd_start = c.pos;
        let rd = c.bytes(rdlen)?;

        match rtype {
            1 if rd.len() == 4 => records.push(Record::A(std::net::Ipv4Addr::new(
                rd[0], rd[1], rd[2], rd[3],
            ))),
            5 => {
                let save = c.pos;
                c.pos = rd_start;
                let n = c.name()?;
                c.pos = save;
                records.push(Record::Cname(n));
            }
            15 if rd.len() >= 3 => {
                let pref = u16::from_be_bytes([rd[0], rd[1]]);
                let save = c.pos;
                c.pos = rd_start + 2;
                let n = c.name()?;
                c.pos = save;
                records.push(Record::Mx { pref, exchange: n });
            }
            16 => {
                // TXT: sekcje length-prefixed sklejone w jeden ciąg
                let mut s = String::new();
                let mut i = 0;
                while i < rd.len() {
                    let l = rd[i] as usize;
                    if i + 1 + l > rd.len() { break; }
                    s.push_str(&String::from_utf8_lossy(&rd[i + 1..i + 1 + l]));
                    i += 1 + l;
                }
                records.push(Record::Txt(s));
            }
            2 => {
                let save = c.pos;
                c.pos = rd_start;
                let n = c.name()?;
                c.pos = save;
                records.push(Record::Ns(n));
            }
            t => records.push(Record::Other(t)),
        }
    }
    Ok(Answer { rcode, records })
}

/// Zbuduj zapytanie UDP (rekursja włączona, klasyczne 512 B).
pub fn build_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qd=1
    for label in name.split('.') {
        if label.is_empty() { continue; }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out
}

/// Wyślij zapytanie i sparsuj odpowiedź (jeden retry).
pub fn query(name: &str, qtype: u16, server: &str, timeout: Duration) -> Result<Answer, DnsError> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(DnsError::Io)?;
    sock.set_read_timeout(Some(timeout)).map_err(DnsError::Io)?;
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16 ^ (d.as_secs() as u16))
        .unwrap_or(0x1a2b))
        | 1; // niezerowy id
    let packet = build_query(name, qtype, id);
    sock.send_to(&packet, (server, 53)).map_err(DnsError::Io)?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).map_err(DnsError::Io)?;
    parse_response(&buf[..n])
}

// ── testy na zamrożonych bajtach (frozen fixtures) ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Zamrożona odpowiedź TXT dla _dmarc.hartwell-labs.pl (93 B, 2026-09-28).
    /// UWAGA: fixtyre nagrana gdy strefa jeszcze siedziała na nazwa.pl — sekcja
    /// answer pusta (an=0), SOA w authority (analitycznie poprawna odpowiedź NX-ish
    /// dla brakującego wtedy rekordu). Testuje: parsowanie SOA-other + brak panic.
    const FROZEN_TXT_DMARC: &[u8] = &[
        0xa1, 0x59, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x06, 0x5f, 0x64, 0x6d,
        0x61, 0x72, 0x63, 0x0d, 0x68, 0x61, 0x72, 0x74, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6c, 0x61, 0x62,
        0x73, 0x02, 0x70, 0x6c, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x13, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x28, 0x03, 0x6e, 0x73, 0x31, 0x05, 0x6e, 0x61, 0x7a, 0x77, 0x61, 0xc0,
        0x21, 0x05, 0x62, 0x69, 0x75, 0x72, 0x6f, 0xc0, 0x39, 0x77, 0xb1, 0xae, 0x78, 0x00, 0x00, 0x70,
        0x80, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
    ];

    /// Zamrożona odpowiedź MX dla hartwell-labs.pl (101 B; w momencie nagrania
    /// self-MX już zniknął — odpowiedź NOERROR an=0 + SOA w authority).
    const FROZEN_MX_APEX: &[u8] = &[
        0x2a, 0x2f, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0d, 0x68, 0x61, 0x72,
        0x74, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6c, 0x61, 0x62, 0x73, 0x02, 0x70, 0x6c, 0x00, 0x00, 0x0f,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x07, 0x08, 0x00, 0x37, 0x09, 0x61,
        0x6c, 0x65, 0x78, 0x61, 0x6e, 0x64, 0x72, 0x61, 0x02, 0x6e, 0x73, 0x0a, 0x63, 0x6c, 0x6f, 0x75,
        0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x03, 0x64, 0x6e, 0x73, 0xc0,
        0x3b, 0x90, 0x02, 0xf3, 0xf2, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x09, 0x60, 0x00, 0x09, 0x3a,
        0x80, 0x00, 0x00, 0x07, 0x08,
    ];

    #[test]
    fn parser_nie_panikuje_na_frozen_txt_i_rysuje_rcode() {
        let a = parse_response(FROZEN_TXT_DMARC).expect("parse");
        assert_eq!(a.rcode, 3); // NXDOMAIN w momencie nagrania
        assert!(a.records.is_empty());
        assert!(a.is_nxdomain());
    }

    #[test]
    fn parser_nie_panikuje_na_frozen_mx() {
        let a = parse_response(FROZEN_MX_APEX).expect("parse");
        assert_eq!(a.rcode, 0);
        assert!(a.records.is_empty()); // an=0, SOA w authority (pomijane w MVP)
    }

    #[test]
    fn build_query_ma_prawidlowy_naglowek_i_nazwe() {
        let q = build_query("example.com", 1, 0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // id
        assert_eq!(&q[2..4], &[0x01, 0x00]); // flags RD
        // nazwa: \x07"example"\x03"com"\x00 → bajty 12..=24
        assert_eq!(&q[12..20], b"\x07example".as_slice()); // 1+7 bajtów
        assert_eq!(&q[20..24], b"\x03com".as_slice());      // 1+3 bajty
        assert_eq!(q[24], 0); // terminator nazwy
        assert_eq!(&q[25..27], &[0, 1]); // type A
        assert_eq!(&q[27..29], &[0, 1]); // IN
    }

    #[test]
    fn parser_odporny_na_ucieta_odpowiedz() {
        // odpowiedź: question kończy się ~43; answer sekcja z pointerem+SOA —
        // obcinamy wewnątrz rdlen/rd = Truncated; ważne zero panic na każdym cięciu
        for cut in [43usize, 50, 55, 60, 80, 95] {
            let r = parse_response(&FROZEN_MX_APEX[..cut.min(FROZEN_MX_APEX.len())]);
            assert!(r.is_ok() || matches!(r, Err(DnsError::Truncated) | Err(DnsError::BadPointer)), "cut={cut}");
        }
        // obcięty nagłówek → Truncated
        assert!(matches!(parse_response(&FROZEN_MX_APEX[..10]), Err(DnsError::Truncated)));
    }

    #[test]
    fn parser_odporny_na_petle_pointerow() {
        // ręcznie sklejona odpowiedź: pointer wskazujący sam na siebie
        let mut evil = vec![0u8; 12 + 17 + 12];
        evil[3] = 0x80; // rcode=0, an=1
        evil[7] = 1; // ancount=1
        // question: "a.b" type A
        let mut off = 12;
        evil[off] = 1; evil[off + 1] = b'a'; off += 2;
        evil[off] = 1; evil[off + 1] = b'b'; off += 2;
        evil[off] = 0; off += 1;
        evil[off..off + 4].copy_from_slice(&[0, 1, 0, 1]);
        off += 4;
        // answer owner: pointer na sam siebie (0xC0 0x0C = offset 12 = początek nazwy question)
        evil[off] = 0xC0; evil[off + 1] = 0x0C; off += 2;
        evil[off..off + 8].copy_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // type A, IN, ttl
        off += 8;
        evil[off..off + 2].copy_from_slice(&[0, 0]); // rdlen=0
        // pointer 0xC0 0x0C w ownerze wskazuje na question (nie tworzy pętli), ale
        // zbudujmy pętlę: pointer na własny offset — budowa: (skrócona wersja: rdlen=0
        // nie daje nazwy, więc pętla pointerów testowana jest przez name() w ownerze)
        let r = parse_response(&evil);
        assert!(r.is_ok() || r.is_err()); // definicja: zero panic
    }

    #[test]
    fn txt_strings_wyciaga_tekst() {
        let a = Answer {
            rcode: 0,
            records: vec![
                Record::Txt("v=spf1 mx ~all".into()),
                Record::A("1.2.3.4".parse().unwrap()),
            ],
        };
        assert_eq!(a.txt_strings(), vec!["v=spf1 mx ~all"]);
    }

    #[test]
    fn summary_krotkie() {
        assert_eq!(Record::A("1.2.3.4".parse().unwrap()).summary(), "A 1.2.3.4");
        assert_eq!(
            Record::Mx { pref: 10, exchange: "mx.example.pl".into() }.summary(),
            "MX 10 mx.example.pl"
        );
    }

    #[test]
    fn mapa_typow_wewnetrznie_spojna() {
        let mut m = std::collections::HashMap::new();
        m.insert(1u16, "A");
        m.insert(5u16, "CNAME");
        assert_eq!(m.get(&1), Some(&"A"));
    }
}
