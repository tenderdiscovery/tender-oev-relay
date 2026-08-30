"""
fetch_oeffentlichevergabe.py

Detects genuinely new DriveLock/idgard-relevant German public tenders on
oeffentlichevergabe.de (the Bund's zentraler "Bekanntmachungsservice"/
Datenservice Öffentlicher Einkauf), dedupes against the existing master
dataset, and shapes new records into the same schema used for the other five
sources (ted_shaped_final.json), tagged with "source": "oeffentlichevergabe.de".

Integration shape (verified live, see diligence notes below):
    GET https://oeffentlichevergabe.de/api/notice-exports
        ?pubDay=YYYY-MM-DD&format=csv.zip
This is an OFFICIAL Open-Data-Schnittstelle (documented via Swagger,
OAS 3.1, CC0-lizenziert), not a scrape - explicitly built for bulk re-use.
No auth required. `pubDay` and `pubMonth` are mutually exclusive; `pubDay`
must be strictly in the past (today/future -> 400) since a day's notices
only become retrievable after midnight the following day. Data is available
from 2022-12 onward.

Unlike the other five sources, this endpoint has NO server-side keyword or
free-text search: it returns EVERY notice published nationwide on the
requested day (557 notices / ~326 KB on a sampled weekday), bundled as a ZIP
of ~19 CSV tables (RFC 4180, stable column names/order per the API docs).
KEYWORDS are matched client-side against `purpose.csv` (title/description),
the same "pull everything, filter locally" approach already used for
bayvebe.bayern.de - see that module's docstring for the precedent.

Known quirks/limitations (live-verified against a real day's export, not
inferred from the docs alone):
- Two DIFFERENT noticeIdentifier formats appear in the SAME notice.csv,
  depending on origin: plain integers (~60% of rows in the sampled day,
  e.g. "25763844") for notices that also flow through the EU-wide TED
  pipeline, and UUIDs (~40%, e.g. "806ae8bc-089a-4671-9b32-c8800f6dfa7b")
  for purely national eForms-DE submissions. Both are used as-is as the join
  key across this day's CSV tables (stable within one export), but this
  means a meaningful share of matches here will be notices ALSO already
  present in ted_shaped_final.json via fetch_new_notices.py (TED) - see
  looks_like_cross_source_duplicate() below, same heuristic as the other
  secondary-source fetchers.
- NO bid-submission-deadline field exists anywhere in the CSV table set
  (checked every column across all 19 tables: submissionTerms.csv only has
  tenderValidityDeadline/publicOpeningDate, neither of which is the
  submission deadline shown elsewhere as "Frist"). `deadline` is therefore
  always None for this source - a genuine data-source limitation, not a
  parsing bug. Deadlines ARE present in the OCDS export format instead
  (tender.tenderPeriod.endDate), which would require switching this fetcher
  from CSV to OCDS/JSON parsing - a larger follow-up, not done here.
- originalUrl is BEST-EFFORT and UNVERIFIED for numeric-ID notices: the only
  confirmed detail-page URL pattern seen (via a public search result) uses a
  UUID (`/ui/de/search/details?noticeId=<uuid>&lotId=<lotId>`). It is
  assumed the same pattern also works for numeric IDs since both are valid
  values of the same `noticeIdentifier` column, but this has NOT been
  click-verified for the numeric case - same category of caveat as
  fetch_bayvebe.py's AJAX-modal link.
- CPV codes (classification.csv) and buyer/PLZ (organisation.csv,
  placeOfPerformance.csv) ARE reliably present and used to populate
  cpvCodes / performanceLocation, unlike the Berlin/Saarland fetchers.
- Expected scarcity, same as the other secondary sources: a single sampled
  day (557 notices nationwide) produced 4 substring hits against the
  DriveLock/idgard KEYWORDS list before de-duplication - most days are
  expected to yield 0-1 genuinely new (non-duplicate) records.

Usage:
    python3 fetch_oeffentlichevergabe.py [--days N] [--out new_notices_found_oeffentlichevergabe.json]
"""
import argparse
import csv
import io
import json
import re
import time
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timedelta, timezone

EXPORT_URL_TMPL = "https://oeffentlichevergabe.de/api/notice-exports?pubDay={day}&format=csv.zip"
DETAIL_URL_TMPL = "https://oeffentlichevergabe.de/ui/de/search/details?noticeId={notice_id}"

# Same list as fetch_bayvebe.py - kept as a per-module copy (existing
# convention in this codebase: each fetcher owns its own KEYWORDS constant
# rather than importing a shared one) so a future edit to one source's list
# can't silently change another's matching behavior.
KEYWORDS = [
    "DriveLock",
    "idgard",
    "BitLocker",
    "Sealed Cloud",
    "HYPERSECURE",
    "Endpoint Security",
    "Datenraum",
    "Wechseldatenträger",
    "Festplattenverschlüsselung",
    "IGEL",
    "Managed File Transfer",
    "ESET Endpoint",
    "SIEM/SOC",
    # Added 2026-08-30: DriveLock/idgard/Compliance-Signale keyword-profile
    # expansion, clean bucket (safe as bare substring/word-boundary matches,
    # live-tested against TED's fuzzy FT~ operator with 0 hits or genuinely
    # on-topic single-digit hits - this source's client-side matching is
    # stricter (word-boundary regex against full title+description), so if a
    # term is safe on TED it is at least as safe here).
    "Application Control",
    "BitLocker Management",
    "USB Control",
    "USB-Kontrolle",
    "Schnittstellenkontrolle",
    "Port Control",
    "Application Allowlisting",
    "Endpoint Protection",
    "Endpoint Encryption",
    "Vulnerability Management",
    "Security Awareness",
    "Key Recovery",
    "Wechseldatenträgerkontrolle",
    "Application Behavior Control",
    "Verschlüsselung von USB-Datenträgern",
    "Encryption to Go",
    "Microsoft Defender Management",
    "Windows Firewall Management",
    "Local User and Group Management",
    "Security Configuration Management",
    "Endpoint Compliance",
    "Security Event Manager",
    "Agentic AI Control",
    "Hypersecure Platform",
    "sicherer Datenaustausch",
    "verschlüsselter Datenaustausch",
    "Filesharing",
    "File Sharing",
    "Secure Collaboration",
    "sichere externe Zusammenarbeit",
    "Gremienportal",
    "sichere Vorstandskommunikation",
    "verschlüsselter E-Mail-Anhang",
    "Secure Mail",
    "sichere Dateiübertragung",
    "Company Drive",
    "Datenhoheit",
    "Datensouveränität",
    "digitale Souveränität",
    "DSGVO-konforme Cloud",
    "Datenhaltung in Deutschland",
    "Betreiberzugriff",
    "Zero-Knowledge",
    "Gastbenutzer",
    "SharePoint-Alternative",
    "Dropbox-Alternative",
    "Common Criteria",
    "Datenresidenz",
    "Hosting in Deutschland",
    "Hosting in der EU",
    "regulierte Branche",
]
# Excluded everywhere (live-tested, too generic/fuzzy-matched broadly): DORA,
# öffentliche Verwaltung, DLP, EFSS, Device Control, Whitelisting, System
# Hardening, Schlüsselverwaltung, externe Projektpartner,
# Microsoft-Teams-Integration.
#
# CPV-coupled bucket (added 2026-08-30): same terms as fetch_new_notices.py's
# CPV_COUPLED_KEYWORDS - too generic to match as bare terms, but this source
# (unlike service.bund.de/bayvebe.bayern.de/vergabekooperation.berlin) DOES
# have reliable CPV data per-notice (classification.csv, see module
# docstring), so the CPV-coupling technique validated live against TED can be
# reimplemented here as a client-side post-filter condition: a CPV-coupled
# term only counts as a match if the record's OWN cpvCodes intersect the
# security-software CPV pre-filter list.
CPV_COUPLED_KEYWORDS = [
    "KRITIS",
    "NIS2",
    "BSI IT-Grundschutz",
    "VS-NfD",
    "ISO 27001",
    "C5",
    "Geheimschutz",
    "DSGVO",
    "GDPR",
    "kritische Infrastruktur",
    "Projektraum",
    "Due Diligence",
]

# Same 7-code "CPV-Codes (Vorfilter)" list used in fetch_new_notices.py.
CPV_CODES = {
    "48730000", "48731000", "48732000", "48760000", "48781000", "48516000", "48783000",
}


def fetch_export_zip(day_str, retries=3):
    """Downloads the csv.zip export for one calendar day (YYYY-MM-DD).
    Returns raw ZIP bytes, or None if every attempt failed."""
    url = EXPORT_URL_TMPL.format(day=day_str)
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.bekanntmachungsservice.csv.zip+zip"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            print(f"  HTTP error {e.code} for {day_str} (attempt {attempt+1}/{retries})")
            if e.code == 400:
                return None  # day out of range (e.g. today/future) - retrying won't help
            time.sleep(2)
        except Exception as e:
            print(f"  error {e} for {day_str} (attempt {attempt+1}/{retries})")
            time.sleep(3)
    return None


def read_csv_table(zf, name):
    """Reads one CSV member of the ZIP as a list of dicts. Returns [] if the
    member is absent (some tables are only present when relevant data
    exists for that day, e.g. cvdInformation.csv)."""
    try:
        with zf.open(name) as f:
            text = io.TextIOWrapper(f, encoding="utf-8", newline="")
            return list(csv.DictReader(text))
    except KeyError:
        return []


def parse_day_export(zip_bytes):
    """Parses one day's ZIP into per-notice records shaped for KEYWORDS
    matching + final output. Returns a dict keyed by (noticeIdentifier,
    noticeVersion) -> shaped record (pre-filter, pre-dedup)."""
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))

    notices = read_csv_table(zf, "notice.csv")
    purposes = read_csv_table(zf, "purpose.csv")
    classifications = read_csv_table(zf, "classification.csv")
    organisations = read_csv_table(zf, "organisation.csv")
    places = read_csv_table(zf, "placeOfPerformance.csv")

    # purpose.csv/classification.csv/organisation.csv/placeOfPerformance.csv
    # all carry MULTIPLE rows per notice (one per lot, plus often one
    # notice-level row with a blank lotIdentifier) - group first, one entry
    # per (noticeIdentifier, noticeVersion).
    purpose_by_notice = {}
    for row in purposes:
        key = (row.get("noticeIdentifier"), row.get("noticeVersion"))
        purpose_by_notice.setdefault(key, []).append(row)

    cpv_by_notice = {}
    for row in classifications:
        key = (row.get("noticeIdentifier"), row.get("noticeVersion"))
        codes = cpv_by_notice.setdefault(key, set())
        for field in ("mainClassificationCode", "additionalClassificationCodes"):
            raw = row.get(field) or ""
            for code in re.split(r"[;,]", raw):
                code = code.strip()
                if code:
                    codes.add(code)

    buyer_by_notice = {}
    for row in organisations:
        if (row.get("organisationRole") or "").strip().lower() != "buyer":
            continue
        key = (row.get("noticeIdentifier"), row.get("noticeVersion"))
        buyer_by_notice.setdefault(key, row)  # first buyer row wins

    place_by_notice = {}
    for row in places:
        key = (row.get("noticeIdentifier"), row.get("noticeVersion"))
        place_by_notice.setdefault(key, row)  # first place row wins

    shaped = {}
    for n in notices:
        key = (n.get("noticeIdentifier"), n.get("noticeVersion"))
        p_rows = purpose_by_notice.get(key, [])
        if not p_rows:
            continue  # no title anywhere for this notice - can't display it meaningfully

        # Prefer the notice-level row (blank/"" lotIdentifier) for the
        # displayed title/description; fall back to the first lot row.
        primary = next((r for r in p_rows if not (r.get("lotIdentifier") or "").strip()), p_rows[0])
        title = (primary.get("title") or "").strip() or None
        description = (primary.get("description") or "").strip() or None
        if not title:
            continue

        # Match against ALL rows for this notice (title+description of
        # every lot), not just the primary one - a DriveLock/idgard mention
        # could sit in a single lot's description even if the notice-level
        # title is generic.
        match_blob = " ".join(
            f"{r.get('title','')} {r.get('description','')}" for r in p_rows
        ).lower()

        buyer = buyer_by_notice.get(key, {})
        place = place_by_notice.get(key, {})
        plz = (buyer.get("organisationPostCode") or place.get("placePerformancePostCode") or "").strip() or None
        city = (buyer.get("organisationCity") or place.get("placePerformanceCity") or "").strip() or None
        country = (buyer.get("organisationCountryCode") or place.get("placePerformanceCountryCode") or "DEU").strip() or "DEU"

        notice_id = n.get("noticeIdentifier")
        lot_id = primary.get("lotIdentifier") or None
        detail_url = DETAIL_URL_TMPL.format(notice_id=notice_id) + (f"&lotId={lot_id}" if lot_id else "")

        pub_date = None
        raw_pub = n.get("publicationDate") or ""
        m = re.match(r"(\d{4}-\d{2}-\d{2})", raw_pub)
        if m:
            pub_date = m.group(1)

        shaped[key] = {
            "publicationNumber": f"OEV-{notice_id}",
            "title": title,
            "buyerName": (buyer.get("organisationName") or "").strip() or None,
            "country": country,
            "publicationDate": pub_date,
            # No submission-deadline field exists in this export (checked
            # all 19 tables - see module docstring); always None here, not a
            # bug. OCDS export would carry tender.tenderPeriod.endDate
            # instead but requires a separate JSON-parsing path.
            "deadline": None,
            "noticeType": n.get("noticeType") or "oeffentlichevergabe-notice",
            "procedureType": None,
            "cpvCodes": sorted(cpv_by_notice.get(key, set())),
            "estimatedValue": None,
            "currency": None,
            "description": description,
            "originalUrl": detail_url,  # best-effort/unverified for numeric noticeIdentifier - see module docstring
            "lotName": lot_id,
            "awardedTo": None,
            "documentsUrl": detail_url,
            "contractDurationMonths": None,
            "buyerEmail": None,
            "buyerLegalType": (buyer.get("buyerLegalType") or "").strip() or None,
            "buyerActivity": None,
            "contractFolderId": None,
            "internalId": notice_id,
            "procedureCode": None,
            "accelerated": None,
            "performanceLocation": {"postalZone": plz, "city": city} if (plz or city) else None,
            "source": "oeffentlichevergabe.de",
            "_match_blob": match_blob,  # stripped before writing output, used only for KEYWORDS matching below
        }

    return shaped


def normalize_title(title):
    if not title:
        return ""
    t = title.lower().strip()
    parts = [p.strip() for p in t.split("–") if p.strip()]
    tail = parts[-1] if parts else t
    return re.sub(r"\s+", " ", tail)


def looks_like_cross_source_duplicate(rec, existing):
    """Same heuristic-only approach as the other secondary-source fetchers
    (title tail + buyer-name-prefix match). Particularly relevant here since
    a meaningful share of notices on this portal also flow through TED -
    see module docstring."""
    new_tail = normalize_title(rec.get("title"))
    if not new_tail:
        return None
    new_buyer = (rec.get("buyerName") or "").lower().strip()
    for ex in existing:
        ex_tail = normalize_title(ex.get("title"))
        if not ex_tail:
            continue
        if new_tail == ex_tail or new_tail in ex_tail or ex_tail in new_tail:
            ex_buyer = (ex.get("buyerName") or "").lower().strip()
            if new_buyer and ex_buyer and new_buyer[:15] not in ex_buyer and ex_buyer[:15] not in new_buyer:
                continue
            return ex.get("publicationNumber")
    return None


def build_keyword_pattern():
    """Word-boundary regex instead of naive substring matching. Live-tested
    against a real day's export and found this IS necessary, not
    theoretical: "IGEL" as a plain substring matched inside ordinary German
    words like "Steigeleitungen", "beigelegt", "Freigelände",
    "freigelegte" - every single match in an initial 3-day test run was a
    false positive of exactly this kind, because this module (unlike
    fetch_bayvebe.py, which only checks the short title field) matches
    against full lot descriptions too, giving "igel" far more surface to
    accidentally appear in. fetch_bayvebe.py has the same underlying
    substring-match code (`kw in title_for_match`) but it's a smaller risk
    there since titles are short - flagged separately, not fixed here since
    that's a different, already-deployed module."""
    parts = [re.escape(k) for k in KEYWORDS]
    return re.compile(r"\b(?:" + "|".join(parts) + r")\b", re.IGNORECASE)


def build_cpv_coupled_keyword_pattern():
    """Same word-boundary approach as build_keyword_pattern(), applied to the
    CPV_COUPLED_KEYWORDS bucket. A match against this pattern alone is NOT
    sufficient - see the CPV intersection check in main()."""
    parts = [re.escape(k) for k in CPV_COUPLED_KEYWORDS]
    return re.compile(r"\b(?:" + "|".join(parts) + r")\b", re.IGNORECASE)


KEYWORD_PATTERN = build_keyword_pattern()
CPV_COUPLED_PATTERN = build_cpv_coupled_keyword_pattern()


def main():
    parser = argparse.ArgumentParser(description="Detect new DriveLock/idgard-relevant tenders on oeffentlichevergabe.de.")
    parser.add_argument("--days", type=int, default=3, help="Lookback window in days (default: 3)")
    parser.add_argument("--out", type=str, default="new_notices_found_oeffentlichevergabe.json", help="Output JSON path")
    parser.add_argument("--dataset", type=str, default="ted_shaped_final.json", help="Existing dataset path for dedup")
    args = parser.parse_args()

    with open(args.dataset, "r", encoding="utf-8") as f:
        existing = json.load(f)
    existing_ids = {r["publicationNumber"] for r in existing}
    print(f"Existing dataset: {len(existing)} records")

    seen_ids = set()
    new_records = []

    # pubDay must be strictly BEFORE today (today/future -> HTTP 400, see
    # module docstring) - start the loop at 1 day back, not 0.
    today = datetime.now(timezone.utc).date()
    any_fetch_ok = False
    for offset in range(1, args.days + 1):
        day = today - timedelta(days=offset)
        day_str = day.strftime("%Y-%m-%d")
        print(f"Fetching oeffentlichevergabe.de export for {day_str}...")
        zip_bytes = fetch_export_zip(day_str)
        if zip_bytes is None:
            print(f"  FAILED to fetch export for {day_str}, skipping this day")
            continue
        any_fetch_ok = True
        try:
            shaped = parse_day_export(zip_bytes)
        except Exception as e:
            print(f"  error parsing export for {day_str}: {e}, skipping this day")
            continue
        print(f"  {len(shaped)} notice(s) with a usable title on {day_str}")

        for rec in shaped.values():
            match_blob = rec.pop("_match_blob")
            clean_hit = bool(KEYWORD_PATTERN.search(match_blob))
            cpv_coupled_hit = False
            if not clean_hit and CPV_COUPLED_PATTERN.search(match_blob):
                # CPV-coupling (added 2026-08-30): a CPV-coupled term (e.g.
                # DSGVO, KRITIS, Projektraum) only counts if this notice's own
                # CPV codes intersect the security-software pre-filter list -
                # otherwise it's exactly the kind of generic false-positive
                # match live-tested and rejected on TED.
                if set(rec.get("cpvCodes") or []) & CPV_CODES:
                    cpv_coupled_hit = True
            if not (clean_hit or cpv_coupled_hit):
                continue
            pn = rec["publicationNumber"]
            if pn in existing_ids or pn in seen_ids:
                continue
            dup_of = looks_like_cross_source_duplicate(rec, existing)
            if dup_of:
                print(f"  SKIP (likely same tender already in dataset as {dup_of} via another source): {pn} -> {rec['title']!r}")
                continue
            seen_ids.add(pn)
            new_records.append(rec)
            print(f"  NEW: {pn} -> {rec['title']!r} (Beschaffer: {rec['buyerName']})")

    if not any_fetch_ok:
        print("FAILED to fetch any day's export, writing empty result")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(new_records, f, ensure_ascii=False, indent=2)
    print(f"\nDone. {len(new_records)} genuinely new record(s) written to {args.out}")


if __name__ == "__main__":
    main()
