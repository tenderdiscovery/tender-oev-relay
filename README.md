# tender-oev-relay

Technisches Hilfs-Repo, kein eigenständiges Produkt. Ruft täglich (via
GitHub Actions, siehe `.github/workflows/fetch-oev.yml`) die offizielle,
CC0-lizenzierte Bulk-Export-API von oeffentlichevergabe.de
(Bundes-Bekanntmachungsservice) ab und schreibt DriveLock-/idgard-relevante
Treffer der letzten 3 Tage nach `latest_oev.json`.

Hintergrund: der Produktivserver (Strato-Shared-Hosting) kann
oeffentlichevergabe.de aus einem noch ungeklärten netzwerkseitigen Grund
nicht direkt erreichen (Verbindung haengt/timeoutet schon beim TCP-Connect).
Dieses Repo läuft auf GitHub-eigener Infrastruktur (kein solches Problem) und
dient als Relay: der Server holt sich `latest_oev.json` per einfachem
HTTPS-GET von `raw.githubusercontent.com` statt direkt bei
oeffentlichevergabe.de anzufragen.

Die enthaltenen Daten (Ausschreibungstitel, Beschaffernamen, Aktenzeichen
etc.) sind öffentlich bekanntgemachte Vergabedaten (CC0-lizenziert) - keine
internen/vertraulichen Informationen.
