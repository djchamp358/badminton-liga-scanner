# Badminton Liga-Scanner

Browser-App für Turnier.de/DBV: Turnier-Link einfügen → Teilnehmer auslesen → DBV-Spielerprofile auflösen → Liga-Historie anzeigen → CSV exportieren.

## Deploy

Die App ist als einzelner FastAPI-Webservice gebaut. Render kann Python/FastAPI direkt als Web Service deployen. Alternativ funktioniert das Dockerfile auf jedem Docker-Host.

### Render
1. Repository mit diesem Projekt verbinden.
2. **New → Web Service**.
3. Runtime **Python**.
4. Build: `pip install -r requirements.txt`
5. Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`
6. Region: Frankfurt.

### Lokal nur zum Testen
`pip install -r requirements.txt`
`uvicorn app:app --reload`

Danach `http://127.0.0.1:8000` öffnen.

## Hinweise

- Der Server ruft Turnier.de/DBV serverseitig ab. Der Browser muss Turnier.de nicht direkt per JavaScript abrufen.
- Die App beschränkt sich auf DBV/Turnier.de-Domains und nutzt Rate-Limits zwischen Profilabrufen.
- Die Liga-Daten stammen aus den öffentlich sichtbaren DBV-Spielerprofilen und deren `/leagues`-Seiten.
- Falls ein Profil keine öffentlich sichtbare Liga enthält, wird das als „keine Liga gefunden“ angezeigt – es wird nichts erfunden.
