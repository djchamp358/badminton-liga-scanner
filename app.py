from __future__ import annotations

import asyncio
import csv
import hashlib
import hmac
import io
import os
import re
import time
import httpx
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

import psycopg
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "Static"
app = FastAPI(title="Badminton Liga-Scanner", version="2.2.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ALLOWED_HOSTS = {"dbv.turnier.de", "turnier.de"}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
MAX_PLAYERS = 120
MAX_COMPETITIONS = 30
CACHE_TTL = 7 * 24 * 60 * 60
MAX_CACHE_ROWS = 1000
FETCH_INTERVAL_SECONDS = 5
_fetch_lock = asyncio.Lock()
_last_fetch = 0.0


class AnalyzeRequest(BaseModel):
    url: str
    competition_url: str
    seasons: int = Field(default=5, ge=1, le=15)
    delay_ms: int = Field(default=250, ge=0, le=2000)


class CompetitionRequest(BaseModel):
    url: str


def settings() -> tuple[str, str]:
    password = os.getenv("APP_PASSWORD", "")
    secret = os.getenv("SESSION_SECRET", "")
    if len(password) < 12:
        raise RuntimeError("APP_PASSWORD fehlt oder ist kürzer als 12 Zeichen.")
    if len(secret) < 32:
        raise RuntimeError("SESSION_SECRET fehlt oder ist kürzer als 32 Zeichen.")
    if not os.getenv("DATABASE_URL"):
        raise RuntimeError("DATABASE_URL fehlt. Bitte die verbundene Blitz-Datenbank prüfen.")
    return password, secret


def db_connect():
    return psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=15)


def init_db():
    settings()
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scanner_cache (
                cache_key TEXT PRIMARY KEY,
                cache_value JSONB NOT NULL,
                created_at DOUBLE PRECISION NOT NULL
            )
        """)
        conn.execute("DELETE FROM scanner_cache WHERE created_at < %s", (time.time() - CACHE_TTL,))
        conn.commit()


@app.on_event("startup")
async def startup():
    await asyncio.to_thread(init_db)


def _signature(stamp: str) -> str:
    _, secret = settings()
    return hmac.new(secret.encode(), stamp.encode(), hashlib.sha256).hexdigest()


def _valid_session(request: Request) -> bool:
    token = request.cookies.get("scanner_session", "")
    try:
        stamp, supplied = token.split(".", 1)
        issued = int(stamp)
        if issued > int(time.time()) + 60 or time.time() - issued > 14 * 86400:
            return False
        return hmac.compare_digest(_signature(stamp), supplied)
    except Exception:
        return False


def require_auth(request: Request):
    if not _valid_session(request):
        raise HTTPException(401, "Bitte zuerst anmelden.")


LOGIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Anmeldung</title>
<style>body{font:16px Arial;background:#f4f7fb;color:#172033;max-width:420px;margin:12vh auto;padding:20px}
main{background:white;padding:26px;border-radius:14px;box-shadow:0 2px 12px #0001}
input,button{box-sizing:border-box;width:100%;padding:13px;margin:9px 0;font-size:16px;border-radius:8px}
input{border:1px solid #bbb}button{background:#176b46;color:white;border:0;font-weight:bold}
#error{color:#a21d1d}</style><main><h1>Badminton Liga-Scanner</h1>
<p>Bitte mit deinem persönlichen Passwort anmelden.</p><p id="error">__ERROR__</p>
<form method="post" action="/login"><input type="password" name="password" placeholder="Passwort" required autofocus>
<button type="submit">Anmelden</button></form></main></html>"""


@app.get("/")
async def index(request: Request):
    if not _valid_session(request):
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", ""))
    return FileResponse(str(STATIC_DIR / "Index.html"))


@app.post("/login")
async def login(request: Request):
    password, _ = settings()
    body = (await request.body()).decode("utf-8", "replace")
    supplied = parse_qs(body).get("password", [""])[0]
    if not hmac.compare_digest(supplied, password):
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", "Passwort nicht richtig."), status_code=401)
    stamp = str(int(time.time()))
    token = stamp + "." + _signature(stamp)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("scanner_session", token, max_age=14 * 86400, httponly=True,
                        secure=True, samesite="strict", path="/")
    return response


@app.post("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("scanner_session", path="/", secure=True, httponly=True, samesite="strict")
    return response


def allowed(url: str) -> bool:
    p = urlparse(url)
    return p.scheme == "https" and p.hostname in ALLOWED_HOSTS and not p.username and not p.password


def clean(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _cache_get(key: str):
    with db_connect() as conn:
        row = conn.execute(
            "SELECT cache_value FROM scanner_cache WHERE cache_key=%s AND created_at >= %s",
            (key, time.time() - CACHE_TTL)
        ).fetchone()
        return row[0] if row else None


def _cache_put(key: str, value: Any):
    import json
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO scanner_cache(cache_key,cache_value,created_at)
               VALUES (%s,%s::jsonb,%s)
               ON CONFLICT(cache_key) DO UPDATE SET
               cache_value=EXCLUDED.cache_value, created_at=EXCLUDED.created_at""",
            (key, json.dumps(value, ensure_ascii=False), time.time())
        )
        conn.execute("""
            DELETE FROM scanner_cache WHERE cache_key IN (
              SELECT cache_key FROM scanner_cache ORDER BY created_at DESC OFFSET %s
            )
        """, (MAX_CACHE_ROWS,))
        conn.commit()


async def cache_get(key: str):
    return await asyncio.to_thread(_cache_get, key)


async def cache_put(key: str, value: Any):
    await asyncio.to_thread(_cache_put, key, value)



async def fetch(url: str) -> str:
    global _last_fetch

    if not allowed(url):
        raise HTTPException(
            400,
            "Nur sichere HTTPS-Links von DBV/Turnier.de werden akzeptiert."
        )

    cached_html = await cache_get("html:" + url)
    if cached_html is not None:
        return cached_html

    async with _fetch_lock:
        cached_html = await cache_get("html:" + url)
        if cached_html is not None:
            return cached_html

        wait = FETCH_INTERVAL_SECONDS - (time.monotonic() - _last_fetch)
        if wait > 0:
            await asyncio.sleep(wait)

        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/ms-playwright"
        from playwright.async_api import async_playwright

        browser = None

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)

                page = await browser.new_page(
                    locale="de-DE",
                    user_agent=UA,
                    accept_downloads=False
                )

                last_error = None

                for attempt in range(2):
                    try:
                        print(
                            f"DEBUG FETCH Versuch {attempt + 1}: {url}",
                            flush=True
                        )

                        await page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=90000
                        )

                        await page.wait_for_timeout(1000)

                        if "cookiewall" in page.url.lower():
                            try:
                                await page.get_by_role(
                                    "button",
                                    name=re.compile(
                                        "accept|akzeptieren|zustimmen",
                                        re.I
                                    )
                                ).click(timeout=8000)

                                await page.wait_for_timeout(1000)

                                await page.goto(
                                    url,
                                    wait_until="domcontentloaded",
                                    timeout=90000
                                )
                            except Exception:
                                pass

                        final_url = page.url
                        content = await page.content()

                        if "cookiewall" in final_url.lower():
                            raise HTTPException(
                                502,
                                "Turnier.de zeigt weiterhin die Cookie-Seite."
                            )

                        await cache_put("html:" + url, content)
                        _last_fetch = time.monotonic()

                        print(
                            f"DEBUG FETCH erfolgreich: {url}",
                            flush=True
                        )

                        return content

                    except HTTPException:
                        raise

                    except Exception as exc:
                        last_error = exc
                        print(
                            f"DEBUG FETCH Fehler Versuch {attempt + 1}: "
                            f"{type(exc).__name__}: {exc}",
                            flush=True
                        )

                        if attempt == 0:
                            await asyncio.sleep(3)

                print(
                    "DEBUG: Versuche jetzt direkten HTTPX-Abruf:",
                    url,
                    flush=True
                )

                try:
                    async with httpx.AsyncClient(
                        follow_redirects=True,
                        timeout=httpx.Timeout(30.0),
                        headers={
                            "User-Agent": UA,
                            "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
                            "Accept": "text/html,application/xhtml+xml"
                        }
                    ) as client:
                        response = await client.get(url)
                        response.raise_for_status()

                        if not allowed(str(response.url)):
                            raise ValueError(
                                "Weiterleitung auf eine nicht erlaubte Adresse"
                            )

                        content = response.text

                        if "cookiewall" in str(response.url).lower():
                            raise ValueError(
                                "DBV hat auf eine Cookie-Seite weitergeleitet"
                            )

                        await cache_put("html:" + url, content)
                        _last_fetch = time.monotonic()

                        print(
                            f"DEBUG HTTPX erfolgreich: Status "
                            f"{response.status_code}, {len(content)} Zeichen",
                            flush=True
                        )

                        return content

                except Exception as exc:
                    print(
                        f"DEBUG HTTPX ebenfalls fehlgeschlagen: "
                        f"{type(exc).__name__}: {exc}",
                        flush=True
                    )

                raise HTTPException(
                    502,
                    f"Browser und HTTPX fehlgeschlagen. "
                    f"Letzter Browser-Fehler: "
                    f"{type(last_error).__name__}: {last_error}"
                )

        except HTTPException:
            raise

        except Exception as exc:
            raise HTTPException(
                502,
                f"Browser-Abruf fehlgeschlagen: "
                f"{type(exc).__name__}: {exc}"
            )

        finally:
            if browser:
                await browser.close()



def competition_urls(content: str, base: str) -> list[dict[str, str]]:
    """Liest Konkurrenznamen und deren Unterseiten-URLs aus der Turnierübersicht."""
    soup = BeautifulSoup(content, "lxml")
    found, seen = [], set()
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        parsed = urlparse(href)
        if parsed.hostname not in ALLOWED_HOSTS or parsed.path.lower().rstrip("/") != "/sport/event.aspx":
            continue
        params = parse_qs(parsed.query)
        if "event" not in params or "id" not in params:
            continue
        name = clean(a.get_text(" "))
        event_id = params["event"][0]
        if not name or href in seen:
            continue
        seen.add(href)
        found.append({"name": name, "url": href, "event_id": event_id})
    return found[:MAX_COMPETITIONS]


def player_links(content: str, base: str) -> list[dict[str, str]]:
    """Erkennt ausschließlich echte Spieler-URLs; keine Navigations-Fallbacks."""
    soup = BeautifulSoup(content, "lxml")
    candidates, seen = [], set()
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        parsed = urlparse(href)
        path = parsed.path.lower()
        is_player = (
            path.rstrip("/") == "/sport/player.aspx"
            or re.search(r"/tournament/[^/]+/player/[^/]+/?$", path)
            or "/player-profile/" in path
        )
        if parsed.hostname not in ALLOWED_HOSTS or not is_player:
            continue
        name = clean(a.get_text(" "))
        name = re.sub(r"\s*\[[^\]]+\]\s*$", "", name).strip()
        if not name or len(name) < 3 or len(name) > 80:
            continue
        if name.lower() in {"spieler", "player", "favorit", "log in"}:
            continue
        match = re.search(r"/player/([^/]+)", path)
        identity = parse_qs(parsed.query).get("player", [""])[0] or (match.group(1) if match else href)
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append({"name": name, "url": href})
    return candidates


async def event_players(competition_url: str, competition_name: str) -> list[dict[str, str]]:
    """Liest nur die ausgewählte Konkurrenz aus."""
    content = await fetch(competition_url)
    players = player_links(content, competition_url)
    return [{**p, "competition": competition_name} for p in players[:MAX_PLAYERS]]


def find_profile_url(content: str, base: str) -> str | None:
    soup = BeautifulSoup(content, "lxml")

    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        parsed = urlparse(href)
        path = parsed.path.lower().rstrip("/")

        # DBV-Profilformate:
        # Alt: /player/{UUID}/{Spielerkennung}
        # Neu: /player-profile/{UUID}
        if parsed.hostname in ALLOWED_HOSTS and (
            re.fullmatch(r"/player/[^/]+/[^/]+", path)
            or re.fullmatch(r"/player-profile/[^/]+", path)
        ):
            # Tracking- und sonstige Query-Parameter entfernen
            return urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path.rstrip("/"),
                "",
                "",
                ""
            ))

    return None



def league_pages(content: str, base: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(content, "lxml")
    out, seen = [], set()

    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        parsed = urlparse(href)

        if parsed.hostname not in ALLOWED_HOSTS:
            continue

        # Jahreszahl aus dem URL-Parameter Year lesen
        params = parse_qs(parsed.query)
        year = params.get("Year", [None])[0]

        # Zusätzlich das ältere URL-Format unterstützen
        if not year:
            path = parsed.path.lower().rstrip("/")
            match = re.fullmatch(
                r"/player/[^/]+/[^/]+/leagues/(\d{4})",
                path
            )
            if match:
                year = match.group(1)

        if not year or not re.fullmatch(r"\d{4}", year):
            continue

        if year not in {str(y) for y in range(2010, 2040)}:
            continue

        if href not in seen:
            seen.add(href)
            out.append((year, href))

    out.sort(key=lambda x: int(x[0]), reverse=True)
    return out



def parse_league_season(content: str, season_code: str, url: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(content, "lxml")
    result = []
    for a in soup.find_all("a", href=True):
        href = urljoin(url, a["href"])
        if "/league/" not in urlparse(href).path.lower():
            continue
        text = clean(a.get_text(" "))
        if not text:
            continue
        league = text.split(")", 1)[1].strip() if ")" in text else text
        if "–" in league and league.count("–") >= 2:
            league = league.split("–")[-1].strip() or league
        team, node = "", a
        for _ in range(5):
            node = node.parent
            if not node:
                break
            for tag in node.find_all(["h1", "h2", "h3", "h4", "h5", "strong"], limit=5):
                candidate = clean(tag.get_text(" "))
                if candidate and candidate != text and len(candidate) <= 100:
                    team = candidate
                    break
            if team:
                break
        season = f"{int(season_code)-1}/{str(int(season_code))[-2:]}" if season_code.isdigit() else "aktuell"
        result.append({"season": season, "league": league, "team": team, "url": href})
    unique, keys = [], set()
    for item in result:
        key = (item["season"], item["league"], item["team"])
        if key not in keys:
            keys.add(key)
            unique.append(item)
    return unique




async def analyze_player(p: dict[str, str], seasons: int, delay_ms: int):
    key = f"player-v6:{p['url']}:{seasons}:{p.get('competition', '')}"

    hit = await cache_get(key)
    if hit is not None:
        print("DEBUG CACHE-TREFFER:", p.get("name", p.get("player", p["url"])), flush=True)
        return hit

    print("DEBUG NEUE SPIELERANALYSE:", p.get("name", p.get("player", p["url"])), flush=True)

    try:
        # Spielerprofil laden
        content = await fetch(p["url"])

        # Manche Teilnehmerlinks führen bereits direkt zum DBV-Spielerprofil.
        # In diesem Fall nicht nochmals auf der Profilseite nach einem Profil-Link suchen.
        player_url = urlparse(p["url"])
        player_path = player_url.path.lower().rstrip("/")
        is_direct_profile = (
            player_url.hostname in ALLOWED_HOSTS
            and (
                re.fullmatch(r"/player-profile/[^/]+", player_path)
                or re.fullmatch(r"/player/[^/]+/[^/]+", player_path)
            )
        )
        profile = p["url"] if is_direct_profile else find_profile_url(content, p["url"])

        if not profile:
            print("DEBUG KEIN PROFILLINK:", p.get("name", p["url"]), "| Teilnehmerseite:", p["url"], flush=True)
            result = {
                **p,
                "profile_url": None,
                "leagues": [],
                "status": "Kein DBV-Profil-Link gefunden"
            }
            await cache_put(key, result)
            return result

        # Liga-Übersichtsseite laden
        index_url = profile.rstrip("/") + "/leagues"
        index_html = await fetch(index_url)

        # Vorhandene Saisonlinks ermitteln
        pages = league_pages(index_html, index_url)

        print("DEBUG PROFIL:", profile, flush=True)
        print("DEBUG LIGA-SEITE:", index_url, flush=True)
        print("DEBUG GEFUNDENE SAISONS:", pages, flush=True)

        leagues = []

        if pages:
            # Die Liga-Übersichtsseite enthält bereits
            # die aktuell ausgewählte Saison.
            selected_year = pages[0][0]

            print(
                "DEBUG: Lese Liga-Daten direkt aus der Übersichtsseite:",
                selected_year,
                flush=True
            )

            leagues = parse_league_season(
                index_html,
                selected_year,
                index_url
            )

            print(
                "DEBUG: Gefundene Liga-Einträge:",
                len(leagues),
                flush=True
            )

        result = {
            **p,
            "profile_url": profile,
            "leagues": leagues,
            "status": "OK" if leagues else "Keine Liga gefunden"
        }

        await cache_put(key, result)
        return result

    except HTTPException as exc:
        if exc.status_code == 502:
            raise

        return {
            **p,
            "profile_url": None,
            "leagues": [],
            "status": f"Fehler: {exc.detail}"
        }

    except Exception as exc:
        return {
            **p,
            "profile_url": None,
            "leagues": [],
            "status": f"Fehler: {str(exc)[:120]}"
        }




@app.get("/api/cache-info")
async def cache_info(request: Request):
    require_auth(request)
    def count_rows():
        with db_connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM scanner_cache").fetchone()[0]
    count = await asyncio.to_thread(count_rows)
    return {"database": "verbunden", "cache_entries": count, "cache_days": 7}


@app.get("/api/test-profile")
async def test_profile(request: Request):
    require_auth(request)
    return {"hinweis": "Der DBV-Zugriff wird beim nächsten Scan geprüft. Ein separates Testabrufen würde unnötige Anfragen erzeugen."}


@app.post("/api/competitions")
async def get_competitions(req: CompetitionRequest, request: Request):
    require_auth(request)
    if not allowed(req.url):
        raise HTTPException(400, "Bitte einen sicheren HTTPS-Link von dbv.turnier.de oder turnier.de verwenden.")
    html_content = await fetch(req.url)
    competitions = competition_urls(html_content, req.url)
    if not competitions:
        raise HTTPException(422, "Auf dieser Seite wurden keine Konkurrenz-Unterseiten gefunden. Bitte den Link zur Turnierübersicht prüfen.")
    return {"competitions": competitions}


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    require_auth(request)
    if not allowed(req.url) or not allowed(req.competition_url):
        raise HTTPException(400, "Bitte sichere HTTPS-Links von dbv.turnier.de oder turnier.de verwenden.")
    overview_html = await fetch(req.url)
    competitions = competition_urls(overview_html, req.url)
    selected = next((c for c in competitions if c["url"] == req.competition_url), None)
    if selected is None:
        raise HTTPException(400, "Die ausgewählte Konkurrenz gehört nicht zu dieser Turnierübersicht. Bitte Konkurrenzen erneut laden.")
    players = await event_players(selected["url"], selected["name"])
    if not players:
        raise HTTPException(422, f"Keine Spielerlinks in {selected['name']} erkannt. Bitte prüfen, ob die Konkurrenz Meldungen enthält und wie die Teilnehmerseite aufgebaut ist.")
    rows = []
    for i, player in enumerate(players):
        if i and req.delay_ms:
            await asyncio.sleep(req.delay_ms / 1000)
        rows.append(await analyze_player(player, req.seasons, req.delay_ms))
    return {
        "source_url": req.url,
        "competition": selected["name"],
        "count": len(rows),
        "players": rows
    }


@app.post("/api/csv")
async def make_csv(payload: dict, request: Request):
    require_auth(request)
    players = payload.get("players") or []
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\n")
    writer.writerow(["Konkurrenz", "Spieler", "Aktuelle Liga", "Verein", "Liga-Historie", "DBV-Profil", "Status"])
    for player in players:
        leagues = player.get("leagues") or []
        current = leagues[0] if leagues else {}
        history = " | ".join(f"{x.get('season','')}: {x.get('league','')} ({x.get('team','')})" for x in leagues)
        writer.writerow([
            player.get("competition", ""),
            player.get("name", ""),
            current.get("league", ""),
            current.get("team", ""),
            history,
            player.get("profile_url", ""),
            player.get("status", "")
        ])
    data = buf.getvalue().encode("utf-8-sig")
    return StreamingResponse(io.BytesIO(data), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": "attachment; filename=badminton_liga_scan.csv"})
