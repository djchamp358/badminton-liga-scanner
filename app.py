from __future__ import annotations
1
import asyncio
import csv
import io
import re
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

APP = FastAPI(title="Badminton Liga-Scanner", version="1.0.0")
APP.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "Static")), name="static")

ALLOWED_HOSTS = {"dbv.turnier.de", "turnier.de"}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
TIMEOUT = httpx.Timeout(25.0, connect=15.0)
CACHE: OrderedDict[str, tuple[float, Any]] = OrderedDict()
CACHE_TTL = 60 * 60 * 6
MAX_PLAYERS = 80

class AnalyzeRequest(BaseModel):
    url: str
    seasons: int = Field(default=5, ge=1, le=15)
    delay_ms: int = Field(default=250, ge=0, le=2000)


def clean(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def allowed(url: str) -> bool:
    p = urlparse(url)
    return p.scheme in {"http", "https"} and p.hostname in ALLOWED_HOSTS


def cached(key: str):
    hit = CACHE.get(key)
    if not hit:
        return None
    ts, value = hit
    if time.time() - ts > CACHE_TTL:
        CACHE.pop(key, None)
        return None
    CACHE.move_to_end(key)
    return value


def put_cache(key: str, value: Any):
    CACHE[key] = (time.time(), value)
    CACHE.move_to_end(key)
    while len(CACHE) > 300:
        CACHE.popitem(last=False)


async def fetch(client: httpx.AsyncClient, url: str) -> str:
    if not allowed(url):
        raise HTTPException(400, "Nur DBV/Turnier.de-Links werden akzeptiert.")

    r = await client.get(url, follow_redirects=True)
    print("DEBUG Turnier.de:", r.status_code, r.url)
    r.raise_for_status()

    if "cookiewall" in str(r.url).lower():
        raise HTTPException(
            502,
            "Turnier.de liefert dem Scanner eine Cookie-Seite statt der Teilnehmerliste."
        )

    if "text/html" not in r.headers.get("content-type", "text/html"):
        raise HTTPException(502, "Die Zielseite liefert kein HTML.")

    return r.text


def event_players(html: str, base: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "lxml")
    candidates: list[dict[str, str]] = []
    seen = set()

    # Spielerlinks auf Turnier.de erkennen
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        text = clean(a.get_text(" "))
        path = urlparse(href).path.lower()

        if not text or len(text) < 3 or len(text) > 80:
            continue

        if not any(x in path for x in ("/sport/player.aspx", "/tournament/", "/player/")):
            continue

        if href in seen:
            continue

        if text.lower() in {"spieler", "player", "favorit", "log in"}:
            continue

        seen.add(href)
        candidates.append({"name": text, "url": href})

    # Diagnose: Wenn keine Spielerlinks gefunden werden,
    # ersatzweise bis zu 20 Links mit Text zurückgeben.
    if candidates:
        return candidates[:MAX_PLAYERS]

    return [
        {
            "name": clean(a.get_text(" ")),
            "url": urljoin(base, a["href"]),
        }
        for a in soup.find_all("a", href=True)
        if clean(a.get_text(" ")) and len(clean(a.get_text(" "))) >= 3
    ][:20]


def find_profile_url(html: str, base: str) -> str | None:
    soup = BeautifulSoup(html, "lxml")
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        if "/player-profile/" in urlparse(href).path.lower():
            return href
    return None


def league_pages(html: str, base: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "lxml")
    out: list[tuple[str, str]] = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = urljoin(base, a["href"])
        path = urlparse(href).path.lower()
        text = clean(a.get_text(" "))
        if not re.search(r"/player-profile/.+/leagues(?:/\d+)?$", path):
            continue
        m = re.search(r"/leagues/(\d+)$", path)
        if not m or href in seen:
            continue
        year = m.group(1)
        if year not in {str(y) for y in range(2010, 2040)}:
            continue
        seen.add(href)
        out.append((year, href))
    # Also support a profile page whose current season is only exposed as /leagues.
    if not out:
        for a in soup.find_all("a", href=True):
            href = urljoin(base, a["href"])
            if re.search(r"/player-profile/.+/leagues$", urlparse(href).path.lower()):
                out.append(("current", href))
                break
    # newest first
    out.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 9999, reverse=True)
    return out


def parse_league_season(html: str, season_code: str, url: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "lxml")
    result: list[dict[str, str]] = []
    for a in soup.find_all("a", href=True):
        href = urljoin(url, a["href"])
        path = urlparse(href).path.lower()
        text = clean(a.get_text(" "))
        if "/league/" not in path or not text:
            continue
        # DBV renders names like "O19-N1 – O19-N1-KK – (129) Kreisklasse Nord 1".
        league_name = text
        if ")" in league_name:
            league_name = league_name.split(")", 1)[1].strip()
        if "–" in league_name and league_name.count("–") >= 2:
            # Prefer the human-readable tail after the classification code.
            tail = league_name.split("–")[-1].strip()
            if tail:
                league_name = tail
        # Find a nearby heading/strong element for the team.
        team = ""
        node = a
        for _ in range(5):
            node = node.parent
            if not node:
                break
            for tag in node.find_all(["h1", "h2", "h3", "h4", "h5", "strong"], limit=5):
                t = clean(tag.get_text(" "))
                if t and t != text and len(t) <= 100:
                    team = t
                    break
            if team:
                break
        season = f"{int(season_code)-1}/{str(int(season_code))[-2:]}" if season_code.isdigit() else "aktuell"
        result.append({"season": season, "league": league_name, "team": team, "url": href})
    # de-duplicate
    unique = []
    keys = set()
    for x in result:
        k = (x["season"], x["league"], x["team"])
        if k not in keys:
            keys.add(k); unique.append(x)
    return unique


async def analyze_player(client: httpx.AsyncClient, p: dict[str, str], seasons: int, delay_ms: int) -> dict[str, Any]:
    cached_result = cached("player:" + p["url"] + f":{seasons}")
    if cached_result:
        return cached_result
    try:
        html = await fetch(client, p["url"])
        profile = find_profile_url(html, p["url"])
        if not profile:
            out = {**p, "profile_url": None, "leagues": [], "status": "Kein DBV-Profil-Link gefunden"}
            put_cache("player:" + p["url"] + f":{seasons}", out)
            return out
        league_index_url = profile.rstrip("/") + "/leagues"
        idx_html = await fetch(client, league_index_url)
        pages = league_pages(idx_html, league_index_url)
        all_leagues: list[dict[str, str]] = []
        for _, page_url in pages[:seasons]:
            await asyncio.sleep(delay_ms / 1000)
            try:
                page_html = await fetch(client, page_url)
                all_leagues.extend(parse_league_season(page_html, page_url.rstrip("/").split("/")[-1], page_url))
            except Exception:
                continue
        out = {**p, "profile_url": profile, "leagues": all_leagues, "status": "OK" if all_leagues else "Keine Liga gefunden"}
        put_cache("player:" + p["url"] + f":{seasons}", out)
        return out
    except Exception as e:
        return {**p, "profile_url": None, "leagues": [], "status": f"Fehler: {str(e)[:120]}"}


@APP.get("/")
async def index():
    return FileResponse(str(Path(__file__).resolve().parent / "Static" / "Index.html"))

@APP.get("/api/test-profile")
async def test_profile():
    url = "https://turnier.de/"

    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": UA, "Accept-Language": "de-DE,de;q=0.9"},
            timeout=httpx.Timeout(45.0, connect=10.0),
            follow_redirects=True,
        ) as client:
            response = await client.get(url)

        return {
            "ok": True,
            "status_code": response.status_code,
            "final_url": str(response.url),
            "content_type": response.headers.get("content-type", ""),
            "html_length": len(response.text),
            "preview": clean(BeautifulSoup(response.text, "lxml").get_text(" "))[:1000],
        }

    except httpx.TimeoutException:
        return {
            "ok": False,
            "error": "Zeitüberschreitung beim Verbindungsaufbau zu Turnier.de.",
        }
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "error": f"HTTP-Verbindungsfehler: {type(exc).__name__}",
        }

@APP.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    if not allowed(req.url):
        raise HTTPException(400, "Bitte einen dbv.turnier.de- oder turnier.de-Link verwenden.")
    async with httpx.AsyncClient(headers={"User-Agent": UA, "Accept-Language": "de-DE,de;q=0.9,en;q=0.7"}, timeout=TIMEOUT) as client:
        try:
            html = await fetch(client, req.url)
        except httpx.HTTPError as e:
            raise HTTPException(502, f"Turnier.de konnte nicht abgerufen werden: {e}")
        players = event_players(html, req.url)
        if not players:
            raise HTTPException(422, f"Keine Spielerlinks erkannt. Geladener HTML-Text: {len(html)} Zeichen. Bitte Diagnose prüfen.")
        rows = []
        for i, p in enumerate(players):
            if i:
                await asyncio.sleep(req.delay_ms / 1000)
            rows.append(await analyze_player(client, p, req.seasons, req.delay_ms))
        # Pairing is based on the starter-list order on the competition page.
        for i, row in enumerate(rows):
            row["pair_no"] = i // 2 + 1
        return {"source_url": req.url, "count": len(rows), "players": rows}

@APP.post("/api/csv")
async def make_csv(payload: dict):
    players = payload.get("players") or []
    buf = io.StringIO(); w = csv.writer(buf, delimiter=";", lineterminator="\n")
    w.writerow(["Paar", "Spieler", "Aktuelle Liga", "Verein", "Liga-Historie", "DBV-Profil", "Status"])
    for p in players:
        leagues = p.get("leagues") or []
        current = leagues[0] if leagues else {}
        history = " | ".join(f"{x.get('season','')}: {x.get('league','')} ({x.get('team','')})" for x in leagues)
        w.writerow([p.get("pair_no", ""), p.get("name", ""), current.get("league", ""), current.get("team", ""), history, p.get("profile_url", ""), p.get("status", "")])
    data = buf.getvalue().encode("utf-8-sig")
    return StreamingResponse(io.BytesIO(data), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=badminton_liga_scan.csv"})
