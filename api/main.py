from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

app = FastAPI(title="MXSEC API", version="0.1.0")

# CORS erlauben (für später, wenn du per fetch() von deiner HTML-Seite zugreifst)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später enger machen (Domain)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
#   MODELS
# =========================

class User(BaseModel):
    id: str
    email: EmailStr
    plan: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class OverviewResponse(BaseModel):
    overall_score: int
    score_change: int
    attacks_last_24h: int
    attacks_change_percent: int
    uptime_percent: float
    uptime_note: str
    targets_total: int
    targets_note: str


class Website(BaseModel):
    id: str
    domain: str
    status: str
    last_score: Optional[int]
    last_scan_at: Optional[datetime]
    risk_level: Optional[str]


class Alert(BaseModel):
    id: str
    type: str
    severity: str
    message: str
    target_type: str
    target_label: str
    created_at: datetime
    tag: str


# =========================
#   FAKE DATA (Demo)
# =========================

FAKE_USER = User(
    id="u_123",
    email="mxdev@example.de",
    plan="pro",
)

FAKE_WEBSITES = [
    Website(
        id="w_1",
        domain="mxdev.de",
        status="online",
        last_score=93,
        last_scan_at=datetime.utcnow() - timedelta(minutes=20),
        risk_level="low",
    ),
    Website(
        id="w_2",
        domain="shop.mxdev.de",
        status="online",
        last_score=81,
        last_scan_at=datetime.utcnow() - timedelta(hours=1, minutes=30),
        risk_level="medium",
    ),
    Website(
        id="w_3",
        domain="demo.mxsec.app",
        status="reachable",
        last_score=67,
        last_scan_at=datetime.utcnow() - timedelta(hours=12),
        risk_level="high",
    ),
    Website(
        id="w_4",
        domain="kundenprojekt.de",
        status="ssl_error",
        last_score=54,
        last_scan_at=datetime.utcnow() - timedelta(days=1),
        risk_level="critical",
    ),
]

FAKE_ALERTS = [
    Alert(
        id="a_1",
        type="cve",
        severity="critical",
        message="Kritische Schwachstelle gefunden",
        target_type="website",
        target_label="kundenprojekt.de",
        created_at=datetime.utcnow() - timedelta(minutes=5),
        tag="CVE",
    ),
    Alert(
        id="a_2",
        type="ssh",
        severity="warn",
        message="Mehrere fehlerhafte SSH Logins",
        target_type="server",
        target_label="mc-prod-01",
        created_at=datetime.utcnow() - timedelta(minutes=12),
        tag="SSH",
    ),
    Alert(
        id="a_3",
        type="info",
        severity="info",
        message="Neue Domain hinzugefügt",
        target_type="website",
        target_label="demo.mxsec.app",
        created_at=datetime.utcnow() - timedelta(minutes=34),
        tag="Info",
    ),
    Alert(
        id="a_4",
        type="autofix",
        severity="info",
        message="AutoFix angewendet (Firewall)",
        target_type="server",
        target_label="mc-prod-01",
        created_at=datetime.utcnow() - timedelta(hours=1),
        tag="AutoFix",
    ),
]


# =========================
#   AUTH (FAKE)
# =========================

@app.post("/api/v1/auth/login", response_model=User)
def login(payload: LoginRequest):
    """
    Fake Login:
    - Ignoriert Passwort
    - Gibt immer den gleichen User zurück, wenn Email passt
    """
    if payload.email != FAKE_USER.email:
        # Fürs MVP einfach eine feste Mail "erlauben"
        raise HTTPException(status_code=401, detail="Ungültige Zugangsdaten")

    # Hier würdest du normalerweise:
    # - Passwort prüfen
    # - Session / JWT ausstellen
    return FAKE_USER


@app.get("/api/v1/auth/me", response_model=User)
def get_me():
    """
    Gibt den aktuellen User zurück.
    Für MVP immer FAKE_USER.
    Später: User aus Token/Cookie.
    """
    return FAKE_USER


# =========================
#   OVERVIEW
# =========================

@app.get("/api/v1/overview", response_model=OverviewResponse)
def get_overview():
    """
    Daten für die vier großen Stat-Karten im Dashboard.
    """
    return OverviewResponse(
        overall_score=89,
        score_change=4,
        attacks_last_24h=432,
        attacks_change_percent=18,
        uptime_percent=99.96,
        uptime_note="1 kurzer Ausfall bei shop.mxdev.de (3 Minuten).",
        targets_total=4,
        targets_note="3 Websites, 1 Server. Grenze deines Pro-Plans.",
    )


# =========================
#   WEBSITES
# =========================

@app.get("/api/v1/websites", response_model=List[Website])
def list_websites():
    """
    Liste der Websites für die Tabelle im Dashboard.
    """
    return FAKE_WEBSITES


# =========================
#   ALERTS
# =========================

@app.get("/api/v1/alerts", response_model=List[Alert])
def list_alerts(limit: int = 10):
    """
    Letzte Alerts für die rechte Spalte.
    Parameter: ?limit=20
    """
    return FAKE_ALERTS[:limit]


# Root (optional) zum Testen
@app.get("/")
def root():
    return {"status": "ok", "service": "mxsec-api"}
