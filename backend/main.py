import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import aiosqlite
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from anomaly import AnomalyDetector
from simulator import TrafficSimulator
from validator import validate_dfa, validate_regex


DATABASE_PATH = Path(__file__).with_name("dns_logs.db")
detector = AnomalyDetector()
clients: set[WebSocket] = set()
db_lock = asyncio.Lock()
event_history: list[dict[str, Any]] = []
MAX_HISTORY = 500
stats = {
    "total_queries": 0,
    "valid_queries": 0,
    "blocked_malformed": 0,
    "threat_counts": {"NORMAL": 0, "SUSPICIOUS": 0, "MALFORMED": 0, "CRITICAL": 0},
    "record_counts": {},
}


async def init_db() -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                entropy REAL NOT NULL,
                status TEXT NOT NULL,
                anomaly_reason TEXT NOT NULL
            )"""
        )
        await db.commit()
        cursor = await db.execute(
            """SELECT COUNT(*),
            COALESCE(SUM(CASE WHEN status != 'MALFORMED' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status = 'MALFORMED' THEN 1 ELSE 0 END), 0)
            FROM dns_logs"""
        )
        total, valid, malformed = await cursor.fetchone()
        stats.update(
            total_queries=total,
            valid_queries=valid,
            blocked_malformed=malformed,
        )

        cursor = await db.execute(
            "SELECT status, COUNT(*) FROM dns_logs GROUP BY status"
        )
        stats["threat_counts"] = {
            "NORMAL": 0, "SUSPICIOUS": 0, "MALFORMED": 0, "CRITICAL": 0,
            **{status: count for status, count in await cursor.fetchall()},
        }
        cursor = await db.execute(
            "SELECT record_type, COUNT(*) FROM dns_logs GROUP BY record_type"
        )
        stats["record_counts"] = {
            record_type: count for record_type, count in await cursor.fetchall()
        }

        cursor = await db.execute(
            """SELECT timestamp, client_ip, domain, record_type, entropy, status, anomaly_reason
            FROM dns_logs ORDER BY id DESC LIMIT ?""",
            (MAX_HISTORY,),
        )
        stored_events = await cursor.fetchall()
        event_history.clear()
        for timestamp, client_ip, domain, record_type, entropy, status, reason in reversed(stored_events):
            event_history.append(
                {
                    "timestamp": timestamp,
                    "client_ip": client_ip,
                    "domain": domain,
                    "record_type": record_type,
                    "entropy": entropy,
                    "status": status,
                    "anomaly_reason": reason,
                    "is_valid": status != "MALFORMED",
                }
            )


async def persist_event(event: dict[str, Any]) -> None:
    async with db_lock:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                """INSERT INTO dns_logs
                (timestamp, client_ip, domain, record_type, entropy, status, anomaly_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["timestamp"],
                    event["client_ip"],
                    event["domain"],
                    event["record_type"],
                    event["entropy"],
                    event["status"],
                    event["anomaly_reason"],
                ),
            )
            await db.commit()


async def broadcast(event: dict[str, Any]) -> None:
    stale: list[WebSocket] = []
    payload = json.dumps({"type": "dns_event", "data": event})
    for websocket in list(clients):
        try:
            await websocket.send_text(payload)
        except (RuntimeError, WebSocketDisconnect):
            stale.append(websocket)
    for websocket in stale:
        clients.discard(websocket)


async def emit_query(query: dict[str, Any]) -> None:
    analysis = detector.analyze(query["domain"], query["client_ip"])
    valid = validate_regex(query["domain"])["is_valid"]
    event = {**query, **analysis, "is_valid": valid}
    await persist_event(event)
    event_history.append(event)
    if len(event_history) > MAX_HISTORY:
        del event_history[: len(event_history) - MAX_HISTORY]
    stats["total_queries"] += 1
    stats["valid_queries"] += int(valid)
    stats["blocked_malformed"] += int(not valid)
    stats["threat_counts"][event["status"]] += 1
    record_type = event["record_type"]
    stats["record_counts"][record_type] = stats["record_counts"].get(record_type, 0) + 1
    await broadcast(event)


simulator = TrafficSimulator(emit_query)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    simulator.start()
    yield
    simulator.pause()
    if simulator.task:
        simulator.task.cancel()
        try:
            await simulator.task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="DNS Query Analysis & Threat Detection", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ValidationRequest(BaseModel):
    domain: str


class StreamControlRequest(BaseModel):
    action: Literal["start", "pause", "burst"]


@app.post("/api/validate")
async def validate_domain(request: ValidationRequest) -> dict[str, Any]:
    regex_result = validate_regex(request.domain)
    dfa_result = validate_dfa(request.domain)
    return {
        "domain": request.domain,
        "regex": regex_result,
        "dfa": dfa_result,
        "engines_agree": regex_result["is_valid"] == dfa_result["is_valid"],
    }


@app.post("/api/stream/control")
async def control_stream(request: StreamControlRequest) -> dict[str, str]:
    action = request.action
    if action == "start":
        simulator.start()
        return {"status": "running", "message": "Traffic stream started."}
    if action == "pause":
        simulator.pause()
        return {"status": "paused", "message": "Traffic stream paused."}
    if action == "burst":
        asyncio.create_task(simulator.burst())
        return {"status": "burst_started", "message": "20-query attack burst injected."}


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    total = stats["total_queries"]
    return {
        **stats,
        "valid_percent": round(stats["valid_queries"] / total * 100, 1) if total else 0,
        "active_threat_alerts": stats["threat_counts"]["SUSPICIOUS"]
        + stats["threat_counts"]["CRITICAL"],
        "recent_events": event_history[-80:],
    }


@app.websocket("/ws/dns")
async def dns_websocket(websocket: WebSocket) -> None:
    await websocket.accept()
    clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)
