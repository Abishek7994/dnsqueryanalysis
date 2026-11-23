import asyncio
import random
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable


class TrafficSimulator:
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "PTR"]
    NORMAL_DOMAINS = [
        "www.example.com",
        "api.github.com",
        "mail.google.com",
        "cdn.cloudflare.net",
        "ns1.example.org",
        "shop.example.co",
        "assets.microsoft.com",
        "status.python.org",
        "4.3.2.1.in-addr.arpa",
    ]
    MALFORMED_DOMAINS = [
        "-bad.example.com",
        "bad..example.com",
        "bad_label.example.com",
        "trailing-.example.net",
        "invalid-domain",
    ]
    DGA_DOMAINS = [
        "xj4k9q2m8v7n3p1a.example.com",
        "a8f3d9c2b7e1q5z6.tunnel.example.net",
        "dns-payload-" + "7a9c2e4f6b8d1a3c" * 4 + ".example.org",
        "sub.one.two.three.four.five.example.com",
    ]

    def __init__(self, emit: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        self.emit = emit
        self.running = False
        self.task: asyncio.Task[None] | None = None
        self.clients = [f"192.0.2.{number}" for number in range(10, 25)]

    def start(self) -> None:
        self.running = True
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._run())

    def pause(self) -> None:
        self.running = False

    async def burst(self) -> None:
        for index in range(20):
            await self.emit(self._make_query(attack=True, index=index))
            await asyncio.sleep(0.06)

    async def _run(self) -> None:
        while True:
            if self.running:
                await self.emit(self._make_query())
                await asyncio.sleep(random.uniform(0.35, 0.9))
            else:
                await asyncio.sleep(0.2)

    def _make_query(self, attack: bool = False, index: int = 0) -> dict[str, Any]:
        category = random.choices(
            ["normal", "malformed", "attack"], weights=[0.78, 0.1, 0.12]
        )[0]
        if attack:
            domain = random.choice(self.DGA_DOMAINS)
            client_ip = "198.51.100.77"
        elif category == "malformed":
            domain = random.choice(self.MALFORMED_DOMAINS)
            client_ip = random.choice(self.clients)
        elif category == "attack":
            domain = random.choice(self.DGA_DOMAINS)
            client_ip = random.choice(self.clients)
        else:
            domain = random.choice(self.NORMAL_DOMAINS)
            client_ip = random.choice(self.clients)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "domain": domain,
            "record_type": random.choice(self.RECORD_TYPES),
            "burst_index": index if attack else None,
        }
