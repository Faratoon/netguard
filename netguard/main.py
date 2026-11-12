"""NetGuard application entrypoint."""
from __future__ import annotations

import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import admin, controls, devices, dns, media, network
from .config import load_config
from .db import TrafficSample, get_engine
from .state import STATE

STATIC_DIR = __import__("pathlib").Path(__file__).resolve().parent / "static"


def _sampler_loop(stop_event: threading.Event) -> None:
    """Periodically collect traffic samples from the router."""
    from sqlalchemy.orm import sessionmaker

    interval = max(STATE.config.monitoring.sample_interval_seconds, 30)
    while not stop_event.wait(interval):
        try:
            engine = get_engine()
            Session = sessionmaker(bind=engine, expire_on_commit=False)
            with Session() as session:
                from .api.network import collect_sample

                collect_sample(session)
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    STATE.boot()
    _start_dns_filter()
    stop_event = threading.Event()
    thread = threading.Thread(target=_sampler_loop, args=(stop_event,), daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop_event.set()
        if STATE.dns_filter is not None:
            STATE.dns_filter.stop()


def _start_dns_filter() -> None:
    """Start NetGuard's DNS filter server (blocking DNS for the whole LAN)."""
    from sqlalchemy.orm import sessionmaker

    from .services.dnsfilter import DnsFilterServer

    cfg = STATE.config.dns_filter
    if not cfg.enabled:
        return
    try:
        factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    except Exception:
        return
    server = DnsFilterServer(
        host=cfg.host,
        port=cfg.port,
        upstream=cfg.upstream,
        session_factory=factory,
        default_categories=set(STATE.config.filtering.default_block_categories),
        log_blocks=cfg.log_blocks,
    )
    STATE.dns_filter = server
    server.start()
    if not server._threads:
        print(f"[netguard] DNS filter not started: {server.error}")


app = FastAPI(
    title="NetGuard",
    description="Open source router / network administration, monitoring and parental control dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)


def verify_token(x_netguard_token: str | None = Header(default=None)) -> None:
    """Optional API token protection (enabled by setting api_token)."""
    expected = STATE.config.api_token
    if expected and x_netguard_token != expected:
        raise HTTPException(status_code=401, detail="invalid or missing X-NetGuard-Token header")


app.include_router(devices.router, dependencies=[Depends(verify_token)])
app.include_router(controls.router, dependencies=[Depends(verify_token)])
app.include_router(network.router, dependencies=[Depends(verify_token)])
app.include_router(dns.router, dependencies=[Depends(verify_token)])
app.include_router(admin.router, dependencies=[Depends(verify_token)])
app.include_router(media.router, dependencies=[Depends(verify_token)])


@app.get("/health", tags=["meta"])
def health() -> dict[str, object]:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/version", tags=["meta"])
def version() -> dict[str, str]:
    from . import __version__

    return {"version": __version__, "name": "NetGuard"}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {exc}"})


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    cfg = load_config()
    uvicorn.run("netguard.main:app", host=cfg.host, port=cfg.port, reload=False)
