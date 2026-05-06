"""FastAPI web UI + CSV download."""

from __future__ import annotations

import argparse
import re
import threading
import webbrowser
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pcf_inventory_extractor.client import CfProgrammaticAuthError
from pcf_inventory_extractor.extraction import ExtractConfig, default_output_name
from pcf_inventory_extractor.run import run_extraction

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = REPO_ROOT / "templates"
STATIC = REPO_ROOT / "static"
_TEMPL: Jinja2Templates | None = None


def get_templates() -> Jinja2Templates:
    global _TEMPL
    if _TEMPL is None:
        _TEMPL = Jinja2Templates(directory=str(TEMPLATES))
    return _TEMPL


def sanitize_output_filename(filename: str) -> str:
    """Extract just the filename component, reject paths."""
    # Remove any path components
    name = filename.strip()
    # Reject if contains path separators
    if '/' in name or '\\' in name or name.startswith('.'):
        raise HTTPException(
            status_code=400,
            detail="Invalid output filename. Only simple filenames are allowed (no paths)."
        )
    # Additional sanitization
    name = re.sub(r'[/\\:*?"<>|\x00-\x1f]', '_', name)
    if not name or name == '.':
        raise HTTPException(status_code=400, detail="Invalid output filename.")
    return name


def create_app() -> FastAPI:
    app = FastAPI(
        title="pcf-inventory-extractor",
        description="CF v3 org metadata to CSV (same as extract-pcf-inventory).",
    )

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Any:
        # Starlette 1.x: TemplateResponse(request, name, context)
        return get_templates().TemplateResponse(
            request,
            "index.html",
            {
                "default_hint": "Leave blank to use "
                f"{default_output_name('<org>')} in the server process working directory",
            },
        )

    @app.get("/help", response_class=HTMLResponse)
    def help_page(request: Request) -> Any:
        return get_templates().TemplateResponse(request, "help.html", {})

    @app.post("/extract")
    def do_extract(
        org_name: str = Form(..., min_length=1, description="CF org name"),
        cf_api_url: str = Form(..., min_length=1, description="CF API URL (cf login -a)"),
        cf_username: str = Form(..., min_length=1, description="CF username"),
        cf_password: str = Form(..., min_length=1, description="CF password"),
        output_path: str = Form(""),
        debug: str | None = Form(default=None),
        disable_ssl_verify: str | None = Form(default=None),
        no_env_vars: str | None = Form(default=None),
    ) -> FileResponse:
        org = org_name.strip()
        if not org:
            raise HTTPException(
                status_code=400,
                detail="Organization name is required and cannot be only whitespace.",
            )
        is_debug = (debug or "").strip().lower() in ("on", "true", "1", "yes")
        is_ssl_disabled = (disable_ssl_verify or "").strip().lower() in ("on", "true", "1", "yes")
        https_verify = not is_ssl_disabled  # Invert: checkbox is "disable", config is "verify"
        is_skip_env_vars = (no_env_vars or "").strip().lower() in ("on", "true", "1", "yes")

        o = (output_path or "").strip()
        if o:
            # Validate that it's just a filename, not a path
            safe_filename = sanitize_output_filename(o)
            out = Path(safe_filename)
        else:
            out = Path(default_output_name(org))
        cfg = ExtractConfig(
            org_name=org,
            output_path=out.resolve(),
            debug=is_debug,
            cf_api_url=cf_api_url.strip(),
            cf_username=cf_username.strip(),
            cf_password=cf_password,
            https_verify=https_verify,
            skip_env_vars=is_skip_env_vars,
        )
        try:
            run_extraction(cfg)
        except CfProgrammaticAuthError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        p = out.resolve()
        return FileResponse(
            path=str(p),
            media_type="text/csv; charset=utf-8",
            filename=p.name,
        )

    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    return app


def _url_for_browser(host: str, port: int) -> str:
    """Host/port the app binds to; return a URL a local browser can open."""
    h = (host or "").strip()
    if h in ("0.0.0.0", ""):
        h = "127.0.0.1"
    elif h in ("::", "[::]"):
        h = "127.0.0.1"
    elif ":" in h and not h.startswith("["):
        h = f"[{h}]"
    return f"http://{h}:{port}/"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the app URL in the default browser after the server starts.",
    )
    a = parser.parse_args()
    app = create_app()
    if a.open:
        url = _url_for_browser(a.host, a.port)
        threading.Timer(0.4, lambda u=url: webbrowser.open(u)).start()
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")
