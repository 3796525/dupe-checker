"""Entrypoint: uvicorn app.web:app with guard enforcement at import time."""
from __future__ import annotations

import logging
import os

import uvicorn

from app.config import config

if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run(
        "app.web:app",
        host=config.host,
        port=config.port,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        access_log=True,
    )
