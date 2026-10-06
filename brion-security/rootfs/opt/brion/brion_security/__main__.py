"""Entry point: python3 -m brion_security"""
import sys

import uvicorn

from . import logsafe, settings
from .app import create_app


def main() -> int:
    cfg = settings.load()
    logsafe.setup(cfg.log_level)
    uvicorn.run(create_app(cfg), host=cfg.bind_host, port=cfg.port, log_config=None, access_log=False,
                server_header=False, proxy_headers=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
