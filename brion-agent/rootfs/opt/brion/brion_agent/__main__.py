import logging
import signal
import sys
import threading

from . import __version__, settings
from .api import serve
from .lifecycle import Lifecycle
from .service import Agent

LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}


def main() -> int:
    cfg = settings.load()
    level = LEVELS.get(str(cfg.options().get("log_level", "info")), logging.INFO)
    logging.basicConfig(level=level, stream=sys.stdout, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("brion")
    agent = Agent(cfg)
    lifecycle = Lifecycle(agent)
    agent.lifecycle = lifecycle
    try:
        lifecycle.boot()
    except Exception:
        log.exception("boot sequence failed - background loop keeps enforcing fail-closed policy")
    agent.run_background()
    servers = [serve(agent, lifecycle, "lan")]
    try:
        servers.append(serve(agent, lifecycle, "ingress"))
    except OSError as exc:
        log.error("ingress listener unavailable (%s) - web UI disabled", exc)

    def stop(*_):
        agent.stop()
        for s in servers:
            threading.Thread(target=s.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    log.info("Brion Agent %s: API %s:%s, UI %s:%s", __version__, cfg.api_host, cfg.api_port,
             cfg.ingress_host, cfg.ingress_port)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
