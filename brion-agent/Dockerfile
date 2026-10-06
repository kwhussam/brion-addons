ARG BUILD_FROM
FROM ${BUILD_FROM}

# WireGuard-Werkzeuge und iproute2 für das Tunnel-Interface. Bewusst KEIN nmap:
# der Netzwerkscan gehört ausschließlich zum Add-on Brion Security.
RUN apk add --no-cache wireguard-tools-wg iproute2

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

# brion_core is vendored into rootfs/opt/brion by scripts/sync-core.sh
COPY rootfs /
RUN test -f /opt/brion/brion_core/__init__.py \
    && chmod a+x /etc/s6-overlay/s6-rc.d/brion-agent/run /etc/s6-overlay/s6-rc.d/brion-agent/finish \
    && python3 -m compileall -q /opt/brion

ENV PYTHONPATH=/opt/brion PYTHONUNBUFFERED=1
