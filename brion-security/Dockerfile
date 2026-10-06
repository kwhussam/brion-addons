ARG BUILD_FROM
FROM ${BUILD_FROM}

ARG WITH_PDF=1
# nmap: lokale Erkennung/Portprüfung; pango+Fonts nur für WeasyPrint
RUN apk add --no-cache nmap \
    && if [ "$WITH_PDF" = "1" ]; then apk add --no-cache pango font-dejavu; fi

COPY requirements.txt /tmp/requirements.txt
RUN if [ "$WITH_PDF" = "1" ]; then pip install --no-cache-dir -r /tmp/requirements.txt; \
    else grep -v -i weasyprint /tmp/requirements.txt > /tmp/req.txt && pip install --no-cache-dir -r /tmp/req.txt; fi \
    && rm -f /tmp/requirements.txt /tmp/req.txt

COPY rootfs /
COPY config /opt/brion/config
RUN chmod a+x /etc/s6-overlay/s6-rc.d/brion-security/run /etc/s6-overlay/s6-rc.d/brion-security/finish \
    && python3 -m compileall -q /opt/brion/brion_security

ENV PYTHONPATH=/opt/brion PYTHONUNBUFFERED=1
