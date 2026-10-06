"""TR-064 client for AVM FRITZ!Box (read-only queries).

* Description (/tr64desc.xml) and GetSecurityPort need no login.
* Authenticated calls use HTTP Digest; the hash is computed directly from the
  Secret's bytearray, so the router password never becomes a Python string and
  is never sent over the network. After GetSecurityPort the client switches to
  HTTPS (self-signed router certificate, LAN only).
* Only "Get*" actions are allowed – the client cannot change router settings,
  and never requests WLAN keys (GetSecurityKeys is blocked).
"""
from __future__ import annotations

import hashlib
import http.client
import logging
import os
import re
import ssl
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .sensitive import Secret

LOG = logging.getLogger("brion.security.tr064")
MAX_BODY = 2 * 1024 * 1024
MAX_HOSTS = 256
MAX_MAPPINGS = 128
BLOCKED_ACTIONS = {"GetSecurityKeys", "X_AVM-DE_GetWLANHybridMode", "X_AVM-DE_GetWPSInfo"}
_DS = "urn:dslforum-org:service:"


class Tr064Error(Exception):
    pass


class Tr064Unavailable(Tr064Error):
    pass


class Tr064AuthError(Tr064Error):
    pass


@dataclass
class RouterInfo:
    host: Optional[str] = None
    reachable: bool = False
    tr064: bool = False
    authenticated: bool = False
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    update_available: Optional[bool] = None
    upnp_enabled: Optional[bool] = None
    remote_access_enabled: Optional[bool] = None
    myfritz_enabled: Optional[bool] = None
    port_mappings: Optional[List[Dict[str, Any]]] = None
    wifi: Optional[List[Dict[str, Any]]] = None
    hosts: Optional[List[Dict[str, Any]]] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_text(el: ET.Element, name: str) -> Optional[str]:
    for child in el.iter():
        if _local(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def wifi_security(beacon: Optional[str], basic_enc: Optional[str]) -> str:
    b = (beacon or "").strip()
    if b in ("None", "Basic", ""):
        if (basic_enc or "None") in ("None", ""):
            return "OPEN" if b else "UNKNOWN"
        return "WEP"
    return {"WPA": "WPA", "11i": "WPA2", "WPAand11i": "WPA_WPA2", "11iandWPA3": "WPA2_WPA3",
            "WPA3": "WPA3"}.get(b, "UNKNOWN")


class _Digest:
    """RFC 2617 digest (MD5, qop=auth) computed from a Secret."""

    def __init__(self, username: str, password: Secret) -> None:
        self.username, self.password, self.nc = username, password, 0

    def header(self, challenge: str, method: str, uri: str) -> str:
        params = dict(re.findall(r'(\w+)="?([^",]*)"?', challenge))
        realm, nonce = params.get("realm", ""), params.get("nonce", "")
        if not nonce or params.get("algorithm", "MD5").upper() not in ("MD5", ""):
            raise Tr064AuthError("unsupported digest challenge")
        h1 = hashlib.md5()
        h1.update(f"{self.username}:{realm}:".encode())
        self.password.feed(h1)
        ha1 = h1.hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        self.nc += 1
        nc, cnonce = f"{self.nc:08x}", os.urandom(8).hex()
        qop = "auth" if "auth" in params.get("qop", "auth").split(",") else ""
        if qop:
            resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        else:
            resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        out = (f'Digest username="{self.username}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
               f'response="{resp}", algorithm=MD5')
        if qop:
            out += f', qop={qop}, nc={nc}, cnonce="{cnonce}"'
        if "opaque" in params:
            out += f', opaque="{params["opaque"]}"'
        return out


class Tr064Client:
    def __init__(self, host: str, username: str = "", password: Optional[Secret] = None,
                 port: int = 49000, timeout: float = 8.0) -> None:
        if not re.match(r"^[0-9A-Za-z.:-]{1,253}$", host):
            raise Tr064Error("invalid router host")
        self.host, self.port, self.timeout = host, port, timeout
        self.username = username or ""
        self.password = password
        self.services: Dict[str, str] = {}
        self.secure_port: Optional[int] = None

    # ------------------------------------------------------------ transport
    def _conn(self, secure: bool) -> http.client.HTTPConnection:
        if secure and self.secure_port:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # FRITZ!Box uses a self-signed certificate (LAN only)
            return http.client.HTTPSConnection(self.host, self.secure_port, timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _request(self, method: str, path: str, body: bytes = b"", headers: Optional[Dict[str, str]] = None,
                 auth: bool = False) -> bytes:
        headers = dict(headers or {})
        digest = _Digest(self.username, self.password) if auth and self.password else None
        for attempt in range(2):
            conn = self._conn(secure=auth)
            try:
                conn.request(method, path, body=body or None, headers=headers)
                resp = conn.getresponse()
                data = resp.read(MAX_BODY + 1)
            except (OSError, http.client.HTTPException) as exc:
                raise Tr064Unavailable(f"router not reachable ({type(exc).__name__})") from None
            finally:
                conn.close()
            if len(data) > MAX_BODY:
                raise Tr064Error("router response too large")
            if resp.status == 401 and digest and attempt == 0:
                challenge = resp.getheader("WWW-Authenticate", "")
                if not challenge.lower().startswith("digest"):
                    raise Tr064AuthError("router did not offer digest authentication")
                headers["Authorization"] = digest.header(challenge, method, path)
                continue
            if resp.status == 401:
                raise Tr064AuthError("router rejected the credentials")
            if resp.status >= 400:
                try:
                    fault = _find_text(ET.fromstring(data), "errorDescription") if data.startswith(b"<") else None
                except ET.ParseError:
                    fault = None
                raise Tr064Error(f"HTTP {resp.status}{': ' + fault if fault else ''}")
            return data
        raise Tr064AuthError("authentication failed")

    # -------------------------------------------------------------- api
    def describe(self) -> Dict[str, Optional[str]]:
        data = self._request("GET", "/tr64desc.xml")
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            raise Tr064Unavailable("no TR-064 description") from None
        for svc in root.iter():
            if _local(svc.tag) == "service":
                st, url = _find_text(svc, "serviceType"), _find_text(svc, "controlURL")
                if st and url:
                    self.services[st] = url
        version = None
        for el in root.iter():
            if _local(el.tag) == "systemVersion":
                version = _find_text(el, "Display")
        return {"manufacturer": _find_text(root, "manufacturer"), "model": _find_text(root, "modelName"),
                "friendly_name": _find_text(root, "friendlyName"), "firmware": version}

    def has(self, service: str) -> bool:
        return service in self.services

    def call(self, service: str, action: str, args: Optional[Dict[str, Any]] = None, auth: bool = True) -> Dict[str, str]:
        if not action.startswith(("Get", "X_AVM-DE_Get")) or action in BLOCKED_ACTIONS:
            raise Tr064Error(f"action {action} is not allowed (read-only client)")
        url = self.services.get(service)
        if not url:
            raise Tr064Error(f"service {service} not offered by router")
        arg_xml = "".join(f"<{k}>{_xml_escape(str(v))}</{k}>" for k, v in (args or {}).items())
        body = ('<?xml version="1.0" encoding="utf-8"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:{action} xmlns:u="{service}">{arg_xml}</u:{action}></s:Body></s:Envelope>').encode()
        data = self._request("POST", url, body, {"Content-Type": 'text/xml; charset="utf-8"',
                                                 "SOAPACTION": f'"{service}#{action}"'}, auth=auth)
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            raise Tr064Error("unparseable SOAP response") from None
        out = {}
        for el in root.iter():
            if _local(el.tag).endswith("Response"):
                for child in el:
                    out[_local(child.tag)] = (child.text or "").strip()
        return out


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _flag(v: Optional[str]) -> Optional[bool]:
    return None if v is None else v.strip() in ("1", "true", "True")


def collect(host: str, username: str = "", password: Optional[Secret] = None, port: int = 49000,
            timeout: float = 8.0) -> RouterInfo:
    """Gather everything the rules need. Each sub-query may fail independently (-> None/unknown)."""
    info = RouterInfo(host=host)
    client = Tr064Client(host, username, password, port, timeout)
    try:
        desc = client.describe()
    except Tr064Error as exc:
        info.errors.append(f"description: {exc}")
        return info
    info.reachable = info.tr064 = True
    info.manufacturer, info.model, info.firmware = desc["manufacturer"], desc["model"], desc["firmware"]
    try:
        info_port = client.call(_DS + "DeviceInfo:1", "GetSecurityPort", auth=False)
        client.secure_port = int(info_port.get("NewSecurityPort") or 0) or None
    except (Tr064Error, ValueError) as exc:
        info.errors.append(f"security port: {exc}")
    if not password:
        info.errors.append("no router credentials supplied")
        return info

    def q(service: str, action: str, args: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, str]]:
        if not client.has(service):
            return None
        try:
            return client.call(service, action, args)
        except Tr064AuthError:
            raise
        except Tr064Error as exc:
            info.errors.append(f"{action}: {exc}")
            return None

    try:
        dev = q(_DS + "DeviceInfo:1", "GetInfo")
        info.authenticated = dev is not None
        if dev:
            info.model = dev.get("NewModelName") or info.model
            info.firmware = dev.get("NewSoftwareVersion") or info.firmware
        ui = q(_DS + "UserInterface:1", "GetInfo")
        if ui:
            info.update_available = _flag(ui.get("NewUpgradeAvailable"))
        upnp = q(_DS + "X_AVM-DE_UPnP:1", "GetInfo")
        if upnp:
            info.upnp_enabled = _flag(upnp.get("NewEnable"))
        ra = q(_DS + "X_AVM-DE_RemoteAccess:1", "GetInfo")
        if ra:
            info.remote_access_enabled = _flag(ra.get("NewEnabled"))
        mf = q(_DS + "X_AVM-DE_MyFritz:1", "GetInfo")
        if mf:
            info.myfritz_enabled = _flag(mf.get("NewEnabled"))
        # WLAN (2.4 GHz, 5 GHz, Gast) – nur Typ/Status, niemals Schlüssel
        wifi = []
        for idx in (1, 2, 3, 4):
            w = q(f"{_DS}WLANConfiguration:{idx}", "GetInfo")
            if w is None:
                continue
            wifi.append({"index": idx, "ssid": w.get("NewSSID"), "enabled": _flag(w.get("NewEnable")),
                         "standard": w.get("NewStandard"),
                         "security": wifi_security(w.get("NewBeaconType"), w.get("NewBasicEncryptionModes"))})
        info.wifi = wifi if wifi else None
        # bekannte Hosts
        hn = q(_DS + "Hosts:1", "GetHostNumberOfEntries")
        if hn is not None:
            hosts = []
            for i in range(min(int(hn.get("NewHostNumberOfEntries") or 0), MAX_HOSTS)):
                e = q(_DS + "Hosts:1", "GetGenericHostEntry", {"NewIndex": i})
                if e:
                    hosts.append({"ip": e.get("NewIPAddress") or None, "mac": (e.get("NewMACAddress") or "").lower() or None,
                                  "name": e.get("NewHostName"), "active": _flag(e.get("NewActive"))})
            info.hosts = hosts
        # Portfreigaben (WAN-Verbindung: PPP bei DSL, IP bei Kabel/Glasfaser)
        for svc in (_DS + "WANPPPConnection:1", _DS + "WANIPConnection:1"):
            n = q(svc, "GetPortMappingNumberOfEntries")
            if n is None:
                continue
            maps = []
            for i in range(min(int(n.get("NewPortMappingNumberOfEntries") or 0), MAX_MAPPINGS)):
                m = q(svc, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
                if m:
                    maps.append({"external_port": int(m.get("NewExternalPort") or 0),
                                 "internal_client": m.get("NewInternalClient"),
                                 "internal_port": int(m.get("NewInternalPort") or 0),
                                 "protocol": m.get("NewProtocol"), "enabled": _flag(m.get("NewEnabled")),
                                 "description": m.get("NewPortMappingDescription")})
            info.port_mappings = (info.port_mappings or []) + maps
    except Tr064AuthError as exc:
        info.authenticated = False
        info.errors.append(f"authentication: {exc}")
    return info


def probe_model(host: str, timeout: float = 3.0) -> Optional[str]:
    """Unauthenticated model probe for the status page (e.g. 'FRITZ!Box 7590')."""
    try:
        return Tr064Client(host, timeout=timeout).describe().get("model")
    except Tr064Error:
        return None
