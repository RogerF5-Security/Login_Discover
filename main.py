#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Login Panel Discover

Requisitos:
    pip install customtkinter aiohttp beautifulsoup4 lxml

Uso:
    python main.py
    python main.py --self-test

Herramienta GUI para enumerar paneles de login/autenticacion mediante fuzzing de
rutas, analisis DOM y apertura rapida en navegador para validacion manual.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import queue
import random
import re
import sys
import threading
import time
import unicodedata
import webbrowser
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse

try:
    import aiohttp
except ImportError:  # pragma: no cover - handled at runtime
    aiohttp = None

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - handled at runtime
    BeautifulSoup = None

try:
    import customtkinter as ctk
except ImportError:  # pragma: no cover - handled at runtime
    ctk = None


APP_NAME = "Login Panel Discover"
APP_VERSION = "1.0.0"

DEFAULT_WORDLIST_TEXT = """
/
/login
/login/
/logon
/logon/
/signin
/signin/
/sign-in
/sign-in/
/sign_in
/auth
/auth/
/authenticate
/authentication
/account/login
/accounts/login
/users/login
/user/login
/members/login
/member/login
/session/new
/sessions/new
/portal
/portal/
/console
/console/
/dashboard
/dashboard/
/control
/control/
/manage
/manage/
/management
/management/
/manager
/manager/
/administrator
/administrator/
/admin
/admin/
/admin/login
/admin/login/
/admin/signin
/admin/auth
/admin/auth/login
/admin/index
/admin/index.php
/admin/index.html
/admin/login.php
/admin/login.html
/admin/login.jsp
/admin/login.aspx
/admin/login.asp
/admin/admin.php
/admin/admin.html
/admincp
/admincp/
/admincp/login
/admin_area
/admin_area/
/admin_area/login
/adminpanel
/adminpanel/
/admin-panel
/admin-panel/
/admin_portal
/admin_portal/
/admin-console
/admin-console/
/backend
/backend/
/backend/login
/backoffice
/backoffice/
/backoffice/login
/cms
/cms/
/cms/login
/cms/admin
/cmsadmin
/cmsadmin/
/siteadmin
/siteadmin/
/siteadmin/login
/webadmin
/webadmin/
/webadmin/login
/sysadmin
/sysadmin/
/sysadmin/login
/superadmin
/superadmin/
/superadmin/login
/root
/root/
/cpanel
/cpanel/
/cpanel/login
/whm
/whm/
/plesk
/plesk/
/login.html
/login.htm
/login.php
/login.jsp
/login.aspx
/login.asp
/login.cgi
/login.do
/login.action
/login.json
/signin.html
/signin.php
/auth/login
/auth/login/
/auth/signin
/auth/signin/
/login/auth
/login/auth/
/login/index
/login/index.php
/login/index.html
/index.php?login=1
/index.php/login
/index.php/admin
/index.php/user/login
/index.html
/main/login
/secure
/secure/
/secure/login
/private
/private/
/private/login
/member
/member/
/members
/members/
/user
/user/
/users
/users/
/account
/account/
/accounts
/accounts/
/profile/login
/client
/client/
/client/login
/customer
/customer/
/customer/login
/customers/login
/employee
/employee/
/employee/login
/staff
/staff/
/staff/login
/intranet
/intranet/
/intranet/login
/extranet
/extranet/
/extranet/login
/sso
/sso/
/sso/login
/oauth
/oauth/
/oauth/login
/oauth2
/oauth2/
/oauth2/authorize
/openid
/openid/
/idp
/idp/
/idp/login
/saml
/saml/
/saml/login
/adfs
/adfs/
/adfs/ls
/login/callback
/password
/password/
/password/login
/wp-login.php
/wp-admin
/wp-admin/
/wp-admin/admin.php
/wordpress/wp-login.php
/wordpress/wp-admin
/blog/wp-login.php
/blog/wp-admin
/site/wp-login.php
/site/wp-admin
/wp/wp-login.php
/wp/wp-admin
/joomla/administrator
/administrator/index.php
/administrator/login
/typo3
/typo3/
/typo3/index.php
/drupal/user/login
/user/login?destination=admin
/admin/people
/admin/content
/magento/admin
/index.php/admin
/index.php/backend
/admin_1
/admin123
/adminer
/adminer.php
/phpmyadmin
/phpmyadmin/
/phpMyAdmin
/phpMyAdmin/
/pma
/pma/
/mysql
/mysql/
/myadmin
/myadmin/
/dbadmin
/dbadmin/
/pgadmin
/pgadmin/
/pgadmin4
/pgadmin4/
/database
/database/
/db
/db/
/roundcube
/roundcube/
/webmail
/webmail/
/mail
/mail/
/owa
/owa/
/exchange
/exchange/
/ecp
/ecp/
/zimbra
/zimbra/
/horde
/horde/
/squirrelmail
/squirrelmail/
/iredadmin
/iredadmin/
/grafana
/grafana/
/grafana/login
/kibana
/kibana/
/kibana/login
/prometheus
/prometheus/
/alertmanager
/alertmanager/
/jenkins
/jenkins/
/jenkins/login
/jenkins/securityRealm/commenceLogin
/hudson
/hudson/
/teamcity
/teamcity/
/teamcity/login.html
/bamboo
/bamboo/
/jira
/jira/
/login.jsp
/confluence
/confluence/
/users/login.action
/bitbucket
/bitbucket/
/users/sign_in
/gitlab
/gitlab/
/gitlab/users/sign_in
/sonarqube
/sonarqube/
/sonar
/sonar/
/nexus
/nexus/
/nexus/#admin/security/users
/artifactory
/artifactory/
/harbor
/harbor/
/portainer
/portainer/
/portainer/#!/auth
/rancher
/rancher/
/rancher/dashboard/auth/login
/kubernetes
/kubernetes/
/k8s
/k8s/
/openshift
/openshift/
/oauth/authorize
/openshift-console
/openshift-console/
/argocd
/argocd/
/argo-cd
/argo-cd/
/dex/auth
/minio
/minio/
/minio/login
/ceph
/ceph/
/ceph/dashboard
/cockpit
/cockpit/
/cockpit/login
/webmin
/webmin/
/webmin/session_login.cgi
/usermin
/usermin/
/usermin/session_login.cgi
/ispconfig
/ispconfig/
/ispconfig/login
/directadmin
/directadmin/
/vesta
/vesta/
/vesta/login
/vestacp
/vestacp/
/cyberpanel
/cyberpanel/
/e107_admin
/e107_admin/
/matomo
/matomo/
/piwik
/piwik/
/owncloud
/owncloud/
/owncloud/index.php/login
/nextcloud
/nextcloud/
/nextcloud/index.php/login
/seafile
/seafile/
/accounts/login/
/guacamole
/guacamole/
/guacamole/#/
/guacamole/login
/noVNC
/noVNC/
/novnc
/novnc/
/vnc
/vnc/
/rdweb
/rdweb/
/RDWeb
/RDWeb/
/remote
/remote/
/remote/login
/remote/logincheck
/vpn
/vpn/
/vpn/index.html
/vpn/login.html
/vpn/tmindex.html
/vpn/index.php
/sslvpn
/sslvpn/
/sslvpn/login
/ssl-vpn
/ssl-vpn/
/global-protect/login.esp
/global-protect/portal
/global-protect
/dana-na/auth/url_default/welcome.cgi
/dana/html5acc/guacamole/
/remote/login?lang=en
/remote/fgt_lang
/+CSCOE+/logon.html
/+CSCOE+/saml/sp/login
/+CSCOE+/portal.html
/+webvpn+/index.html
/vpn/tmindex.html
/my.policy
/tmui/login.jsp
/tmui/
/tmui/Control/jspmap/tmui/login.jsp
/por/login_psw.csp
/sslvpnLogin.html
/sslvpn/sslvpnLogin.html
/vpnssl
/vpnssl/
/logon/LogonPoint/index.html
/Citrix/StoreWeb/
/Citrix/XenApp/
/citrix/storeweb
/citrix/xenapp
/owa/auth/logon.aspx
/ews
/mapi
/rpc
/autodiscover
/cgi-bin/login.cgi
/cgi-bin/login
/cgi-bin/admin.cgi
/cgi-bin/webproc
/cgi-bin/luci
/cgi-bin/luci/admin
/cgi-bin/luci/admin/status
/cgi-bin/index.cgi
/cgi-bin/mainfunction.cgi
/cgi-bin/userLogin.cgi
/cgi-bin/viewer/video.jpg
/cgi-bin/configManager.cgi
/login.cgi
/login.htm
/start.htm
/start.html
/home.htm
/home.html
/main.htm
/main.html
/status.htm
/status.html
/setup.htm
/setup.html
/setup.cgi
/admin.htm
/admin.html
/adm
/adm/
/boaform/admin/formLogin
/HNAP1/
/goform/login
/goform/formLogin
/goform/webLogin
/goform/SetLogin
/goform/Login
/goform/loginForm
/userRpm/LoginRpm.htm
/userRpm/Index.htm
/cgi-bin/luci/;stok=/locale
/webfig
/webfig/
/winbox
/winbox/
/router
/router/
/routerlogin
/routerlogin/
/routerlogin.net
/routerlogin.asp
/wlc
/wlc/
/wireless
/wireless/
/ap
/ap/
/switch
/switch/
/switch/login
/firewall
/firewall/
/firewall/login
/utm
/utm/
/utm/login
/fortinet
/fortinet/
/fortigate
/fortigate/
/sonicwall
/sonicwall/
/main.html
/auth.html
/admin/Login
/Admin/Login
/asp/login.asp
/login_sid.lua
/login_sid.xml
/apply.cgi
/index.asp
/index.htm
/doc/page/login.asp
/doc/page/login.asp?_1616824718074
/ISAPI/Security/userCheck
/SDK/webLanguage
/web/login
/web/login.html
/web/index.html
/ui/login
/ui/login.html
/ui/
/mobile/login
/mobile/
/api/login
/api/auth/login
/api/v1/login
/api/v1/auth/login
/api/v2/login
/api/v2/auth/login
/rest/login
/rest/auth/login
/json/login
/graphql
/graphql/console
/swagger
/swagger-ui
/swagger-ui.html
/api-docs
/openapi
/actuator
/actuator/env
/actuator/heapdump
/manager/html
/host-manager/html
/manager/status
/manager/text/list
/axis2-admin
/axis2/axis2-admin
/jmx-console
/web-console
/admin-console/login.seam
/console/App.html
/ibm/console
/ibm/console/login.do
/wlsconsole
/console/login/LoginForm.jsp
/em
/em/console/logon/logon
/orion
/orion/
/sap/bc/gui/sap/its/webgui
/sap/public/bc/icf/logoff
/sap/bc/bsp/sap/it00/default.htm
/irj/portal
/BOE/BI
/BOE/CMC
/InfoViewApp
/MicroStrategy/servlet/mstrWeb
/servlet/mstrWeb
/Tableau
/tableau
/superset
/superset/
/login/
/admin/
/auth/
/signin/
/portal/
/console/
/manage/
/dhcp/AXDHCPController2/#/login
/dhcp/AXDHCPController2/
/printers
/printers/
/printers/login
/printer
/printer/
/printer/login
/ipp
/ipp/
/ews/
/hp/device/this.LCDispatcher
/hp/device/SignIn/Index
/hp/jetdirect
/xerox
/xerox/
/centreware
/centreware/
/canon
/canon/
/ricoh
/ricoh/
/web/guest/en/websys/webArch/mainFrame.cgi
/dms
/dms/
/erp
/erp/
/crm
/crm/
/helpdesk
/helpdesk/
/otrs
/otrs/
/otrs/index.pl
/zabbix
/zabbix/
/zabbix/index.php
/nagios
/nagios/
/nagiosxi
/nagiosxi/
/icinga
/icinga/
/icingaweb2
/icingaweb2/
/cacti
/cacti/
/munin
/munin/
/observium
/observium/
/librenms
/librenms/
/graylog
/graylog/
/splunk
/splunk/
/en-US/account/login
/login?next=/
/login?redirect=/
/login?returnUrl=/
/login?ReturnUrl=/
/signin?next=/
/auth?next=/
/admin?login=1
"""

LOGIN_KEYWORDS = {
    "login",
    "log in",
    "log-in",
    "signin",
    "sign in",
    "sign-in",
    "sign_in",
    "auth",
    "authenticate",
    "authentication",
    "admin portal",
    "administrator",
    "control panel",
    "dashboard login",
    "iniciar sesion",
    "inicio de sesion",
    "acceder",
    "usuario",
    "contrasena",
    "password",
    "credential",
    "credentials",
    "account",
    "portal",
    "vpn",
    "sso",
    "secure access",
}

AUTH_PATH_HINTS = {
    "login",
    "logon",
    "signin",
    "sign-in",
    "sign_in",
    "auth",
    "admin",
    "administrator",
    "portal",
    "console",
    "manager",
    "manage",
    "dashboard",
    "cpanel",
    "vpn",
    "remote",
    "sso",
    "wp-login",
    "user/login",
    "accounts/login",
    "session",
}

USERNAME_FIELD_HINTS = {
    "user",
    "username",
    "user_name",
    "userid",
    "user_id",
    "login",
    "email",
    "mail",
    "account",
    "uid",
    "usuario",
    "correo",
    "j_username",
    "name",
}

PASSWORD_FIELD_HINTS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "contrasena",
    "clave",
    "j_password",
}

MODERN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
    "Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]


@dataclass(frozen=True)
class ScanConfig:
    concurrency: int = 25
    timeout: float = 5.0
    retries: int = 1
    verify_ssl: bool = False
    follow_redirects: bool = True
    user_agent_mode: str = "Rotativo moderno"
    custom_user_agent: str = ""
    max_body_bytes: int = 524288
    catch_all_probes: int = 2


@dataclass
class ScanFinding:
    target: str
    url: str
    status_code: int
    title: str
    confidence: str
    reason: str
    final_url: str
    matched_path: str
    response_time_ms: int
    response_length: int = 0


@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int
    final_url: str
    headers: dict[str, str]
    body: str
    response_length: int
    response_time_ms: int


@dataclass(frozen=True)
class ResponseProfile:
    status_code: int
    final_url_key: str
    title: str
    response_length: int
    text_digest: str
    form_digest: str
    structure_digest: str


def normalize_text(value: str) -> str:
    """Lowercase text and strip accents for language-agnostic matching."""
    normalized = unicodedata.normalize("NFKD", value or "")
    no_marks = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", no_marks.lower()).strip()


def clean_title(value: str) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value[:160] if value else "(sin titulo)"


def unique_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(key)
    return output


def default_wordlist() -> list[str]:
    return unique_preserve_order(
        line.strip()
        for line in DEFAULT_WORDLIST_TEXT.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def load_lines_from_file(path: str | Path) -> list[str]:
    loaded: list[str] = []
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        for raw in handle:
            item = raw.strip()
            if not item or item.startswith("#"):
                continue
            loaded.append(item)
    return unique_preserve_order(loaded)


def normalize_path(path: str) -> str:
    path = path.strip()
    if not path:
        return "/"
    if path.startswith(("http://", "https://")):
        return path
    if path.startswith(("/", "?", "#")):
        return path
    return f"/{path}"


def expand_targets(targets: Iterable[str]) -> list[tuple[str, str]]:
    expanded: list[tuple[str, str]] = []
    seen: set[str] = set()

    for raw_target in targets:
        raw_target = raw_target.strip()
        if not raw_target:
            continue

        candidates = [raw_target]
        if not re.match(r"^https?://", raw_target, flags=re.IGNORECASE):
            stripped = raw_target.strip("/")
            candidates = [f"https://{stripped}", f"http://{stripped}"]

        for candidate in candidates:
            parsed = urlparse(candidate)
            if not parsed.scheme or not parsed.netloc:
                continue
            path = parsed.path.rstrip("/")
            base = urlunparse((parsed.scheme.lower(), parsed.netloc, path, "", "", ""))
            key = base.lower()
            if key in seen:
                continue
            seen.add(key)
            expanded.append((raw_target, base))
    return expanded


def join_url(base_url: str, path: str) -> str:
    path = normalize_path(path)
    if path.startswith(("http://", "https://")):
        return path
    base = base_url.rstrip("/")
    if path.startswith("?"):
        return f"{base}/{path}"
    if path.startswith("#"):
        return f"{base}/{path}"
    return f"{base}{path}"


def has_auth_path_hint(value: str) -> bool:
    lowered = normalize_text(value)
    return any(hint in lowered for hint in AUTH_PATH_HINTS)


def attribute_blob(tag: Any) -> str:
    values: list[str] = []
    for attr in ("type", "name", "id", "placeholder", "aria-label", "autocomplete", "value"):
        raw = tag.get(attr)
        if raw:
            values.append(str(raw))
    return normalize_text(" ".join(values))


def parse_html(body: str) -> Any:
    if BeautifulSoup is None:
        raise RuntimeError("BeautifulSoup no esta instalado.")
    try:
        return BeautifulSoup(body, "lxml")
    except Exception:
        return BeautifulSoup(body, "html.parser")


def stable_digest(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:length]


def normalize_dynamic_tokens(value: str) -> str:
    value = normalize_text(value)
    value = re.sub(r"\b[a-f0-9]{16,}\b", "<hex>", value)
    value = re.sub(r"\b[a-z0-9_-]{24,}\b", "<token>", value)
    value = re.sub(r"\b\d{4,}\b", "<num>", value)
    return value


def response_length_close(left: int, right: int, ratio: float = 0.03, absolute: int = 180) -> bool:
    if left == right:
        return True
    return abs(left - right) <= max(absolute, int(max(left, right) * ratio))


def final_url_key(value: str) -> str:
    parsed = urlparse(value)
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", "", parsed.query, ""))


def form_structure_digest(soup: Any) -> str:
    signatures: list[str] = []
    for form in soup.find_all("form"):
        form_bits = [
            normalize_text(str(form.get("method", ""))),
            normalize_text(str(form.get("action", ""))),
            normalize_text(str(form.get("id", ""))),
            normalize_text(str(form.get("name", ""))),
        ]
        input_bits: list[str] = []
        for field in form.find_all(["input", "button", "select", "textarea"]):
            input_bits.append(
                "|".join(
                    normalize_text(str(field.get(attr, "")))
                    for attr in ("type", "name", "id", "autocomplete")
                )
            )
        signatures.append("::".join(form_bits + sorted(input_bits)))
    return stable_digest("\n".join(sorted(signatures))) if signatures else ""


def page_structure_digest(soup: Any) -> str:
    tags: list[str] = []
    for tag in soup.find_all(True, limit=250):
        name = normalize_text(getattr(tag, "name", ""))
        tag_id = normalize_text(str(tag.get("id", "")))
        classes = " ".join(sorted(normalize_text(str(item)) for item in tag.get("class", [])))
        tag_type = normalize_text(str(tag.get("type", "")))
        tags.append(f"{name}:{tag_id}:{classes}:{tag_type}")
    return stable_digest("\n".join(tags)) if tags else ""


def build_response_profile(snapshot: ResponseSnapshot) -> ResponseProfile:
    title = ""
    text_digest = ""
    form_digest = ""
    structure_digest = ""

    if snapshot.body:
        try:
            soup = parse_html(snapshot.body)
            title = clean_title(soup.title.get_text(" ", strip=True) if soup.title else "")
            visible_text = soup.get_text(" ", strip=True)[:12000]
            text_digest = stable_digest(normalize_dynamic_tokens(visible_text))
            form_digest = form_structure_digest(soup)
            structure_digest = page_structure_digest(soup)
        except Exception:
            text_digest = stable_digest(normalize_dynamic_tokens(snapshot.body[:12000]))

    return ResponseProfile(
        status_code=snapshot.status_code,
        final_url_key=final_url_key(snapshot.final_url),
        title=normalize_text(title),
        response_length=snapshot.response_length,
        text_digest=text_digest,
        form_digest=form_digest,
        structure_digest=structure_digest,
    )


def profiles_match_for_catch_all(left: ResponseProfile, right: ResponseProfile) -> bool:
    if left.status_code != right.status_code:
        return False
    if not response_length_close(left.response_length, right.response_length):
        return False
    if left.final_url_key == right.final_url_key:
        return True
    if left.title and right.title and left.title != right.title:
        return False
    if left.form_digest and left.form_digest == right.form_digest:
        return True
    if left.text_digest and left.text_digest == right.text_digest:
        return True
    if left.structure_digest and left.structure_digest == right.structure_digest:
        return True
    return False


def response_profile_key(profile: ResponseProfile) -> str:
    return "|".join(
        [
            str(profile.status_code),
            profile.title,
            str(profile.response_length // 128),
            profile.form_digest,
            profile.text_digest,
            profile.structure_digest,
        ]
    )


def analyze_login_page(
    *,
    target: str,
    url: str,
    final_url: str,
    matched_path: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
    response_time_ms: int,
    response_length: int,
) -> ScanFinding | None:
    reasons: list[str] = []
    normalized_url = normalize_text(f"{url} {final_url} {matched_path}")
    auth_header = ""
    for key, value in headers.items():
        if key.lower() == "www-authenticate":
            auth_header = value
            break

    if auth_header and any(token in normalize_text(auth_header) for token in ("basic", "digest", "bearer", "negotiate")):
        return ScanFinding(
            target=target,
            url=url,
            status_code=status_code,
            title="HTTP Authentication",
            confidence="Alto",
            reason="Cabecera WWW-Authenticate detectada",
            final_url=final_url,
            matched_path=matched_path,
            response_time_ms=response_time_ms,
            response_length=response_length,
        )

    if not body:
        if status_code in {401, 403} and has_auth_path_hint(normalized_url):
            return ScanFinding(
                target=target,
                url=url,
                status_code=status_code,
                title="Acceso restringido",
                confidence="Medio",
                reason=f"Status {status_code} en ruta de autenticacion",
                final_url=final_url,
                matched_path=matched_path,
                response_time_ms=response_time_ms,
                response_length=response_length,
            )
        return None

    soup = parse_html(body)
    title = clean_title(soup.title.get_text(" ", strip=True) if soup.title else "")
    normalized_title = normalize_text(title)

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    buttons = soup.find_all(["button", "input"])
    scripts = soup.find_all("script")
    app_roots = soup.select("[id*=app], [id*=root], [data-reactroot], [ng-app], [data-v-app]")

    input_blobs = [attribute_blob(tag) for tag in inputs]
    button_blobs = [attribute_blob(tag) + " " + normalize_text(tag.get_text(" ", strip=True)) for tag in buttons]
    form_blobs = [normalize_text(f"{form.get('action', '')} {form.get('id', '')} {form.get('name', '')}") for form in forms]

    password_found = any(
        "type password" in blob
        or "password" in blob
        or any(hint in blob.split() for hint in PASSWORD_FIELD_HINTS)
        for blob in input_blobs
    )
    username_found = any(any(hint in blob for hint in USERNAME_FIELD_HINTS) for blob in input_blobs)
    submit_login_found = any(
        any(keyword in blob for keyword in ("login", "sign in", "signin", "acceder", "entrar", "submit"))
        for blob in button_blobs
    )
    form_action_auth = any(has_auth_path_hint(blob) for blob in form_blobs)

    body_text = ""
    if soup.body:
        body_text = soup.body.get_text(" ", strip=True)
    else:
        body_text = soup.get_text(" ", strip=True)
    normalized_body = normalize_text(body_text[:80000])
    keyword_hits = sorted(
        keyword
        for keyword in LOGIN_KEYWORDS
        if keyword in normalized_title or keyword in normalized_body or keyword in normalized_url
    )

    if forms:
        reasons.append(f"{len(forms)} formulario(s)")
    if password_found:
        reasons.append("input password")
    if username_found:
        reasons.append("campo usuario/email")
    if submit_login_found:
        reasons.append("boton de acceso")
    if form_action_auth:
        reasons.append("action/id de formulario asociado a auth")
    if keyword_hits:
        reasons.append("keywords: " + ", ".join(keyword_hits[:5]))

    if password_found and (forms or username_found or submit_login_found or keyword_hits):
        return ScanFinding(
            target=target,
            url=url,
            status_code=status_code,
            title=title,
            confidence="Alto",
            reason="; ".join(reasons[:6]),
            final_url=final_url,
            matched_path=matched_path,
            response_time_ms=response_time_ms,
            response_length=response_length,
        )

    if forms and (username_found or submit_login_found or form_action_auth or keyword_hits):
        return ScanFinding(
            target=target,
            url=url,
            status_code=status_code,
            title=title,
            confidence="Medio",
            reason="; ".join(reasons[:6]),
            final_url=final_url,
            matched_path=matched_path,
            response_time_ms=response_time_ms,
            response_length=response_length,
        )

    spa_like = bool(scripts and app_roots)
    if has_auth_path_hint(normalized_url) and keyword_hits and (spa_like or status_code in {200, 401, 403}):
        spa_reason = "ruta auth con keywords"
        if spa_like:
            spa_reason += "; posible SPA"
        return ScanFinding(
            target=target,
            url=url,
            status_code=status_code,
            title=title,
            confidence="Medio",
            reason=spa_reason,
            final_url=final_url,
            matched_path=matched_path,
            response_time_ms=response_time_ms,
            response_length=response_length,
        )

    if status_code in {401, 403} and has_auth_path_hint(normalized_url):
        return ScanFinding(
            target=target,
            url=url,
            status_code=status_code,
            title=title,
            confidence="Medio",
            reason=f"Status {status_code} en ruta de autenticacion",
            final_url=final_url,
            matched_path=matched_path,
            response_time_ms=response_time_ms,
            response_length=response_length,
        )

    return None


class LoginPanelScanner:
    def __init__(
        self,
        *,
        targets: list[str],
        paths: list[str],
        config: ScanConfig,
        event_queue: queue.Queue[tuple[str, dict[str, Any]]],
        pause_event: threading.Event,
        stop_event: threading.Event,
    ) -> None:
        if aiohttp is None:
            raise RuntimeError("aiohttp no esta instalado. Ejecuta: pip install aiohttp")
        self.targets = targets
        self.paths = unique_preserve_order(normalize_path(path) for path in paths)
        self.config = config
        self.event_queue = event_queue
        self.pause_event = pause_event
        self.stop_event = stop_event
        self.completed = 0
        self.total = 0
        self.findings = 0
        self.suppressed = 0
        self.errors = 0
        self.started_at = time.monotonic()
        self._last_progress_emit = 0.0
        self.catch_all_profiles: dict[str, list[ResponseProfile]] = {}
        self.seen_catch_all_signatures: set[tuple[str, str]] = set()
        self.seen_final_destinations: set[tuple[str, str]] = set()

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        self.event_queue.put((event_type, payload))

    async def run(self) -> None:
        base_targets = expand_targets(self.targets)
        self.total = len(base_targets) * len(self.paths)
        self.started_at = time.monotonic()
        self.emit(
            "started",
            {
                "total": self.total,
                "targets": len(base_targets),
                "paths": len(self.paths),
                "concurrency": self.config.concurrency,
            },
        )

        if not base_targets or not self.paths:
            self.emit("done", self.summary("sin trabajo"))
            return

        timeout = aiohttp.ClientTimeout(total=self.config.timeout, connect=self.config.timeout)
        connector = aiohttp.TCPConnector(
            limit=self.config.concurrency,
            ssl=self.config.verify_ssl,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        cookie_jar = aiohttp.CookieJar(unsafe=True)

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            cookie_jar=cookie_jar,
            trust_env=True,
        ) as session:
            await self.prepare_catch_all_baselines(session, base_targets)
            jobs: asyncio.Queue[tuple[str, str, str] | None] = asyncio.Queue(
                maxsize=max(self.config.concurrency * 4, 10)
            )
            workers = [
                asyncio.create_task(self.worker(worker_id, jobs, session))
                for worker_id in range(self.config.concurrency)
            ]
            await self.producer(jobs, base_targets)
            await jobs.join()
            await asyncio.gather(*workers, return_exceptions=True)

        status = "detenido" if self.stop_event.is_set() else "completado"
        self.emit("progress", self.progress_payload())
        self.emit("done", self.summary(status))

    async def producer(
        self,
        jobs: asyncio.Queue[tuple[str, str, str] | None],
        base_targets: list[tuple[str, str]],
    ) -> None:
        for target_label, base_url in base_targets:
            if self.stop_event.is_set():
                break
            for path in self.paths:
                if self.stop_event.is_set():
                    break
                await jobs.put((target_label, base_url, path))

        for _ in range(self.config.concurrency):
            await jobs.put(None)

    async def worker(
        self,
        worker_id: int,
        jobs: asyncio.Queue[tuple[str, str, str] | None],
        session: Any,
    ) -> None:
        while True:
            job = await jobs.get()
            try:
                if job is None:
                    return
                await self.wait_if_paused()
                if self.stop_event.is_set():
                    continue

                target_label, base_url, path = job
                url = join_url(base_url, path)
                finding = await self.fetch_with_retries(session, target_label, base_url, url, path)
                if finding:
                    self.findings += 1
                    self.emit("finding", asdict(finding))
            finally:
                self.completed += 1 if job is not None else 0
                self.emit_progress_throttled()
                jobs.task_done()

    async def wait_if_paused(self) -> None:
        while self.pause_event.is_set() and not self.stop_event.is_set():
            await asyncio.sleep(0.2)

    def request_headers(self) -> dict[str, str]:
        if self.config.user_agent_mode == "Personalizado" and self.config.custom_user_agent.strip():
            user_agent = self.config.custom_user_agent.strip()
        elif self.config.user_agent_mode == "Chrome Windows":
            user_agent = MODERN_USER_AGENTS[0]
        elif self.config.user_agent_mode == "Firefox Windows":
            user_agent = MODERN_USER_AGENTS[1]
        elif self.config.user_agent_mode == "Edge Windows":
            user_agent = MODERN_USER_AGENTS[2]
        else:
            user_agent = random.choice(MODERN_USER_AGENTS)

        return {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

    async def prepare_catch_all_baselines(
        self,
        session: Any,
        base_targets: list[tuple[str, str]],
    ) -> None:
        if self.config.catch_all_probes <= 0:
            return

        self.emit("status", {"message": "Generando baselines anti-falso-positivo por target..."})
        semaphore = asyncio.Semaphore(max(1, min(self.config.concurrency, 20)))

        async def collect_for_base(base_url: str) -> None:
            async with semaphore:
                profiles: list[ResponseProfile] = []
                for _ in range(self.config.catch_all_probes):
                    if self.stop_event.is_set():
                        break
                    probe = f"/__login_discover_probe_{int(time.time() * 1000)}_{random.randint(100000, 999999)}"
                    snapshot = await self.request_snapshot(session, join_url(base_url, probe))
                    if snapshot:
                        profiles.append(build_response_profile(snapshot))
                if profiles:
                    self.catch_all_profiles[base_url] = profiles

        await asyncio.gather(*(collect_for_base(base_url) for _target, base_url in base_targets))

    async def fetch_with_retries(
        self,
        session: Any,
        target_label: str,
        base_url: str,
        url: str,
        path: str,
    ) -> ScanFinding | None:
        snapshot = await self.request_snapshot(session, url)
        if not snapshot:
            return None

        finding = analyze_login_page(
            target=target_label,
            url=url,
            final_url=snapshot.final_url,
            matched_path=path,
            status_code=snapshot.status_code,
            headers=snapshot.headers,
            body=snapshot.body,
            response_time_ms=snapshot.response_time_ms,
            response_length=snapshot.response_length,
        )
        if finding and self.should_suppress_finding(base_url, path, snapshot, finding):
            return None
        return finding

    async def request_snapshot(self, session: Any, url: str) -> ResponseSnapshot | None:
        attempts = max(self.config.retries, 0) + 1
        last_error: str | None = None

        for attempt in range(attempts):
            if self.stop_event.is_set():
                return None
            try:
                started = time.monotonic()
                async with session.get(
                    url,
                    headers=self.request_headers(),
                    allow_redirects=self.config.follow_redirects,
                ) as response:
                    raw = await response.content.read(self.config.max_body_bytes)
                    elapsed_ms = int((time.monotonic() - started) * 1000)

                    if response.status in {429, 500, 502, 503, 504} and attempt < attempts - 1:
                        await asyncio.sleep(0.25 * (attempt + 1))
                        continue

                    charset = response.charset or "utf-8"
                    body = raw.decode(charset, errors="replace")
                    headers = {str(k): str(v) for k, v in response.headers.items()}
                    return ResponseSnapshot(
                        status_code=response.status,
                        final_url=str(response.url),
                        headers=headers,
                        body=body,
                        response_length=len(raw),
                        response_time_ms=elapsed_ms,
                    )
            except (asyncio.TimeoutError, aiohttp.ClientError, UnicodeError) as exc:
                last_error = exc.__class__.__name__
                if attempt < attempts - 1:
                    await asyncio.sleep(0.25 * (attempt + 1))
                    continue
            except Exception as exc:  # network parsers can fail in noisy real targets
                last_error = f"{exc.__class__.__name__}: {exc}"
                break

        self.errors += 1
        if self.errors <= 5 or self.errors % 50 == 0:
            self.emit("status", {"message": f"Errores de red/parsing: {self.errors} ({last_error})"})
        return None

    def should_suppress_finding(
        self,
        base_url: str,
        path: str,
        snapshot: ResponseSnapshot,
        finding: ScanFinding,
    ) -> bool:
        profile = build_response_profile(snapshot)
        normalized_path = normalize_path(path)
        baseline_profiles = self.catch_all_profiles.get(base_url, [])
        matches_catch_all = any(
            profiles_match_for_catch_all(profile, baseline)
            for baseline in baseline_profiles
        )

        if matches_catch_all:
            signature = (base_url, response_profile_key(profile))
            if signature in self.seen_catch_all_signatures:
                self.suppressed += 1
                if self.suppressed <= 5 or self.suppressed % 25 == 0:
                    self.emit(
                        "status",
                        {
                            "message": (
                                f"Filtrados por catch-all/redirect comun: {self.suppressed} "
                                f"({finding.url})"
                            )
                        },
                    )
                return True

            self.seen_catch_all_signatures.add(signature)
            finding.confidence = "Medio" if finding.confidence == "Alto" else finding.confidence
            if normalized_path not in {"/", ""}:
                finding.reason = f"{finding.reason}; posible catch-all, primer representante conservado"
            return False

        destination_key = (base_url, profile.final_url_key)
        if profile.final_url_key != final_url_key(join_url(base_url, path)):
            if destination_key in self.seen_final_destinations:
                self.suppressed += 1
                return True
            self.seen_final_destinations.add(destination_key)
            finding.reason = f"{finding.reason}; redireccion consolidada"

        return False

    def emit_progress_throttled(self) -> None:
        now = time.monotonic()
        if now - self._last_progress_emit >= 0.25 or self.completed >= self.total:
            self._last_progress_emit = now
            self.emit("progress", self.progress_payload())

    def progress_payload(self) -> dict[str, Any]:
        elapsed = max(time.monotonic() - self.started_at, 0.001)
        return {
            "completed": self.completed,
            "total": self.total,
            "findings": self.findings,
            "suppressed": self.suppressed,
            "errors": self.errors,
            "rps": self.completed / elapsed,
            "elapsed": elapsed,
        }

    def summary(self, status: str) -> dict[str, Any]:
        payload = self.progress_payload()
        payload["status"] = status
        return payload


class LoginDiscoverApp(ctk.CTk if ctk else object):
    def __init__(self) -> None:
        if ctk is None:
            raise RuntimeError("customtkinter no esta instalado. Ejecuta: pip install customtkinter")
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1280x780")
        self.minsize(1100, 680)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.targets: list[str] = []
        self.paths: list[str] = default_wordlist()
        self.results: list[dict[str, Any]] = []
        self.result_by_iid: dict[str, dict[str, Any]] = {}

        self.event_queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue()
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.scan_thread: threading.Thread | None = None
        self.scanning = False

        self.concurrency_var = ctk.IntVar(value=25)
        self.timeout_var = ctk.IntVar(value=5)
        self.retries_var = ctk.IntVar(value=1)
        self.verify_ssl_var = ctk.BooleanVar(value=False)
        self.combine_wordlist_var = ctk.BooleanVar(value=True)
        self.ua_mode_var = ctk.StringVar(value="Rotativo moderno")

        self.configure(fg_color="#0f1117")
        self.build_layout()
        self.after(100, self.process_events)

    def build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=330, corner_radius=8, fg_color="#161a23")
        self.sidebar.grid(row=0, column=0, padx=14, pady=14, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content.grid(row=0, column=1, padx=(0, 14), pady=14, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(2, weight=1)

        self.build_sidebar()
        self.build_status_area()
        self.build_table()
        self.build_detail_area()

    def build_sidebar(self) -> None:
        title = ctk.CTkLabel(
            self.sidebar,
            text=APP_NAME,
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="w",
        )
        title.grid(row=0, column=0, padx=18, pady=(18, 4), sticky="ew")

        subtitle = ctk.CTkLabel(
            self.sidebar,
            text="Enumeracion de Login/Auth Panels",
            text_color="#9aa4b2",
            anchor="w",
        )
        subtitle.grid(row=1, column=0, padx=18, pady=(0, 18), sticky="ew")

        self.targets_label = ctk.CTkLabel(self.sidebar, text="Targets: 0", anchor="w")
        self.targets_label.grid(row=2, column=0, padx=18, pady=(4, 6), sticky="ew")
        ctk.CTkButton(
            self.sidebar,
            text="Cargar targets.txt",
            command=self.load_targets,
            height=36,
            corner_radius=8,
        ).grid(row=3, column=0, padx=18, pady=(0, 12), sticky="ew")

        self.wordlist_label = ctk.CTkLabel(self.sidebar, text=f"Rutas: {len(self.paths)}", anchor="w")
        self.wordlist_label.grid(row=4, column=0, padx=18, pady=(2, 6), sticky="ew")
        ctk.CTkCheckBox(
            self.sidebar,
            text="Combinar con lista interna",
            variable=self.combine_wordlist_var,
            corner_radius=5,
        ).grid(row=5, column=0, padx=18, pady=(0, 8), sticky="w")
        ctk.CTkButton(
            self.sidebar,
            text="Cargar wordlist.txt",
            command=self.load_wordlist,
            height=36,
            corner_radius=8,
        ).grid(row=6, column=0, padx=18, pady=(0, 18), sticky="ew")

        self.add_slider(
            parent=self.sidebar,
            row=7,
            label="Concurrencia",
            var=self.concurrency_var,
            from_=10,
            to=50,
        )
        self.add_slider(
            parent=self.sidebar,
            row=9,
            label="Timeout (s)",
            var=self.timeout_var,
            from_=2,
            to=30,
        )
        self.add_slider(
            parent=self.sidebar,
            row=11,
            label="Retries",
            var=self.retries_var,
            from_=0,
            to=5,
        )

        ctk.CTkSwitch(
            self.sidebar,
            text="Verificar SSL",
            variable=self.verify_ssl_var,
            progress_color="#3b82f6",
        ).grid(row=13, column=0, padx=18, pady=(12, 10), sticky="w")

        ctk.CTkLabel(self.sidebar, text="User-Agent", anchor="w").grid(
            row=14, column=0, padx=18, pady=(4, 6), sticky="ew"
        )
        ctk.CTkOptionMenu(
            self.sidebar,
            variable=self.ua_mode_var,
            values=["Rotativo moderno", "Chrome Windows", "Firefox Windows", "Edge Windows", "Personalizado"],
            command=self.on_user_agent_mode_changed,
            height=34,
            corner_radius=8,
        ).grid(row=15, column=0, padx=18, pady=(0, 8), sticky="ew")
        self.custom_ua_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text="User-Agent personalizado",
            height=34,
            corner_radius=8,
        )
        self.custom_ua_entry.grid(row=16, column=0, padx=18, pady=(0, 18), sticky="ew")
        self.custom_ua_entry.configure(state="disabled")

        self.start_button = ctk.CTkButton(
            self.sidebar,
            text="Iniciar Escaneo",
            command=self.start_scan,
            height=40,
            corner_radius=8,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
        )
        self.start_button.grid(row=17, column=0, padx=18, pady=(8, 8), sticky="ew")

        self.pause_button = ctk.CTkButton(
            self.sidebar,
            text="Pausar",
            command=self.toggle_pause,
            height=36,
            corner_radius=8,
            state="disabled",
            fg_color="#475569",
            hover_color="#334155",
        )
        self.pause_button.grid(row=18, column=0, padx=18, pady=(0, 8), sticky="ew")

        self.stop_button = ctk.CTkButton(
            self.sidebar,
            text="Detener",
            command=self.stop_scan,
            height=36,
            corner_radius=8,
            state="disabled",
            fg_color="#991b1b",
            hover_color="#7f1d1d",
        )
        self.stop_button.grid(row=19, column=0, padx=18, pady=(0, 8), sticky="ew")

        self.export_button = ctk.CTkButton(
            self.sidebar,
            text="Exportar Resultados",
            command=self.export_results,
            height=36,
            corner_radius=8,
            fg_color="#166534",
            hover_color="#14532d",
        )
        self.export_button.grid(row=20, column=0, padx=18, pady=(0, 8), sticky="ew")

        self.open_button = ctk.CTkButton(
            self.sidebar,
            text="Abrir en Navegador",
            command=self.open_selected_result,
            height=36,
            corner_radius=8,
            fg_color="#334155",
            hover_color="#1f2937",
        )
        self.open_button.grid(row=21, column=0, padx=18, pady=(0, 18), sticky="ew")

        self.sidebar.grid_rowconfigure(22, weight=1)

    def add_slider(self, parent: Any, row: int, label: str, var: Any, from_: int, to: int) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=row, column=0, padx=18, pady=(2, 0), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=label, anchor="w").grid(row=0, column=0, sticky="ew")
        value_label = ctk.CTkLabel(header, text=str(var.get()), text_color="#93c5fd", width=42)
        value_label.grid(row=0, column=1, sticky="e")

        def on_change(value: float) -> None:
            int_value = int(round(value))
            var.set(int_value)
            value_label.configure(text=str(int_value))

        ctk.CTkSlider(
            parent,
            from_=from_,
            to=to,
            number_of_steps=to - from_,
            variable=var,
            command=on_change,
            progress_color="#3b82f6",
        ).grid(row=row + 1, column=0, padx=18, pady=(0, 12), sticky="ew")

    def build_status_area(self) -> None:
        status_frame = ctk.CTkFrame(self.content, corner_radius=8, fg_color="#161a23")
        status_frame.grid(row=0, column=0, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_columnconfigure(1, weight=0)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Listo",
            anchor="w",
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.status_label.grid(row=0, column=0, padx=16, pady=(12, 4), sticky="ew")

        self.metric_label = ctk.CTkLabel(
            status_frame,
            text="0/0 | 0.00 req/s | Hallazgos: 0",
            text_color="#9aa4b2",
            anchor="e",
        )
        self.metric_label.grid(row=0, column=1, padx=16, pady=(12, 4), sticky="e")

        self.progress = ctk.CTkProgressBar(status_frame, height=12, corner_radius=8, progress_color="#22c55e")
        self.progress.grid(row=1, column=0, columnspan=2, padx=16, pady=(4, 14), sticky="ew")
        self.progress.set(0)

    def build_table(self) -> None:
        table_frame = ctk.CTkFrame(self.content, corner_radius=8, fg_color="#111827")
        table_frame.grid(row=2, column=0, pady=(12, 12), sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Login.Treeview",
            background="#111827",
            foreground="#e5e7eb",
            fieldbackground="#111827",
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Login.Treeview.Heading",
            background="#1f2937",
            foreground="#e5e7eb",
            borderwidth=0,
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Login.Treeview", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])

        columns = ("target", "url", "status", "title", "confidence")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            style="Login.Treeview",
            selectmode="browse",
        )
        headings = {
            "target": "Target",
            "url": "URL Encontrada",
            "status": "Status Code",
            "title": "Titulo de la Pagina",
            "confidence": "Nivel de Confianza",
        }
        widths = {
            "target": 170,
            "url": 420,
            "status": 95,
            "title": 260,
            "confidence": 140,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], minwidth=80, stretch=column in {"url", "title"})

        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        self.tree.bind("<Double-1>", lambda _event: self.open_selected_result())
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_detail_from_selection())

    def build_detail_area(self) -> None:
        detail_frame = ctk.CTkFrame(self.content, corner_radius=8, fg_color="#161a23")
        detail_frame.grid(row=3, column=0, sticky="ew")
        detail_frame.grid_columnconfigure(0, weight=1)

        self.detail_text = ctk.CTkTextbox(
            detail_frame,
            height=96,
            corner_radius=8,
            fg_color="#0f1117",
            border_width=1,
            border_color="#263041",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.detail_text.grid(row=0, column=0, padx=12, pady=12, sticky="ew")
        self.detail_text.insert("1.0", "Selecciona un hallazgo para ver URL final, path y razon de confianza.")
        self.detail_text.configure(state="disabled")

    def on_user_agent_mode_changed(self, value: str) -> None:
        if value == "Personalizado":
            self.custom_ua_entry.configure(state="normal")
        else:
            self.custom_ua_entry.configure(state="disabled")

    def load_targets(self) -> None:
        path = filedialog.askopenfilename(
            title="Seleccionar targets.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            self.targets = load_lines_from_file(path)
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo cargar targets:\n{exc}")
            return
        self.targets_label.configure(text=f"Targets: {len(self.targets)}")
        self.status_label.configure(text=f"Targets cargados: {Path(path).name}")

    def load_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Seleccionar wordlist.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            custom_paths = [normalize_path(item) for item in load_lines_from_file(path)]
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo cargar wordlist:\n{exc}")
            return

        if self.combine_wordlist_var.get():
            self.paths = unique_preserve_order(default_wordlist() + custom_paths)
        else:
            self.paths = unique_preserve_order(custom_paths)

        self.wordlist_label.configure(text=f"Rutas: {len(self.paths)}")
        self.status_label.configure(text=f"Wordlist cargada: {Path(path).name}")

    def build_config(self) -> ScanConfig:
        return ScanConfig(
            concurrency=max(1, int(self.concurrency_var.get())),
            timeout=max(1, int(self.timeout_var.get())),
            retries=max(0, int(self.retries_var.get())),
            verify_ssl=bool(self.verify_ssl_var.get()),
            user_agent_mode=self.ua_mode_var.get(),
            custom_user_agent=self.custom_ua_entry.get().strip(),
        )

    def start_scan(self) -> None:
        if self.scanning:
            return
        if not self.targets:
            messagebox.showwarning(APP_NAME, "Carga primero un archivo de targets.")
            return
        if not self.paths:
            messagebox.showwarning(APP_NAME, "La wordlist esta vacia.")
            return
        if aiohttp is None or BeautifulSoup is None:
            messagebox.showerror(
                APP_NAME,
                "Faltan dependencias. Ejecuta:\npip install customtkinter aiohttp beautifulsoup4 lxml",
            )
            return

        self.results.clear()
        self.result_by_iid.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.pause_event.clear()
        self.stop_event.clear()
        self.scanning = True
        self.set_scan_controls(active=True)
        self.progress.set(0)
        self.status_label.configure(text="Inicializando escaneo...")
        self.metric_label.configure(text="0/0 | 0.00 req/s | Hallazgos: 0 | Filtrados: 0")
        self.write_detail("Escaneo iniciado.")

        scanner = LoginPanelScanner(
            targets=self.targets,
            paths=self.paths,
            config=self.build_config(),
            event_queue=self.event_queue,
            pause_event=self.pause_event,
            stop_event=self.stop_event,
        )

        self.scan_thread = threading.Thread(target=self.run_scanner_thread, args=(scanner,), daemon=True)
        self.scan_thread.start()

    def run_scanner_thread(self, scanner: LoginPanelScanner) -> None:
        try:
            asyncio.run(scanner.run())
        except Exception as exc:
            self.event_queue.put(("error", {"message": f"{exc.__class__.__name__}: {exc}"}))
            self.event_queue.put(("done", {"status": "error", "completed": 0, "total": 0, "findings": 0, "errors": 1, "rps": 0.0}))

    def set_scan_controls(self, *, active: bool) -> None:
        self.start_button.configure(state="disabled" if active else "normal")
        self.pause_button.configure(state="normal" if active else "disabled", text="Pausar")
        self.stop_button.configure(state="normal" if active else "disabled")

    def toggle_pause(self) -> None:
        if not self.scanning:
            return
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.pause_button.configure(text="Pausar")
            self.status_label.configure(text="Escaneo reanudado")
        else:
            self.pause_event.set()
            self.pause_button.configure(text="Continuar")
            self.status_label.configure(text="Escaneo pausado")

    def stop_scan(self) -> None:
        if not self.scanning:
            return
        self.stop_event.set()
        self.pause_event.clear()
        self.status_label.configure(text="Deteniendo...")
        self.stop_button.configure(state="disabled")

    def process_events(self) -> None:
        try:
            while True:
                event_type, payload = self.event_queue.get_nowait()
                if event_type == "started":
                    self.on_scan_started(payload)
                elif event_type == "finding":
                    self.add_finding(payload)
                elif event_type == "progress":
                    self.update_progress(payload)
                elif event_type == "status":
                    self.status_label.configure(text=payload.get("message", "Estado actualizado"))
                elif event_type == "error":
                    self.status_label.configure(text=payload.get("message", "Error"))
                    self.write_detail(payload.get("message", "Error"))
                elif event_type == "done":
                    self.on_scan_done(payload)
        except queue.Empty:
            pass
        self.after(100, self.process_events)

    def on_scan_started(self, payload: dict[str, Any]) -> None:
        total = payload.get("total", 0)
        targets = payload.get("targets", 0)
        paths = payload.get("paths", 0)
        concurrency = payload.get("concurrency", 0)
        self.status_label.configure(text=f"Escaneando {targets} base URLs x {paths} rutas")
        self.metric_label.configure(text=f"0/{total} | 0.00 req/s | Hallazgos: 0 | Filtrados: 0 | C:{concurrency}")

    def update_progress(self, payload: dict[str, Any]) -> None:
        total = int(payload.get("total") or 0)
        completed = int(payload.get("completed") or 0)
        findings = int(payload.get("findings") or 0)
        suppressed = int(payload.get("suppressed") or 0)
        errors = int(payload.get("errors") or 0)
        rps = float(payload.get("rps") or 0.0)
        progress = min(completed / total, 1.0) if total else 0.0
        self.progress.set(progress)
        self.metric_label.configure(
            text=f"{completed}/{total} | {rps:.2f} req/s | Hallazgos: {findings} | Filtrados: {suppressed} | Errores: {errors}"
        )

    def on_scan_done(self, payload: dict[str, Any]) -> None:
        self.scanning = False
        self.set_scan_controls(active=False)
        status = payload.get("status", "completado")
        completed = int(payload.get("completed") or 0)
        total = int(payload.get("total") or 0)
        findings = int(payload.get("findings") or len(self.results))
        suppressed = int(payload.get("suppressed") or 0)
        errors = int(payload.get("errors") or 0)
        rps = float(payload.get("rps") or 0.0)
        self.progress.set(1 if total and completed >= total else self.progress.get())
        self.status_label.configure(text=f"Escaneo {status}")
        self.metric_label.configure(
            text=f"{completed}/{total} | {rps:.2f} req/s | Hallazgos: {findings} | Filtrados: {suppressed} | Errores: {errors}"
        )
        self.write_detail(f"Escaneo {status}. Hallazgos: {findings}. Filtrados: {suppressed}. Errores: {errors}.")

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.results.append(finding)
        iid = str(len(self.results))
        self.result_by_iid[iid] = finding
        values = (
            finding.get("target", ""),
            finding.get("url", ""),
            finding.get("status_code", ""),
            finding.get("title", ""),
            finding.get("confidence", ""),
        )
        tag = "high" if finding.get("confidence") == "Alto" else "medium"
        self.tree.insert("", "end", iid=iid, values=values, tags=(tag,))
        self.tree.tag_configure("high", foreground="#fecaca")
        self.tree.tag_configure("medium", foreground="#fde68a")
        self.status_label.configure(text=f"Hallazgo: {finding.get('url', '')}")

    def selected_finding(self) -> dict[str, Any] | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return self.result_by_iid.get(selection[0])

    def update_detail_from_selection(self) -> None:
        finding = self.selected_finding()
        if not finding:
            return
        detail = (
            f"URL: {finding.get('url', '')}\n"
            f"Final: {finding.get('final_url', '')}\n"
            f"Target: {finding.get('target', '')}\n"
            f"Path: {finding.get('matched_path', '')}\n"
            f"Status: {finding.get('status_code', '')} | Confianza: {finding.get('confidence', '')} | "
            f"RTT: {finding.get('response_time_ms', '')} ms | Length: {finding.get('response_length', '')} bytes\n"
            f"Razon: {finding.get('reason', '')}"
        )
        self.write_detail(detail)

    def write_detail(self, text: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def open_selected_result(self) -> None:
        finding = self.selected_finding()
        if not finding:
            messagebox.showinfo(APP_NAME, "Selecciona un hallazgo primero.")
            return
        url = finding.get("final_url") or finding.get("url")
        if url:
            webbrowser.open(url)

    def export_results(self) -> None:
        if not self.results:
            messagebox.showinfo(APP_NAME, "No hay resultados para exportar.")
            return

        path = filedialog.asksaveasfilename(
            title="Exportar resultados",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return

        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(self.results, handle, ensure_ascii=False, indent=2)
            else:
                fieldnames = [
                    "target",
                    "url",
                    "status_code",
                    "title",
                    "confidence",
                    "reason",
                    "final_url",
                    "matched_path",
                    "response_time_ms",
                    "response_length",
                ]
                with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows({key: row.get(key, "") for key in fieldnames} for row in self.results)
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo exportar:\n{exc}")
            return

        self.status_label.configure(text=f"Resultados exportados: {Path(path).name}")


def run_self_test() -> int:
    missing = []
    if BeautifulSoup is None:
        missing.append("beautifulsoup4")
    if missing:
        print("Faltan dependencias para self-test: " + ", ".join(missing))
        print("Ejecuta: pip install customtkinter aiohttp beautifulsoup4 lxml")
        return 2

    login_html = """
    <html><head><title>Admin Portal Login</title></head>
    <body><form action="/login"><input name="username"><input type="password" id="password">
    <button type="submit">Sign In</button></form></body></html>
    """
    spa_html = """
    <html><head><title>Secure Sign In</title></head>
    <body><div id="app"></div><script src="/assets/app.js"></script></body></html>
    """
    normal_html = "<html><head><title>Welcome</title></head><body><h1>Home</h1></body></html>"

    high = analyze_login_page(
        target="example.com",
        url="https://example.com/admin/login",
        final_url="https://example.com/admin/login",
        matched_path="/admin/login",
        status_code=200,
        headers={},
        body=login_html,
        response_time_ms=12,
        response_length=len(login_html.encode("utf-8")),
    )
    medium = analyze_login_page(
        target="example.com",
        url="https://example.com/login",
        final_url="https://example.com/login",
        matched_path="/login",
        status_code=200,
        headers={},
        body=spa_html,
        response_time_ms=10,
        response_length=len(spa_html.encode("utf-8")),
    )
    none = analyze_login_page(
        target="example.com",
        url="https://example.com/",
        final_url="https://example.com/",
        matched_path="/",
        status_code=200,
        headers={},
        body=normal_html,
        response_time_ms=8,
        response_length=len(normal_html.encode("utf-8")),
    )
    baseline_profile = build_response_profile(
        ResponseSnapshot(
            status_code=200,
            final_url="https://example.com/__missing_probe",
            headers={},
            body=login_html,
            response_length=len(login_html.encode("utf-8")),
            response_time_ms=11,
        )
    )
    catch_all_profile = build_response_profile(
        ResponseSnapshot(
            status_code=200,
            final_url="https://example.com/signin",
            headers={},
            body=login_html.replace("123456", "999999"),
            response_length=len(login_html.encode("utf-8")),
            response_time_ms=10,
        )
    )

    checks = [
        ("login form high confidence", high is not None and high.confidence == "Alto"),
        ("spa login medium confidence", medium is not None and medium.confidence == "Medio"),
        ("normal page ignored", none is None),
        ("default wordlist has hundreds", len(default_wordlist()) >= 200),
        ("target expansion", len(expand_targets(["example.com", "https://app.local/base"])) == 3),
        ("catch-all fingerprint match", profiles_match_for_catch_all(catch_all_profile, baseline_profile)),
    ]

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
    if failed:
        return 1
    print("Self-test completado correctamente.")
    return 0


def verify_runtime_dependencies() -> list[str]:
    missing = []
    if ctk is None:
        missing.append("customtkinter")
    if aiohttp is None:
        missing.append("aiohttp")
    if BeautifulSoup is None:
        missing.append("beautifulsoup4")
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--self-test", action="store_true", help="Ejecuta pruebas locales sin red ni GUI.")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    missing = verify_runtime_dependencies()
    if missing:
        print("Faltan dependencias: " + ", ".join(missing), file=sys.stderr)
        print("Ejecuta: pip install customtkinter aiohttp beautifulsoup4 lxml", file=sys.stderr)
        return 2

    app = LoginDiscoverApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
