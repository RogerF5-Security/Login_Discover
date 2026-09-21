#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Intruder - Auditor CLI de formularios de login

Requisitos:
    pip install requests rich

Ejemplos:
    python Intruder.py --self-test
    python Intruder.py -r login_request.txt -w users.txt -w passwords.txt --attack pitchfork --grep "Invalid password"
    python Intruder.py -r login_request.txt -w passwords.txt --attack sniper --max-requests 100 --audit-limit 15 --delay 0.3 --url-encode

La peticion debe contener posiciones delimitadas con el caracter §:
    username=§admin§&password=§123456§
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import html as html_lib
import itertools
import queue
import re
import statistics
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Iterable, Iterator, Pattern, Sequence
from urllib.parse import parse_qsl, quote_plus, urljoin, urlparse, urlunparse

import requests

try:
    import customtkinter as ctk
except ImportError:  # pragma: no cover - GUI dependency
    ctk = None

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - GUI/form parser dependency
    BeautifulSoup = None

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
except ImportError:  # pragma: no cover - fallback para entornos minimos
    Console = None
    Live = None
    Table = None


APP_NAME = "Intruder"
APP_VERSION = "1.2.0"

DEFAULT_USER_WORDLIST = [
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "support",
    "operator",
    "manager",
    "sysadmin",
    "security",
    "auditor",
    "roger",
    "demo",
    "service",
]

DEFAULT_PASSWORD_WORDLIST = [
    "admin",
    "admin123",
    "password",
    "Password1",
    "123456",
    "12345678",
    "qwerty123",
    "letmein",
    "welcome1",
    "changeme",
    "P@ssw0rd",
    "Summer2026!",
    "Winter2026!",
    "Test1234",
    "Company2026!",
]

ATTACK_MODE_DESCRIPTIONS = {
    "sniper": (
        "SNIPER: prueba una posicion a la vez. Mantiene los demas campos con su valor base. "
        "Util para validar que parametro modifica la respuesta."
    ),
    "battering-ram": (
        "BATTERING RAM: usa el mismo payload en todas las posiciones marcadas simultaneamente. "
        "Util cuando usuario y clave deben recibir el mismo valor de prueba."
    ),
    "pitchfork": (
        "PITCHFORK: avanza listas en paralelo. Usuario[i] se combina con Password[i]. "
        "Util para pares conocidos o listas alineadas."
    ),
    "cluster-bomb": (
        "CLUSTER BOMB: ejecuta el producto cartesiano de las listas. "
        "Util para cubrir todas las combinaciones usuario x password."
    ),
}

CSRF_SIGNATURES = re.compile(
    r"(csrf|xsrf|anti[-_]?csrf|authenticity_token|requestverificationtoken|__requestverificationtoken|nonce)",
    re.IGNORECASE,
)
CAPTCHA_SIGNATURES = re.compile(
    r"(recaptcha|g-recaptcha|hcaptcha|cf-turnstile|turnstile\.render|captcha|arkose|funcaptcha)",
    re.IGNORECASE,
)
MFA_SIGNATURES = re.compile(
    r"(mfa|2fa|two[-\s]?factor|multi[-\s]?factor|otp|one[-\s]?time|verification code|authenticator|duo|webauthn|passkey)",
    re.IGNORECASE,
)
LOCKOUT_SIGNATURES = re.compile(
    r"(too many|rate limit|429|locked|account locked|temporarily blocked|try again later|"
    r"captcha|required verification|demasiad[oa]s intentos|intentos fallidos|bloquead[oa]|15 minutos)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Marker:
    index: int
    base_value: str
    location: str


@dataclass(frozen=True)
class RenderedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: str


@dataclass(frozen=True)
class AttackJob:
    request_id: int
    payloads: tuple[str, ...]
    payload_summary: str


@dataclass(frozen=True)
class AttackResult:
    request_id: int
    payload_summary: str
    status_code: int
    length: int
    grep_match: str
    elapsed_ms: int
    lockout_hint: bool
    error: str = ""


@dataclass(frozen=True)
class ResponseTimingStats:
    count: int
    minimum_ms: int
    maximum_ms: int
    mean_ms: float
    median_ms: float
    p95_ms: int
    stdev_ms: float
    coefficient_variation_pct: float
    first_window_median_ms: float
    last_window_median_ms: float
    trend_delta_ms: float
    trend_delta_pct: float
    outlier_threshold_ms: float
    slow_request_ids: tuple[int, ...]
    verdict: str


@dataclass(frozen=True)
class CapturedField:
    index: int
    name: str
    value: str
    field_type: str
    role: str
    fuzz: bool


@dataclass(frozen=True)
class CapturedLoginForm:
    source_url: str
    action_url: str
    method: str
    fields: list[CapturedField]
    cookies: dict[str, str]
    capture_mode: str = "static-html"


class SharedDelay:
    """Rate limiter simple para espaciar peticiones aun con multiples hilos."""

    def __init__(self, delay: float) -> None:
        self.delay = max(delay, 0.0)
        self.lock = threading.Lock()
        self.next_allowed = 0.0

    def wait(self) -> None:
        if self.delay <= 0:
            return
        with self.lock:
            now = time.monotonic()
            sleep_for = max(self.next_allowed - now, 0.0)
            self.next_allowed = max(now, self.next_allowed) + self.delay
        if sleep_for > 0:
            time.sleep(sleep_for)


class RawRequestTemplate:
    def __init__(
        self,
        *,
        request_line_parts: list[str | int],
        header_parts: list[tuple[str, list[str | int]]],
        body_parts: list[str | int],
        markers: list[Marker],
        default_scheme: str,
        base_url: str | None,
    ) -> None:
        self.request_line_parts = request_line_parts
        self.header_parts = header_parts
        self.body_parts = body_parts
        self.markers = markers
        self.default_scheme = default_scheme
        self.base_url = base_url

    @classmethod
    def from_file(cls, path: str | Path, *, default_scheme: str, base_url: str | None) -> "RawRequestTemplate":
        text = Path(path).read_text(encoding="utf-8-sig", errors="ignore")
        return cls.from_text(text, default_scheme=default_scheme, base_url=base_url)

    @classmethod
    def from_text(cls, text: str, *, default_scheme: str = "https", base_url: str | None = None) -> "RawRequestTemplate":
        text = text.replace("\r\n", "\n")
        if "\n\n" in text:
            head, body = text.split("\n\n", 1)
        else:
            head, body = text, ""

        lines = [line for line in head.split("\n") if line.strip()]
        if not lines:
            raise ValueError("La peticion esta vacia.")

        unfolded: list[str] = []
        for line in lines:
            if line[:1].isspace() and unfolded:
                unfolded[-1] += " " + line.strip()
            else:
                unfolded.append(line)

        request_line = unfolded[0]
        header_lines = unfolded[1:]
        markers: list[Marker] = []
        request_line_parts = parse_marked_string(request_line, markers, "request-line")

        header_parts: list[tuple[str, list[str | int]]] = []
        for raw_header in header_lines:
            if ":" not in raw_header:
                continue
            name, value = raw_header.split(":", 1)
            parts = parse_marked_string(value.lstrip(), markers, f"header:{name.strip()}")
            header_parts.append((name.strip(), parts))

        body_parts = parse_marked_string(body, markers, "body")
        if not markers:
            raise ValueError("No se encontraron posiciones delimitadas con §payload§.")

        return cls(
            request_line_parts=request_line_parts,
            header_parts=header_parts,
            body_parts=body_parts,
            markers=markers,
            default_scheme=default_scheme,
            base_url=base_url,
        )

    @property
    def base_payloads(self) -> tuple[str, ...]:
        return tuple(marker.base_value for marker in self.markers)

    def render(self, payloads: Sequence[str]) -> RenderedRequest:
        payload_map = {index: payload for index, payload in enumerate(payloads)}
        request_line = render_parts(self.request_line_parts, payload_map)
        body = render_parts(self.body_parts, payload_map)

        try:
            method, target, _version = request_line.split(maxsplit=2)
        except ValueError as exc:
            raise ValueError(f"Request line invalida despues de renderizar: {request_line}") from exc

        headers: dict[str, str] = {}
        host = ""
        for name, parts in self.header_parts:
            if name.lower() in {"content-length", "proxy-connection"}:
                continue
            value = render_parts(parts, payload_map)
            headers[name] = value
            if name.lower() == "host":
                host = value.strip()

        url = self.build_url(target, host)
        if body or method.upper() in {"POST", "PUT", "PATCH"}:
            headers["Content-Length"] = str(len(body.encode("utf-8")))

        return RenderedRequest(method=method.upper(), url=url, headers=headers, body=body)

    def build_url(self, target: str, host: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            return target

        if self.base_url:
            base = urlparse(self.base_url)
            if not base.scheme or not base.netloc:
                raise ValueError("--base-url debe incluir esquema y host, ej. https://app.local")
            if target.startswith("/"):
                return urlunparse((base.scheme, base.netloc, target, "", "", ""))
            return urlunparse((base.scheme, base.netloc, "/" + target, "", "", ""))

        if not host:
            raise ValueError("La peticion no tiene Host. Usa --base-url.")

        path = target if target.startswith("/") else "/" + target
        return f"{self.default_scheme}://{host}{path}"


def parse_marked_string(value: str, markers: list[Marker], location: str) -> list[str | int]:
    parts: list[str | int] = []
    cursor = 0
    for match in re.finditer(r"§(.*?)§", value, flags=re.DOTALL):
        parts.append(value[cursor : match.start()])
        marker_index = len(markers)
        markers.append(Marker(index=marker_index, base_value=match.group(1), location=location))
        parts.append(marker_index)
        cursor = match.end()
    parts.append(value[cursor:])
    return parts


def render_parts(parts: Sequence[str | int], payload_map: dict[int, str]) -> str:
    rendered: list[str] = []
    for part in parts:
        if isinstance(part, int):
            rendered.append(payload_map.get(part, ""))
        else:
            rendered.append(part)
    return "".join(rendered)


def load_wordlist(path: str | Path) -> list[str]:
    values: list[str] = []
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        for raw in handle:
            value = raw.rstrip("\r\n")
            if value:
                values.append(value)
    if not values:
        raise ValueError(f"Wordlist vacia: {path}")
    return values


def split_text_wordlist(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def safe_marker_value(value: str) -> str:
    return (value or "").replace("§", "")


def normalize_field_text(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").lower()).strip()


def classify_field(name: str, field_type: str, field_id: str = "", placeholder: str = "", autocomplete: str = "") -> str:
    blob = normalize_field_text(" ".join([name, field_type, field_id, placeholder, autocomplete]))
    if "pass" in blob or "pwd" in blob or "clave" in blob or "contrasena" in blob:
        return "password"
    if any(token in blob for token in ("user", "login", "email", "mail", "account", "usuario", "correo")):
        return "username"
    if any(token in blob for token in ("csrf", "xsrf", "token", "nonce", "authenticity")):
        return "token"
    return "static"


def classify_captured_pair(name: str, value: str) -> str:
    role = classify_field(name=name, field_type="", field_id="", placeholder="", autocomplete="")
    lowered_value = normalize_field_text(value)
    if role == "static" and lowered_value in {"admin", "administrator", "user", "test", "roger"}:
        return "username"
    if role == "static" and lowered_value in {"password", "admin123", "123456", "changeme"}:
        return "password"
    return role


def parse_login_form(source_url: str, html: str, cookies: dict[str, str] | None = None) -> CapturedLoginForm:
    if BeautifulSoup is None:
        raise RuntimeError("beautifulsoup4 no esta instalado. Ejecuta: pip install beautifulsoup4")

    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    if not forms:
        raise ValueError("No se detectaron formularios HTML en la URL indicada.")

    def score_form(form: object) -> int:
        text = normalize_field_text(form.get_text(" ", strip=True))
        score = 0
        if form.find("input", attrs={"type": re.compile("password", re.I)}):
            score += 100
        if any(token in text for token in ("login", "sign in", "iniciar", "acceder", "usuario", "password")):
            score += 20
        score += min(len(form.find_all(["input", "select", "textarea"])), 20)
        return score

    form = max(forms, key=score_form)
    method = str(form.get("method", "GET")).upper()
    action = str(form.get("action", "")).strip()
    action_url = urljoin(source_url, action) if action else source_url

    fields: list[CapturedField] = []
    seen_submit = False
    for node in form.find_all(["input", "select", "textarea"]):
        name = str(node.get("name", "")).strip()
        field_type = str(node.get("type", node.name)).strip().lower() or node.name
        if not name:
            name = str(node.get("id", "")).strip() or str(node.get("placeholder", "")).strip()
        if not name:
            continue
        if field_type in {"button", "image", "reset", "file"}:
            continue
        if field_type == "submit":
            if seen_submit:
                continue
            seen_submit = True

        value = str(node.get("value", ""))
        if node.name == "select":
            selected = node.find("option", selected=True) or node.find("option")
            value = str(selected.get("value", selected.get_text(strip=True))) if selected else ""
        elif node.name == "textarea":
            value = node.get_text()

        role = classify_field(
            name=name,
            field_type=field_type,
            field_id=str(node.get("id", "")),
            placeholder=str(node.get("placeholder", "")),
            autocomplete=str(node.get("autocomplete", "")),
        )
        fuzz = role in {"username", "password"}
        if role == "username" and not value:
            value = "admin"
        if role == "password" and not value:
            value = "password"

        fields.append(
            CapturedField(
                index=len(fields),
                name=name,
                value=value,
                field_type=field_type,
                role=role,
                fuzz=fuzz,
            )
        )

    if not fields:
        raise ValueError("El formulario detectado no contiene campos enviables.")

    return CapturedLoginForm(
        source_url=source_url,
        action_url=action_url,
        method=method if method in {"GET", "POST"} else "POST",
        fields=fields,
        cookies=cookies or {},
    )


def capture_login_form(url: str, *, timeout: float, verify_ssl: bool) -> tuple[CapturedLoginForm, requests.Response]:
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    response = session.get(url, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    response.raise_for_status()
    try:
        form = parse_login_form(
            str(response.url),
            response.text,
            cookies=session.cookies.get_dict(),
        )
        return form, response
    except ValueError:
        form = capture_login_form_with_browser(url, timeout=timeout, verify_ssl=verify_ssl)
        return form, response


def capture_login_form_with_browser(url: str, *, timeout: float, verify_ssl: bool) -> CapturedLoginForm:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "El login parece ser SPA/JavaScript y no hay Playwright disponible. "
            "Instala: pip install playwright && python -m playwright install chromium"
        ) from exc

    username_probe = "admin"
    password_probe = "password"
    timeout_ms = int(max(timeout, 5.0) * 1000)
    captured_requests: list[dict[str, object]] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=not verify_ssl)
        page = context.new_page()

        def on_request(request: object) -> None:
            method = request.method
            if method.upper() in {"GET", "OPTIONS"}:
                return
            body = request.post_data or ""
            url_text = request.url
            score = 0
            lowered_url = url_text.lower()
            lowered_body = body.lower()
            if username_probe in body or password_probe in body:
                score += 100
            if any(token in lowered_url for token in ("login", "auth", "authorise", "authorize", "session")):
                score += 30
            if body:
                score += 10
            captured_requests.append(
                {
                    "method": method,
                    "url": url_text,
                    "headers": dict(request.headers),
                    "body": body,
                    "score": score,
                    "lowered_body": lowered_body,
                }
            )

        page.on("request", on_request)
        try:
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        except PlaywrightTimeoutError:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        page.wait_for_timeout(1200)

        password_locator = page.locator(
            "input[type='password'], input[id*='pass' i], input[placeholder*='pass' i]"
        ).first
        try:
            password_locator.wait_for(state="visible", timeout=timeout_ms)
        except PlaywrightTimeoutError as exc:
            browser.close()
            raise ValueError("No se encontro input password despues de renderizar la SPA.") from exc

        username_locator = page.locator(
            "input[type='text'], input[type='email'], input[id*='user' i], "
            "input[id*='login' i], input[placeholder*='login' i], input[placeholder*='user' i]"
        ).first
        try:
            username_locator.fill(username_probe, timeout=3000)
        except Exception:
            pass
        password_locator.fill(password_probe, timeout=3000)

        clicked = False
        for selector in (
            "input[type='submit']",
            "button[type='submit']",
            "button:has-text('Log In')",
            "button:has-text('Login')",
            "button:has-text('Sign In')",
            "input[value*='Log' i]",
            "input[value*='Sign' i]",
        ):
            try:
                page.locator(selector).first.click(timeout=2500)
                clicked = True
                break
            except Exception:
                continue
        if not clicked:
            password_locator.press("Enter")

        page.wait_for_timeout(2500)
        cookies = {cookie["name"]: cookie["value"] for cookie in context.cookies()}
        rendered_url = page.url
        browser.close()

    if not captured_requests:
        raise ValueError("La SPA renderizo el formulario, pero no se capturo ningun POST/XHR al intentar login.")

    selected = max(captured_requests, key=lambda item: int(item["score"]))
    body = str(selected.get("body") or "")
    request_url = str(selected["url"])
    method = str(selected["method"]).upper()

    fields: list[CapturedField] = []
    content_type = str(dict(selected.get("headers", {})).get("content-type", ""))
    if "application/x-www-form-urlencoded" in content_type or "=" in body:
        for name, value in parse_qsl(body, keep_blank_values=True):
            role = classify_captured_pair(name, value)
            fields.append(
                CapturedField(
                    index=len(fields),
                    name=name,
                    value=value,
                    field_type="body",
                    role=role,
                    fuzz=role in {"username", "password"},
                )
            )

    if not fields:
        if username_probe in body:
            fields.append(CapturedField(0, "username", username_probe, "body", "username", True))
        if password_probe in body:
            fields.append(CapturedField(len(fields), "password", password_probe, "body", "password", True))

    if not fields:
        raise ValueError("Se capturo un request de login, pero no se pudieron extraer parametros editables.")

    return CapturedLoginForm(
        source_url=rendered_url,
        action_url=request_url,
        method=method,
        fields=fields,
        cookies=cookies,
        capture_mode="browser-xhr",
    )


def encode_pairs_for_template(pairs: Sequence[tuple[str, str, bool]]) -> str:
    chunks: list[str] = []
    for name, value, marked in pairs:
        encoded_name = quote_plus(name)
        if marked:
            encoded_value = f"§{safe_marker_value(value)}§"
        else:
            encoded_value = quote_plus(value)
        chunks.append(f"{encoded_name}={encoded_value}")
    return "&".join(chunks)


def request_target_from_url(url: str) -> str:
    parsed = urlparse(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return target


def cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def raw_request_from_form(form: CapturedLoginForm, selected_indices: set[int]) -> str:
    parsed_action = urlparse(form.action_url)
    host = parsed_action.netloc
    method = form.method.upper()
    field_pairs = [
        (field.name, field.value, field.index in selected_indices)
        for field in form.fields
        if field.name
    ]

    headers = [
        f"Host: {host}",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
        f"Referer: {form.source_url}",
        "Connection: close",
    ]
    if form.cookies:
        headers.append(f"Cookie: {cookie_header(form.cookies)}")

    if method == "GET":
        existing = [(name, value, False) for name, value in parse_qsl(parsed_action.query, keep_blank_values=True)]
        query = encode_pairs_for_template(existing + field_pairs)
        target = parsed_action.path or "/"
        if query:
            target += f"?{query}"
        request_line = f"GET {target} HTTP/1.1"
        return "\n".join([request_line, *headers, "", ""])

    body = encode_pairs_for_template(field_pairs)
    headers.append("Content-Type: application/x-www-form-urlencoded")
    headers.append(f"Content-Length: {len(body.encode('utf-8'))}")
    request_line = f"POST {request_target_from_url(form.action_url)} HTTP/1.1"
    return "\n".join([request_line, *headers, "", body])


def marker_roles_from_form(form: CapturedLoginForm, selected_indices: set[int]) -> list[str]:
    return [field.role for field in form.fields if field.index in selected_indices]


def payload_lists_for_roles(roles: Sequence[str], users: list[str], passwords: list[str]) -> list[list[str]]:
    lists: list[list[str]] = []
    for role in roles:
        if role == "password":
            lists.append(passwords)
        else:
            lists.append(users)
    return lists or [users]


def position_lists(position_count: int, payload_lists: list[list[str]]) -> list[list[str]]:
    if not payload_lists:
        raise ValueError("Debes indicar al menos una wordlist o payload inline.")
    if len(payload_lists) == 1:
        return [payload_lists[0] for _ in range(position_count)]
    if len(payload_lists) < position_count:
        raise ValueError(f"Se requieren {position_count} listas o una sola lista reutilizable.")
    return payload_lists[:position_count]


def maybe_encode(value: str, enabled: bool) -> str:
    return quote_plus(value) if enabled else value


def iter_attack_jobs(
    *,
    attack: str,
    base_payloads: tuple[str, ...],
    payload_lists: list[list[str]],
    url_encode: bool,
    max_requests: int,
) -> Iterator[AttackJob]:
    position_count = len(base_payloads)
    lists_by_position = position_lists(position_count, payload_lists)
    emitted = 0

    def emit(payloads: Sequence[str]) -> AttackJob:
        nonlocal emitted
        emitted += 1
        encoded = tuple(maybe_encode(item, url_encode) for item in payloads)
        summary = ", ".join(encoded)
        return AttackJob(request_id=emitted, payloads=encoded, payload_summary=summary)

    def allowed() -> bool:
        return max_requests <= 0 or emitted < max_requests

    attack = attack.lower().replace("_", "-")
    if attack == "sniper":
        for index in range(position_count):
            for payload in lists_by_position[index]:
                if not allowed():
                    return
                current = list(base_payloads)
                current[index] = payload
                yield emit(current)
    elif attack == "battering-ram":
        for payload in payload_lists[0]:
            if not allowed():
                return
            yield emit([payload] * position_count)
    elif attack == "pitchfork":
        for values in zip(*lists_by_position):
            if not allowed():
                return
            yield emit(values)
    elif attack == "cluster-bomb":
        for values in itertools.product(*lists_by_position):
            if not allowed():
                return
            yield emit(values)
    else:
        raise ValueError(f"Modo de ataque no soportado: {attack}")


def compile_grep_patterns(exact_values: Sequence[str], regex_values: Sequence[str]) -> list[tuple[str, Pattern[str]]]:
    compiled: list[tuple[str, Pattern[str]]] = []
    for value in exact_values:
        compiled.append((value, re.compile(re.escape(value), re.IGNORECASE)))
    for value in regex_values:
        compiled.append((value, re.compile(value, re.IGNORECASE)))
    return compiled


def grep_response(text: str, patterns: Sequence[tuple[str, Pattern[str]]]) -> str:
    for label, pattern in patterns:
        if pattern.search(text):
            return label
    return "-"


def send_attack_request(
    *,
    template: RawRequestTemplate,
    job: AttackJob,
    timeout: float,
    verify_ssl: bool,
    allow_redirects: bool,
    grep_patterns: Sequence[tuple[str, Pattern[str]]],
    shared_delay: SharedDelay,
) -> AttackResult:
    shared_delay.wait()
    try:
        rendered = template.render(job.payloads)
        started = time.monotonic()
        response = requests.request(
            rendered.method,
            rendered.url,
            headers=rendered.headers,
            data=rendered.body.encode("utf-8") if rendered.body else None,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=allow_redirects,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        body_text = response.text or ""
        return AttackResult(
            request_id=job.request_id,
            payload_summary=job.payload_summary,
            status_code=response.status_code,
            length=len(response.content),
            grep_match=grep_response(body_text, grep_patterns),
            elapsed_ms=elapsed_ms,
            lockout_hint=bool(LOCKOUT_SIGNATURES.search(body_text)) or response.status_code in {403, 429},
        )
    except requests.RequestException as exc:
        return AttackResult(
            request_id=job.request_id,
            payload_summary=job.payload_summary,
            status_code=0,
            length=0,
            grep_match="-",
            elapsed_ms=0,
            lockout_hint=False,
            error=f"{exc.__class__.__name__}: {exc}",
        )
    except Exception as exc:
        return AttackResult(
            request_id=job.request_id,
            payload_summary=job.payload_summary,
            status_code=0,
            length=0,
            grep_match="-",
            elapsed_ms=0,
            lockout_hint=False,
            error=f"{exc.__class__.__name__}: {exc}",
        )


def request_base_response(
    template: RawRequestTemplate,
    *,
    timeout: float,
    verify_ssl: bool,
    allow_redirects: bool,
) -> requests.Response | None:
    try:
        rendered = template.render(template.base_payloads)
        return requests.request(
            rendered.method,
            rendered.url,
            headers=rendered.headers,
            data=rendered.body.encode("utf-8") if rendered.body else None,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=allow_redirects,
        )
    except requests.RequestException:
        return None


def collect_security_alerts(template: RawRequestTemplate, base_response: requests.Response | None) -> list[str]:
    base_request = template.render(template.base_payloads)
    request_blob = "\n".join(
        [
            base_request.url,
            "\n".join(f"{k}: {v}" for k, v in base_request.headers.items()),
            base_request.body,
        ]
    )
    response_blob = ""
    if base_response is not None:
        response_blob = "\n".join(
            [
                str(base_response.status_code),
                "\n".join(f"{k}: {v}" for k, v in base_response.headers.items()),
                base_response.text or "",
            ]
        )

    alerts: list[str] = []
    if not CSRF_SIGNATURES.search(request_blob):
        alerts.append(
            "[VULNERABILIDAD DETECTADA] Ausencia de control anti-automatizacion / anti-fuerza bruta: "
            "No se detecto Token anti-CSRF"
        )
    if not CAPTCHA_SIGNATURES.search(response_blob + "\n" + request_blob):
        alerts.append(
            "[VULNERABILIDAD DETECTADA] Ausencia de control anti-automatizacion / anti-fuerza bruta: "
            "No se detecto CAPTCHA"
        )
    if not MFA_SIGNATURES.search(response_blob):
        alerts.append(
            "[VULNERABILIDAD DETECTADA] Ausencia de control anti-automatizacion / anti-fuerza bruta: "
            "No se detecto MFA"
        )

    return alerts


def audit_security_controls(template: RawRequestTemplate, base_response: requests.Response | None, console: object) -> None:
    for alert in collect_security_alerts(template, base_response):
        print_alert(console, alert)


def percentile_nearest_rank(values: Sequence[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    rank = max(1, int((percentile / 100.0) * len(ordered) + 0.999999))
    return ordered[min(rank - 1, len(ordered) - 1)]


def analyze_response_times(results: Sequence[AttackResult]) -> ResponseTimingStats | None:
    valid = sorted(
        (item for item in results if not item.error and item.elapsed_ms > 0),
        key=lambda item: item.request_id,
    )
    if not valid:
        return None

    values = [item.elapsed_ms for item in valid]
    median_ms = float(statistics.median(values))
    mean_ms = float(statistics.fmean(values))
    stdev_ms = float(statistics.pstdev(values)) if len(values) > 1 else 0.0
    coefficient_variation_pct = (stdev_ms / mean_ms * 100.0) if mean_ms > 0 else 0.0

    window_size = min(5, max(1, len(values) // 2))
    first_window_median_ms = float(statistics.median(values[:window_size]))
    last_window_median_ms = float(statistics.median(values[-window_size:]))
    trend_delta_ms = last_window_median_ms - first_window_median_ms
    trend_delta_pct = (
        trend_delta_ms / first_window_median_ms * 100.0
        if first_window_median_ms > 0
        else 0.0
    )

    absolute_deviations = [abs(value - median_ms) for value in values]
    median_absolute_deviation = float(statistics.median(absolute_deviations))
    outlier_threshold_ms = median_ms + max(500.0, 3.0 * median_absolute_deviation)
    slow_request_ids = tuple(
        item.request_id
        for item in valid
        if item.elapsed_ms >= outlier_threshold_ms
    )

    progressive_degradation = (
        len(values) >= 6
        and trend_delta_ms >= max(250.0, first_window_median_ms * 0.5)
    )
    high_variation = (
        len(values) >= 3
        and (
            coefficient_variation_pct >= 35.0
            or (max(values) - min(values)) >= max(1000.0, median_ms)
            or bool(slow_request_ids)
        )
    )

    if len(values) < 3:
        verdict = "MUESTRA INSUFICIENTE"
    elif progressive_degradation:
        verdict = "DEGRADACION PROGRESIVA"
    elif high_variation:
        verdict = "VARIACION ALTA"
    else:
        verdict = "ESTABLE"

    return ResponseTimingStats(
        count=len(values),
        minimum_ms=min(values),
        maximum_ms=max(values),
        mean_ms=mean_ms,
        median_ms=median_ms,
        p95_ms=percentile_nearest_rank(values, 95.0),
        stdev_ms=stdev_ms,
        coefficient_variation_pct=coefficient_variation_pct,
        first_window_median_ms=first_window_median_ms,
        last_window_median_ms=last_window_median_ms,
        trend_delta_ms=trend_delta_ms,
        trend_delta_pct=trend_delta_pct,
        outlier_threshold_ms=outlier_threshold_ms,
        slow_request_ids=slow_request_ids,
        verdict=verdict,
    )


def format_response_time_analysis(stats: ResponseTimingStats | None) -> str:
    if stats is None:
        return "Tiempo de respuesta: pendiente de respuestas validas."
    slow = ",".join(str(item) for item in stats.slow_request_ids) or "ninguna"
    return (
        f"Tiempo: n={stats.count} | min={stats.minimum_ms} ms | media={stats.mean_ms:.1f} ms | "
        f"mediana={stats.median_ms:.1f} ms | p95={stats.p95_ms} ms | max={stats.maximum_ms} ms | "
        f"desv={stats.stdev_ms:.1f} ms (CV={stats.coefficient_variation_pct:.1f}%) | "
        f"delta inicio-fin={stats.trend_delta_ms:+.1f} ms ({stats.trend_delta_pct:+.1f}%) | "
        f"lentas={slow} | {stats.verdict}"
    )


def lockout_vulnerability_alert(results: Sequence[AttackResult], audit_limit: int) -> str | None:
    if audit_limit <= 0 or len(results) < audit_limit:
        return None

    sample = list(results[:audit_limit])
    statuses = {item.status_code for item in sample}
    lengths = [item.length for item in sample if item.length > 0]
    times = [item.elapsed_ms for item in sample if item.elapsed_ms > 0]
    lockout_seen = any(item.lockout_hint for item in sample) or bool(statuses & {403, 429})

    length_stable = True
    if lengths:
        median_length = statistics.median(lengths)
        length_stable = all(abs(length - median_length) <= max(250, median_length * 0.25) for length in lengths)

    time_stable = True
    if len(times) >= 3:
        median_time = max(statistics.median(times), 1)
        time_stable = max(times) <= max(median_time * 3.0, median_time + 1500)

    if not lockout_seen and length_stable and time_stable:
        return (
            "[REPORTAR COMO VULN] La aplicacion permite intentos ilimitados sin bloqueo de cuenta "
            f"ni degradacion de servicio en un umbral de {audit_limit} intentos"
        )
    return None


def analyze_lockout(results: Sequence[AttackResult], audit_limit: int, console: object) -> None:
    alert = lockout_vulnerability_alert(results, audit_limit)
    if alert:
        print_alert(console, alert)


def build_table(results: Sequence[AttackResult]) -> object:
    if Table is None:
        return None
    table = Table(title=f"{APP_NAME} v{APP_VERSION}", expand=True)
    table.add_column("ID", justify="right", no_wrap=True)
    table.add_column("Payload(s)", overflow="fold")
    table.add_column("Status", justify="right")
    table.add_column("Length", justify="right")
    table.add_column("Grep-Match")
    table.add_column("Time", justify="right")
    for result in results:
        status = str(result.status_code) if not result.error else "ERR"
        grep = result.grep_match
        if result.lockout_hint:
            grep = f"{grep} | lockout-hint" if grep != "-" else "lockout-hint"
        table.add_row(
            str(result.request_id),
            result.payload_summary[:180],
            status,
            str(result.length),
            grep,
            f"{result.elapsed_ms} ms" if not result.error else result.error[:80],
        )
    return table


def print_alert(console: object, message: str) -> None:
    if Console is not None and isinstance(console, Console):
        console.print(f"[bold red]{message}[/bold red]")
    else:
        print(message)


def print_info(console: object, message: str) -> None:
    if Console is not None and isinstance(console, Console):
        console.print(f"[cyan]{message}[/cyan]")
    else:
        print(message)


def run_attack(args: argparse.Namespace) -> int:
    if not args.verify_ssl:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    console = Console() if Console is not None else object()
    template = RawRequestTemplate.from_file(
        args.request,
        default_scheme=args.scheme,
        base_url=args.base_url,
    )
    print_info(console, f"Posiciones detectadas: {len(template.markers)}")
    for marker in template.markers:
        print_info(console, f"  #{marker.index + 1} {marker.location}: valor base='{marker.base_value}'")

    payload_lists: list[list[str]] = [load_wordlist(path) for path in args.wordlist]
    if args.payload:
        payload_lists.append(args.payload)

    base_response = request_base_response(
        template,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        allow_redirects=args.allow_redirects,
    )
    audit_security_controls(template, base_response, console)

    max_requests = args.max_requests if args.max_requests is not None else args.audit_limit
    jobs = iter_attack_jobs(
        attack=args.attack,
        base_payloads=template.base_payloads,
        payload_lists=payload_lists,
        url_encode=args.url_encode,
        max_requests=max_requests,
    )
    grep_patterns = compile_grep_patterns(args.grep, args.grep_regex)
    shared_delay = SharedDelay(args.delay)
    results: list[AttackResult] = []

    def submit_next(executor: concurrent.futures.ThreadPoolExecutor) -> concurrent.futures.Future[AttackResult] | None:
        try:
            job = next(jobs)
        except StopIteration:
            return None
        return executor.submit(
            send_attack_request,
            template=template,
            job=job,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            allow_redirects=args.allow_redirects,
            grep_patterns=grep_patterns,
            shared_delay=shared_delay,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        pending: set[concurrent.futures.Future[AttackResult]] = set()
        for _ in range(args.threads):
            future = submit_next(executor)
            if future:
                pending.add(future)

        if Live is not None and Table is not None and Console is not None:
            with Live(build_table(results), console=console, refresh_per_second=6) as live:
                while pending:
                    done, pending = concurrent.futures.wait(
                        pending,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    for future in done:
                        results.append(future.result())
                        next_future = submit_next(executor)
                        if next_future:
                            pending.add(next_future)
                    live.update(build_table(results))
        else:
            while pending:
                done, pending = concurrent.futures.wait(
                    pending,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    result = future.result()
                    results.append(result)
                    print(
                        f"{result.request_id}\t{result.payload_summary}\t{result.status_code}\t"
                        f"{result.length}\t{result.grep_match}\t{result.elapsed_ms}ms"
                    )
                    next_future = submit_next(executor)
                    if next_future:
                        pending.add(next_future)

    results.sort(key=lambda item: item.request_id)
    analyze_lockout(results, args.audit_limit, console)
    print_info(console, format_response_time_analysis(analyze_response_times(results)))
    print_info(console, f"Finalizado. Peticiones ejecutadas: {len(results)}")
    return 0


def run_self_test() -> int:
    sample = (
        "POST /login HTTP/1.1\n"
        "Host: example.com\n"
        "User-Agent: audit\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "username=§admin§&password=§123456§"
    )
    template = RawRequestTemplate.from_text(sample, default_scheme="https", base_url=None)
    rendered = template.render(("roger", "winter2026"))
    sniper = list(
        iter_attack_jobs(
            attack="sniper",
            base_payloads=template.base_payloads,
            payload_lists=[["a", "b"], ["1", "2"]],
            url_encode=False,
            max_requests=0,
        )
    )
    pitchfork = list(
        iter_attack_jobs(
            attack="pitchfork",
            base_payloads=template.base_payloads,
            payload_lists=[["u1", "u2"], ["p1", "p2", "p3"]],
            url_encode=False,
            max_requests=0,
        )
    )
    cluster = list(
        iter_attack_jobs(
            attack="cluster-bomb",
            base_payloads=template.base_payloads,
            payload_lists=[["u1", "u2"], ["p1", "p2"]],
            url_encode=False,
            max_requests=0,
        )
    )
    html = """
    <html><body>
      <form method="post" action="/login">
        <input type="hidden" name="csrf_token" value="abc123">
        <input name="username">
        <input type="password" name="password">
        <button type="submit">Login</button>
      </form>
    </body></html>
    """
    captured = parse_login_form("https://example.com/login", html, {"sid": "1"})
    selected = {field.index for field in captured.fields if field.fuzz}
    raw_from_form = raw_request_from_form(captured, selected)
    template_from_form = RawRequestTemplate.from_text(raw_from_form)
    timing_sample = [
        AttackResult(index, f"p{index}", 200, 100, "-", elapsed, False)
        for index, elapsed in enumerate((100, 105, 110, 115, 120, 900), start=1)
    ]
    timing = analyze_response_times(timing_sample)
    limited_cluster = list(
        iter_attack_jobs(
            attack="cluster-bomb",
            base_payloads=template.base_payloads,
            payload_lists=[["u1", "u2"], ["p1", "p2"]],
            url_encode=False,
            max_requests=3,
        )
    )

    checks = [
        ("positions parsed", len(template.markers) == 2),
        ("rendered url", rendered.url == "https://example.com/login"),
        ("rendered body", rendered.body == "username=roger&password=winter2026"),
        ("sniper count", len(sniper) == 4),
        ("pitchfork count", len(pitchfork) == 2),
        ("cluster count", len(cluster) == 4),
        ("configurable max requests", len(limited_cluster) == 3),
        ("form capture fields", len(captured.fields) == 3),
        ("form capture markers", len(template_from_form.markers) == 2),
        ("timing sample analyzed", timing is not None and timing.count == 6),
        ("timing variation detected", timing is not None and timing.verdict != "ESTABLE"),
        ("spanish lockout detected", bool(LOCKOUT_SIGNATURES.search("Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos."))),
    ]
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
    if failed:
        return 1
    print("Self-test completado correctamente.")
    return 0


class IntruderGuiApp(ctk.CTk if ctk else object):
    def __init__(self) -> None:
        if ctk is None:
            raise RuntimeError("customtkinter no esta instalado. Ejecuta: pip install customtkinter")

        super().__init__()
        self.title(f"{APP_NAME} GUI v{APP_VERSION}")
        self.geometry("1380x850")
        self.minsize(1180, 740)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.current_form: CapturedLoginForm | None = None
        self.fuzz_indices: set[int] = set()
        self.results: list[AttackResult] = []
        self.audit_alerts: list[str] = []
        self.lockout_alert: str | None = None
        self.timing_analysis: ResponseTimingStats | None = None
        self.capture_status: int | str = "-"
        self.capture_length: int | str = "-"
        self.last_run_config: dict[str, object] = {}
        self.last_roles: list[str] = []
        self.stop_event = threading.Event()
        self.worker_thread: threading.Thread | None = None

        self.url_var = ctk.StringVar(value="")
        self.mode_var = ctk.StringVar(value="pitchfork")
        self.verify_ssl_var = ctk.BooleanVar(value=False)
        self.url_encode_var = ctk.BooleanVar(value=True)
        self.follow_redirects_var = ctk.BooleanVar(value=True)
        self.threads_var = ctk.StringVar(value="4")
        self.timeout_var = ctk.StringVar(value="8")
        self.delay_var = ctk.StringVar(value="0.2")
        self.audit_limit_var = ctk.StringVar(value="15")
        self.max_requests_var = ctk.StringVar(value="100")
        self.grep_var = ctk.StringVar(
            value="Invalid|incorrect|locked|dashboard|demasiados|intentos fallidos|bloquead[oa]|15 minutos|rate.?limit"
        )

        self.field_rows: dict[str, CapturedField] = {}
        self.build_layout()
        self.after(100, self.process_events)

    def build_layout(self) -> None:
        self.configure(fg_color="#0f1117")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(self, fg_color="#161a23", corner_radius=8)
        top.grid(row=0, column=0, padx=14, pady=(14, 8), sticky="ew")
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top, text="URL Login", font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=0, column=0, padx=(14, 8), pady=12, sticky="w"
        )
        self.url_entry = ctk.CTkEntry(top, textvariable=self.url_var, placeholder_text="https://target.local/login")
        self.url_entry.grid(row=0, column=1, padx=8, pady=12, sticky="ew")
        ctk.CTkButton(top, text="Analizar", command=self.analyze_url, width=110).grid(
            row=0, column=2, padx=8, pady=12
        )
        ctk.CTkButton(top, text="Refrescar/Capturar", command=self.refresh_capture, width=150).grid(
            row=0, column=3, padx=(0, 14), pady=12
        )

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, padx=14, pady=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="#161a23", corner_radius=8)
        left.grid(row=0, column=0, padx=(0, 8), pady=0, sticky="nsew")
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(1, weight=1)
        left.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(left, text="Parametros capturados - doble clic para marcar/desmarcar", anchor="w").grid(
            row=0, column=0, padx=12, pady=(12, 6), sticky="ew"
        )
        self.field_tree = ttk.Treeview(
            left,
            columns=("fuzz", "name", "type", "role", "value"),
            show="headings",
            height=8,
            selectmode="browse",
        )
        self.configure_tree(self.field_tree)
        for col, title, width in [
            ("fuzz", "Fuzz", 70),
            ("name", "Parametro", 180),
            ("type", "Tipo", 90),
            ("role", "Rol", 110),
            ("value", "Valor base", 280),
        ]:
            self.field_tree.heading(col, text=title)
            self.field_tree.column(col, width=width, minwidth=60, stretch=col == "value")
        self.field_tree.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="nsew")
        self.field_tree.bind("<Double-1>", lambda _event: self.toggle_selected_field())

        actions = ctk.CTkFrame(left, fg_color="transparent")
        actions.grid(row=2, column=0, padx=12, pady=(0, 8), sticky="ew")
        actions.grid_columnconfigure(3, weight=1)
        ctk.CTkButton(actions, text="Marcar/Desmarcar", command=self.toggle_selected_field, width=150).grid(
            row=0, column=0, padx=(0, 8)
        )
        ctk.CTkButton(actions, text="Marcar user/pass", command=self.mark_default_fields, width=140).grid(
            row=0, column=1, padx=(0, 8)
        )
        ctk.CTkButton(actions, text="Actualizar Request", command=self.update_request_preview, width=150).grid(
            row=0, column=2, padx=(0, 8)
        )

        ctk.CTkLabel(left, text="Request marcada editable", anchor="w").grid(
            row=3, column=0, padx=12, pady=(4, 4), sticky="sw"
        )
        self.request_text = self.create_text_panel(left, row=4, column=0, padx=12, pady=(0, 12), height=12)

        right = ctk.CTkFrame(body, fg_color="#161a23", corner_radius=8)
        right.grid(row=0, column=1, padx=(8, 0), pady=0, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=1)

        self.side_tabs = ctk.CTkTabview(right, fg_color="#161a23", segmented_button_fg_color="#111827")
        self.side_tabs.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        run_tab = self.side_tabs.add("Ejecucion")
        config_tab = self.side_tabs.add("Config")
        wordlists_tab = self.side_tabs.add("Wordlists")

        run_tab.grid_columnconfigure(0, weight=1)
        run_tab.grid_columnconfigure(1, weight=1)
        run_tab.grid_rowconfigure(2, weight=1)

        self.audit_status_label = ctk.CTkLabel(
            run_tab,
            text="Estado: pendiente",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w",
        )
        self.audit_status_label.grid(row=0, column=0, columnspan=2, padx=12, pady=(12, 8), sticky="ew")

        self.findings_tree = ttk.Treeview(
            run_tab,
            columns=("check", "control", "resultado"),
            show="headings",
            height=7,
            selectmode="none",
        )
        self.configure_tree(self.findings_tree)
        for col, title, width in [
            ("check", "Check", 90),
            ("control", "Control", 150),
            ("resultado", "Resultado", 310),
        ]:
            self.findings_tree.heading(col, text=title)
            self.findings_tree.column(col, width=width, minwidth=70, stretch=col == "resultado")
        self.findings_tree.grid(row=1, column=0, columnspan=2, padx=12, pady=(0, 10), sticky="ew")
        self.findings_tree.tag_configure("ok", foreground="#86efac")
        self.findings_tree.tag_configure("vuln", foreground="#fecaca")
        self.findings_tree.tag_configure("pending", foreground="#fde68a")
        self.findings_tree.tag_configure("info", foreground="#93c5fd")

        ctk.CTkLabel(run_tab, text="Detalle de auditoria", anchor="w").grid(
            row=2, column=0, columnspan=2, padx=12, pady=(0, 4), sticky="sw"
        )
        self.audit_text = self.create_text_panel(
            run_tab,
            row=3,
            column=0,
            columnspan=2,
            padx=12,
            pady=(0, 12),
            height=10,
        )

        run_controls = ctk.CTkFrame(run_tab, fg_color="transparent")
        run_controls.grid(row=4, column=0, columnspan=2, padx=12, pady=(0, 12), sticky="ew")
        run_controls.grid_columnconfigure(0, weight=1)
        run_controls.grid_columnconfigure(1, weight=1)
        run_controls.grid_columnconfigure(2, weight=1)
        self.start_button = ctk.CTkButton(run_controls, text="Iniciar Intruder", command=self.start_attack, fg_color="#2563eb")
        self.start_button.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.stop_button = ctk.CTkButton(run_controls, text="Detener", command=self.stop_attack, fg_color="#991b1b", state="disabled")
        self.stop_button.grid(row=0, column=1, padx=8, sticky="ew")
        self.report_button = ctk.CTkButton(
            run_controls,
            text="Exportar HTML",
            command=self.export_html_report,
            fg_color="#166534",
            hover_color="#14532d",
        )
        self.report_button.grid(row=0, column=2, padx=(8, 0), sticky="ew")
        self.write_audit("Introduce la URL del login y pulsa Analizar.")
        self.refresh_findings_view()

        config_tab.grid_columnconfigure(0, weight=1)
        config_tab.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(config_tab, text="Modo de ataque", anchor="w").grid(row=0, column=0, columnspan=2, padx=12, pady=(12, 4), sticky="ew")
        mode_menu = ctk.CTkOptionMenu(
            config_tab,
            variable=self.mode_var,
            values=list(ATTACK_MODE_DESCRIPTIONS.keys()),
            command=lambda _value: self.update_mode_description(),
        )
        mode_menu.grid(row=1, column=0, columnspan=2, padx=12, pady=(0, 6), sticky="ew")
        self.mode_description = ctk.CTkLabel(
            config_tab,
            text=ATTACK_MODE_DESCRIPTIONS[self.mode_var.get()],
            text_color="#cbd5e1",
            wraplength=430,
            justify="left",
            anchor="w",
        )
        self.mode_description.grid(row=2, column=0, columnspan=2, padx=12, pady=(0, 12), sticky="ew")

        self.add_numeric_entry(config_tab, "Hilos", self.threads_var, 3, 0)
        self.add_numeric_entry(config_tab, "Timeout", self.timeout_var, 3, 1)
        self.add_numeric_entry(config_tab, "Peticiones maximas (0=sin limite)", self.max_requests_var, 5, 0)
        self.add_numeric_entry(config_tab, "Umbral lockout", self.audit_limit_var, 5, 1)
        ctk.CTkLabel(config_tab, text="Delay entre peticiones (s)", anchor="w").grid(
            row=7, column=0, columnspan=2, padx=12, pady=(4, 2), sticky="ew"
        )
        ctk.CTkEntry(config_tab, textvariable=self.delay_var).grid(
            row=8, column=0, columnspan=2, padx=12, pady=(0, 8), sticky="ew"
        )

        toggles = ctk.CTkFrame(config_tab, fg_color="transparent")
        toggles.grid(row=9, column=0, columnspan=2, padx=12, pady=(0, 8), sticky="ew")
        toggles.grid_columnconfigure(0, weight=1)
        toggles.grid_columnconfigure(1, weight=1)
        ctk.CTkCheckBox(toggles, text="URL encode", variable=self.url_encode_var).grid(row=0, column=0, sticky="w")
        ctk.CTkCheckBox(toggles, text="Verificar SSL", variable=self.verify_ssl_var).grid(row=0, column=1, sticky="w")
        ctk.CTkCheckBox(toggles, text="Seguir redirects", variable=self.follow_redirects_var).grid(
            row=1, column=0, columnspan=2, pady=(6, 0), sticky="w"
        )

        ctk.CTkLabel(config_tab, text="Grep regex/texto", anchor="w").grid(
            row=10, column=0, columnspan=2, padx=12, pady=(4, 2), sticky="ew"
        )
        ctk.CTkEntry(config_tab, textvariable=self.grep_var).grid(
            row=11, column=0, columnspan=2, padx=12, pady=(0, 10), sticky="ew"
        )

        wordlists_tab.grid_columnconfigure(0, weight=1)
        wordlists_tab.grid_columnconfigure(1, weight=1)
        wordlists_tab.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(wordlists_tab, text="Users por defecto", anchor="w").grid(row=0, column=0, padx=12, pady=(12, 4), sticky="ew")
        ctk.CTkLabel(wordlists_tab, text="Creds por defecto", anchor="w").grid(row=0, column=1, padx=12, pady=(12, 4), sticky="ew")
        self.users_text = self.create_text_panel(wordlists_tab, row=1, column=0, padx=12, pady=(0, 8), height=14)
        self.passwords_text = self.create_text_panel(wordlists_tab, row=1, column=1, padx=12, pady=(0, 8), height=14)
        self.users_text.insert("1.0", "\n".join(DEFAULT_USER_WORDLIST))
        self.passwords_text.insert("1.0", "\n".join(DEFAULT_PASSWORD_WORDLIST))

        word_buttons = ctk.CTkFrame(wordlists_tab, fg_color="transparent")
        word_buttons.grid(row=2, column=0, columnspan=2, padx=12, pady=(0, 12), sticky="ew")
        ctk.CTkButton(word_buttons, text="Cargar users", command=lambda: self.load_wordlist_into(self.users_text), width=120).grid(
            row=0, column=0, padx=(0, 8)
        )
        ctk.CTkButton(word_buttons, text="Cargar creds", command=lambda: self.load_wordlist_into(self.passwords_text), width=120).grid(
            row=0, column=1, padx=(0, 8)
        )
        ctk.CTkButton(word_buttons, text="Restaurar defaults", command=self.restore_default_wordlists, width=150).grid(
            row=0, column=2
        )

        bottom = ctk.CTkFrame(self, fg_color="#161a23", corner_radius=8)
        bottom.grid(row=2, column=0, padx=14, pady=(8, 14), sticky="nsew")
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(bottom, text="Resultados", anchor="w").grid(row=0, column=0, padx=12, pady=(12, 4), sticky="ew")
        self.timing_status_label = ctk.CTkLabel(
            bottom,
            text=format_response_time_analysis(None),
            anchor="w",
            justify="left",
            wraplength=1320,
            text_color="#93c5fd",
        )
        self.timing_status_label.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="ew")
        self.results_tree = ttk.Treeview(
            bottom,
            columns=("id", "payloads", "status", "length", "grep", "time"),
            show="headings",
            height=8,
        )
        self.configure_tree(self.results_tree)
        for col, title, width in [
            ("id", "ID", 60),
            ("payloads", "Payload(s)", 560),
            ("status", "Status", 80),
            ("length", "Length", 90),
            ("grep", "Grep-Match", 220),
            ("time", "Time", 90),
        ]:
            self.results_tree.heading(col, text=title)
            self.results_tree.column(col, width=width, minwidth=60, stretch=col == "payloads")
        self.results_tree.grid(row=2, column=0, padx=12, pady=(0, 12), sticky="nsew")
        self.results_tree.tag_configure("slow", foreground="#fbbf24")

    def configure_tree(self, tree: ttk.Treeview) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Treeview",
            background="#111827",
            foreground="#e5e7eb",
            fieldbackground="#111827",
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#1f2937",
            foreground="#e5e7eb",
            borderwidth=0,
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])

    def create_text_panel(
        self,
        parent: object,
        *,
        row: int,
        column: int,
        columnspan: int = 1,
        padx: int | tuple[int, int] = 0,
        pady: int | tuple[int, int] = 0,
        height: int = 10,
    ) -> tk.Text:
        wrapper = ctk.CTkFrame(parent, fg_color="#1b1b1b", corner_radius=6)
        wrapper.grid(row=row, column=column, columnspan=columnspan, padx=padx, pady=pady, sticky="nsew")
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(0, weight=1)

        text = tk.Text(
            wrapper,
            height=height,
            wrap="word",
            bg="#1b1b1b",
            fg="#f8fafc",
            insertbackground="#f8fafc",
            selectbackground="#2563eb",
            relief="flat",
            borderwidth=0,
            font=("Consolas", 10),
            undo=True,
        )
        scrollbar = ttk.Scrollbar(wrapper, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(6, 8), pady=8)
        return text

    def get_int_setting(self, var: object, *, default: int, minimum: int | None = None) -> int:
        raw = str(var.get()).strip() if hasattr(var, "get") else str(var).strip()
        if raw == "":
            value = default
        else:
            value = int(raw)
        if minimum is not None:
            value = max(minimum, value)
        return value

    def get_float_setting(self, var: object, *, default: float, minimum: float | None = None) -> float:
        raw = str(var.get()).strip().replace(",", ".") if hasattr(var, "get") else str(var).strip().replace(",", ".")
        if raw == "":
            value = default
        else:
            value = float(raw)
        if minimum is not None:
            value = max(minimum, value)
        return value

    def add_numeric_entry(self, parent: object, label: str, var: object, row: int, column: int) -> None:
        ctk.CTkLabel(parent, text=label, anchor="w").grid(row=row, column=column, padx=12, pady=(4, 2), sticky="ew")
        ctk.CTkEntry(parent, textvariable=var).grid(row=row + 1, column=column, padx=12, pady=(0, 8), sticky="ew")

    def update_mode_description(self) -> None:
        self.mode_description.configure(text=ATTACK_MODE_DESCRIPTIONS.get(self.mode_var.get(), ""))

    def control_status_rows(self) -> list[tuple[str, str, str, str]]:
        captured = self.current_form is not None or bool(self.audit_alerts) or bool(self.results)
        alert_blob = "\n".join(self.audit_alerts).lower()

        def row_for(alert_key: str, control: str, ok_text: str, vuln_text: str) -> tuple[str, str, str, str]:
            if not captured:
                return ("[PEND]", control, "Pendiente de captura/auditoria", "pending")
            if alert_key in alert_blob:
                return ("[VULN]", control, vuln_text, "vuln")
            return ("[OK]", control, ok_text, "ok")

        rows = [
            row_for(
                "anti-csrf",
                "Anti-CSRF",
                "Token o validacion equivalente detectada/no reportada como ausente",
                "No se detecto token anti-CSRF en request/cookies",
            ),
            row_for(
                "captcha",
                "CAPTCHA",
                "Proteccion CAPTCHA detectada/no reportada como ausente",
                "No se detecto CAPTCHA/anti-bot",
            ),
            row_for(
                "mfa",
                "MFA",
                "Flujo MFA detectado/no reportado como ausente",
                "No se detecto MFA/segundo factor",
            ),
        ]

        configured_audit_limit = int(
            self.last_run_config.get("audit_limit", self.get_int_setting(self.audit_limit_var, default=15, minimum=1))
        )
        if self.lockout_alert:
            rows.append(("[VULN]", "Lockout/Rate-limit", self.lockout_alert, "vuln"))
        elif self.results and len(self.results) < configured_audit_limit:
            rows.append(
                (
                    "[PEND]",
                    "Lockout/Rate-limit",
                    f"Solo {len(self.results)} respuestas; no se alcanzo el umbral configurado de {configured_audit_limit}",
                    "pending",
                )
            )
        elif self.results:
            rows.append(("[OK]", "Lockout/Rate-limit", "No se cumplio criterio de intentos ilimitados en el umbral evaluado", "ok"))
        else:
            rows.append(("[PEND]", "Lockout/Rate-limit", "Pendiente de ejecutar Intruder", "pending"))
        if self.results:
            timing = self.timing_analysis or analyze_response_times(self.results)
            rows.append(("[INFO]", "Tiempo respuesta", format_response_time_analysis(timing), "info"))
        return rows

    def refresh_findings_view(self) -> None:
        if not hasattr(self, "findings_tree"):
            return
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)

        rows = self.control_status_rows()
        has_vuln = any(row[3] == "vuln" for row in rows)
        has_pending = any(row[3] == "pending" for row in rows)

        if has_vuln:
            self.audit_status_label.configure(text="Estado: VULNERABILIDADES DETECTADAS", text_color="#fecaca")
        elif has_pending:
            self.audit_status_label.configure(text="Estado: auditoria pendiente/parcial", text_color="#fde68a")
        else:
            self.audit_status_label.configure(text="Estado: sin vulns detectadas por estos checks", text_color="#86efac")

        for row in rows:
            self.findings_tree.insert("", "end", values=row[:3], tags=(row[3],))

    def analyze_url(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning(APP_NAME, "Introduce la URL del login.")
            return
        if not re.match(r"^https?://", url, flags=re.IGNORECASE):
            url = "https://" + url
            self.url_var.set(url)
        self.start_button.configure(state="disabled")
        self.write_audit(f"Analizando {url} ...")
        self.worker_thread = threading.Thread(target=self.capture_worker, args=(url,), daemon=True)
        self.worker_thread.start()

    def refresh_capture(self) -> None:
        self.analyze_url()

    def capture_worker(self, url: str) -> None:
        try:
            if not self.verify_ssl_var.get():
                self.disable_insecure_warnings()
            form, response = capture_login_form(
                url,
                timeout=self.get_float_setting(self.timeout_var, default=8.0, minimum=1.0),
                verify_ssl=bool(self.verify_ssl_var.get()),
            )
            selected = {field.index for field in form.fields if field.fuzz}
            raw = raw_request_from_form(form, selected)
            template = RawRequestTemplate.from_text(raw, default_scheme=urlparse(form.action_url).scheme or "https", base_url=None)
            alerts = collect_security_alerts(template, response)
            self.events.put(("captured", {"form": form, "alerts": alerts, "status": response.status_code, "length": len(response.content)}))
        except Exception as exc:
            self.events.put(("error", f"{exc.__class__.__name__}: {exc}"))

    def disable_insecure_warnings(self) -> None:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    def on_captured(self, payload: dict[str, object]) -> None:
        self.current_form = payload["form"]  # type: ignore[assignment]
        self.fuzz_indices = {field.index for field in self.current_form.fields if field.fuzz}
        self.populate_fields()
        self.update_request_preview()
        alerts = payload.get("alerts", [])
        status = payload.get("status", "-")
        length = payload.get("length", "-")
        self.audit_alerts = [str(item) for item in alerts] if isinstance(alerts, list) else []
        self.lockout_alert = None
        self.capture_status = status
        self.capture_length = length
        lines = [
            f"Captura OK [{self.current_form.capture_mode}]: {self.current_form.method} {self.current_form.action_url}",
            f"Respuesta base: HTTP {status} | Length {length}",
        ]
        if alerts:
            lines.extend(str(item) for item in alerts)
        else:
            lines.append("No se generaron alertas iniciales de controles.")
        self.write_audit("\n".join(lines))
        self.refresh_findings_view()
        self.start_button.configure(state="normal")

    def populate_fields(self) -> None:
        self.field_rows.clear()
        for item in self.field_tree.get_children():
            self.field_tree.delete(item)
        if not self.current_form:
            return
        for field in self.current_form.fields:
            iid = str(field.index)
            self.field_rows[iid] = field
            self.field_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "Si" if field.index in self.fuzz_indices else "No",
                    field.name,
                    field.field_type,
                    field.role,
                    field.value[:120],
                ),
            )

    def toggle_selected_field(self) -> None:
        selection = self.field_tree.selection()
        if not selection:
            return
        field = self.field_rows.get(selection[0])
        if not field:
            return
        if field.index in self.fuzz_indices:
            self.fuzz_indices.remove(field.index)
        else:
            self.fuzz_indices.add(field.index)
        self.populate_fields()
        self.field_tree.selection_set(str(field.index))
        self.update_request_preview()

    def mark_default_fields(self) -> None:
        if not self.current_form:
            return
        self.fuzz_indices = {field.index for field in self.current_form.fields if field.role in {"username", "password"}}
        if not self.fuzz_indices and self.current_form.fields:
            self.fuzz_indices = {self.current_form.fields[0].index}
        self.populate_fields()
        self.update_request_preview()

    def update_request_preview(self) -> None:
        if not self.current_form:
            return
        raw = raw_request_from_form(self.current_form, self.fuzz_indices)
        self.request_text.delete("1.0", "end")
        self.request_text.insert("1.0", raw)

    def load_wordlist_into(self, textbox: object) -> None:
        path = filedialog.askopenfilename(title="Seleccionar wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            values = load_wordlist(path)
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        textbox.delete("1.0", "end")
        textbox.insert("1.0", "\n".join(values))

    def restore_default_wordlists(self) -> None:
        self.users_text.delete("1.0", "end")
        self.users_text.insert("1.0", "\n".join(DEFAULT_USER_WORDLIST))
        self.passwords_text.delete("1.0", "end")
        self.passwords_text.insert("1.0", "\n".join(DEFAULT_PASSWORD_WORDLIST))

    def current_payload_lists(self, roles: Sequence[str]) -> list[list[str]]:
        users = split_text_wordlist(self.users_text.get("1.0", "end"))
        passwords = split_text_wordlist(self.passwords_text.get("1.0", "end"))
        if not users:
            users = DEFAULT_USER_WORDLIST
        if not passwords:
            passwords = DEFAULT_PASSWORD_WORDLIST
        return payload_lists_for_roles(roles, users, passwords)

    def infer_marker_roles(self, template: RawRequestTemplate) -> list[str]:
        if self.current_form:
            roles = marker_roles_from_form(self.current_form, self.fuzz_indices)
            if len(roles) == len(template.markers):
                return roles
        if len(template.markers) == 1:
            return ["password"]
        return ["username" if index == 0 else "password" for index in range(len(template.markers))]

    def build_current_template(self) -> tuple[RawRequestTemplate, list[str]]:
        raw = self.request_text.get("1.0", "end").strip()
        if "§" not in raw:
            if not self.current_form:
                raise ValueError("Analiza una URL o pega una request con marcadores §...§.")
            raw = raw_request_from_form(self.current_form, self.fuzz_indices)
        template = RawRequestTemplate.from_text(raw, default_scheme="https", base_url=None)
        return template, self.infer_marker_roles(template)

    def start_attack(self) -> None:
        try:
            template, roles = self.build_current_template()
            payload_lists = self.current_payload_lists(roles)
            audit_limit = self.get_int_setting(self.audit_limit_var, default=15, minimum=1)
            max_requests = self.get_int_setting(self.max_requests_var, default=100, minimum=0)
            if max_requests < 0:
                raise ValueError("Peticiones maximas debe ser 0 (sin limite) o un entero positivo.")
            threads = self.get_int_setting(self.threads_var, default=4, minimum=1)
            timeout = self.get_float_setting(self.timeout_var, default=8.0, minimum=1.0)
            delay = self.get_float_setting(self.delay_var, default=0.2, minimum=0.0)
            grep_value = self.grep_var.get().strip()
            grep_patterns = compile_grep_patterns([], [grep_value] if grep_value else [])
            self.last_roles = list(roles)
            self.last_run_config = {
                "attack": self.mode_var.get(),
                "audit_limit": audit_limit,
                "max_requests": max_requests,
                "threads": threads,
                "timeout": timeout,
                "delay": delay,
                "grep": grep_value,
                "verify_ssl": bool(self.verify_ssl_var.get()),
                "allow_redirects": bool(self.follow_redirects_var.get()),
                "url_encode": bool(self.url_encode_var.get()),
            }
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        self.results.clear()
        self.lockout_alert = None
        self.timing_analysis = None
        self.update_timing_view()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.stop_event.clear()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.write_audit("Ejecutando auditoria...")
        self.refresh_findings_view()

        args = {
            "template": template,
            "payload_lists": payload_lists,
            "attack": self.mode_var.get(),
            "audit_limit": audit_limit,
            "max_requests": max_requests,
            "threads": threads,
            "timeout": timeout,
            "delay": delay,
            "grep_patterns": grep_patterns,
            "verify_ssl": bool(self.verify_ssl_var.get()),
            "allow_redirects": bool(self.follow_redirects_var.get()),
            "url_encode": bool(self.url_encode_var.get()),
        }
        self.worker_thread = threading.Thread(target=self.attack_worker, kwargs=args, daemon=True)
        self.worker_thread.start()

    def attack_worker(
        self,
        *,
        template: RawRequestTemplate,
        payload_lists: list[list[str]],
        attack: str,
        audit_limit: int,
        max_requests: int,
        threads: int,
        timeout: float,
        delay: float,
        grep_patterns: list[tuple[str, Pattern[str]]],
        verify_ssl: bool,
        allow_redirects: bool,
        url_encode: bool,
    ) -> None:
        if not verify_ssl:
            self.disable_insecure_warnings()
        try:
            base_response = request_base_response(
                template,
                timeout=timeout,
                verify_ssl=verify_ssl,
                allow_redirects=allow_redirects,
            )
            self.events.put(("audit", collect_security_alerts(template, base_response)))
            jobs = iter_attack_jobs(
                attack=attack,
                base_payloads=template.base_payloads,
                payload_lists=payload_lists,
                url_encode=url_encode,
                max_requests=max_requests,
            )
            shared_delay = SharedDelay(delay)
            results: list[AttackResult] = []

            def submit_next(executor: concurrent.futures.ThreadPoolExecutor) -> concurrent.futures.Future[AttackResult] | None:
                if self.stop_event.is_set():
                    return None
                try:
                    job = next(jobs)
                except StopIteration:
                    return None
                return executor.submit(
                    send_attack_request,
                    template=template,
                    job=job,
                    timeout=timeout,
                    verify_ssl=verify_ssl,
                    allow_redirects=allow_redirects,
                    grep_patterns=grep_patterns,
                    shared_delay=shared_delay,
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                pending: set[concurrent.futures.Future[AttackResult]] = set()
                for _ in range(threads):
                    future = submit_next(executor)
                    if future:
                        pending.add(future)

                while pending:
                    done, pending = concurrent.futures.wait(
                        pending,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    for future in done:
                        result = future.result()
                        results.append(result)
                        self.events.put(("result", result))
                        next_future = submit_next(executor)
                        if next_future:
                            pending.add(next_future)
                    if self.stop_event.is_set():
                        for future in pending:
                            future.cancel()
                        break

            results.sort(key=lambda item: item.request_id)
            alert = lockout_vulnerability_alert(results, audit_limit)
            self.events.put(("done", {"count": len(results), "alert": alert}))
        except Exception as exc:
            self.events.put(("error", f"{exc.__class__.__name__}: {exc}"))
            self.events.put(("done", {"count": 0, "alert": None}))

    def stop_attack(self) -> None:
        self.stop_event.set()
        self.write_audit("Deteniendo...")

    def process_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "captured":
                    self.on_captured(payload)  # type: ignore[arg-type]
                elif event == "audit":
                    alerts = payload if isinstance(payload, list) else []
                    self.audit_alerts = [str(item) for item in alerts]
                    self.refresh_findings_view()
                    self.append_audit("\n".join(alerts) if alerts else "Auditoria inicial sin alertas.")
                elif event == "result":
                    self.add_result(payload)  # type: ignore[arg-type]
                elif event == "done":
                    self.on_done(payload)  # type: ignore[arg-type]
                elif event == "error":
                    self.append_audit(str(payload))
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self.process_events)

    def add_result(self, result: AttackResult) -> None:
        self.results.append(result)
        grep = result.grep_match
        if result.lockout_hint:
            grep = f"{grep} | lockout-hint" if grep != "-" else "lockout-hint"
        self.results_tree.insert(
            "",
            "end",
            iid=f"request-{result.request_id}",
            values=(
                result.request_id,
                result.payload_summary[:220],
                result.status_code if not result.error else "ERR",
                result.length,
                grep,
                f"{result.elapsed_ms} ms" if not result.error else result.error[:80],
            ),
        )
        self.update_timing_view()

    def update_timing_view(self) -> None:
        self.timing_analysis = analyze_response_times(self.results)
        if hasattr(self, "timing_status_label"):
            color = "#93c5fd"
            if self.timing_analysis and self.timing_analysis.verdict == "DEGRADACION PROGRESIVA":
                color = "#fca5a5"
            elif self.timing_analysis and self.timing_analysis.verdict == "VARIACION ALTA":
                color = "#fbbf24"
            self.timing_status_label.configure(
                text=format_response_time_analysis(self.timing_analysis),
                text_color=color,
            )

        if not hasattr(self, "results_tree"):
            return
        slow_ids = set(self.timing_analysis.slow_request_ids if self.timing_analysis else ())
        for item in self.results_tree.get_children():
            values = self.results_tree.item(item, "values")
            try:
                request_id = int(values[0])
            except (IndexError, TypeError, ValueError):
                continue
            self.results_tree.item(item, tags=("slow",) if request_id in slow_ids else ())

    def on_done(self, payload: dict[str, object]) -> None:
        count = payload.get("count", len(self.results))
        alert = payload.get("alert")
        self.lockout_alert = str(alert) if alert else None
        self.update_timing_view()
        self.refresh_findings_view()
        lines = [f"Finalizado. Peticiones ejecutadas: {count}"]
        if alert:
            lines.append(str(alert))
        lines.append(format_response_time_analysis(self.timing_analysis))
        self.append_audit("\n".join(lines))
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def export_html_report(self) -> None:
        if not self.current_form and not self.results:
            messagebox.showinfo(APP_NAME, "Primero captura una URL o ejecuta una auditoria.")
            return

        reports_dir = Path(__file__).resolve().parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        default_name = f"intruder_report_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path = filedialog.asksaveasfilename(
            title="Guardar reporte HTML",
            initialdir=str(reports_dir),
            initialfile=default_name,
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            report_html = self.build_html_report()
            output_path = Path(path)
            output_path.write_text(report_html, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo guardar el reporte:\n{exc}")
            return

        messagebox.showinfo(APP_NAME, f"Reporte generado:\n{path}")
        try:
            webbrowser.open(Path(path).resolve().as_uri())
        except Exception:
            pass

    def build_html_report(self) -> str:
        def esc(value: object) -> str:
            return html_lib.escape(str(value), quote=True)

        def yes_no(value: object) -> str:
            return "Si" if bool(value) else "No"

        generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        form = self.current_form
        source_url = self.url_var.get().strip() or (form.source_url if form else "-")
        action_url = form.action_url if form else "-"
        method = form.method if form else "-"
        capture_mode = form.capture_mode if form else "-"
        request_preview = self.request_text.get("1.0", "end").strip() if hasattr(self, "request_text") else ""
        audit_rows = self.control_status_rows()
        vuln_count = sum(1 for row in audit_rows if row[3] == "vuln")
        ok_count = sum(1 for row in audit_rows if row[3] == "ok")
        pending_count = sum(1 for row in audit_rows if row[3] == "pending")

        status_counts: dict[int, int] = {}
        for result in self.results:
            status_counts[result.status_code] = status_counts.get(result.status_code, 0) + 1
        timing = self.timing_analysis or analyze_response_times(self.results)
        slow_ids = set(timing.slow_request_ids if timing else ())

        config = {
            "Modo de ataque": self.last_run_config.get("attack", self.mode_var.get()),
            "Descripcion modo": ATTACK_MODE_DESCRIPTIONS.get(str(self.last_run_config.get("attack", self.mode_var.get())), ""),
            "Hilos": self.last_run_config.get("threads", self.threads_var.get()),
            "Timeout": self.last_run_config.get("timeout", self.timeout_var.get()),
            "Delay": self.last_run_config.get("delay", self.delay_var.get()),
            "Peticiones maximas": self.last_run_config.get("max_requests", self.max_requests_var.get()),
            "Umbral lockout": self.last_run_config.get("audit_limit", self.audit_limit_var.get()),
            "URL encode": yes_no(self.last_run_config.get("url_encode", self.url_encode_var.get())),
            "Verificar SSL": yes_no(self.last_run_config.get("verify_ssl", self.verify_ssl_var.get())),
            "Seguir redirects": yes_no(self.last_run_config.get("allow_redirects", self.follow_redirects_var.get())),
            "Grep": self.last_run_config.get("grep", self.grep_var.get()),
        }

        fields = form.fields if form else []
        field_rows = "\n".join(
            "<tr>"
            f"<td>{esc(field.name)}</td>"
            f"<td>{esc(field.field_type)}</td>"
            f"<td>{esc(field.role)}</td>"
            f"<td>{'Si' if field.index in self.fuzz_indices else 'No'}</td>"
            f"<td><code>{esc(field.value)}</code></td>"
            "</tr>"
            for field in fields
        ) or "<tr><td colspan='5'>Sin parametros capturados.</td></tr>"

        audit_table_rows = "\n".join(
            "<tr class='{klass}'>"
            f"<td>{esc(check)}</td><td>{esc(control)}</td><td>{esc(result)}</td>"
            "</tr>".format(klass=klass)
            for check, control, result, klass in audit_rows
        )

        config_rows = "\n".join(
            f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>"
            for key, value in config.items()
        )

        user_samples = split_text_wordlist(self.users_text.get("1.0", "end"))[:10] if hasattr(self, "users_text") else []
        password_samples = split_text_wordlist(self.passwords_text.get("1.0", "end"))[:10] if hasattr(self, "passwords_text") else []
        result_payload_samples = []
        seen_payloads: set[str] = set()
        for result in self.results:
            if result.payload_summary not in seen_payloads:
                seen_payloads.add(result.payload_summary)
                result_payload_samples.append(result.payload_summary)
            if len(result_payload_samples) >= 20:
                break
        payload_rows = "\n".join(
            f"<tr><td>{idx}</td><td><code>{esc(payload)}</code></td></tr>"
            for idx, payload in enumerate(result_payload_samples, start=1)
        ) or "<tr><td colspan='2'>Sin payloads ejecutados todavia.</td></tr>"

        result_rows = "\n".join(
            f"<tr class='{'slow' if result.request_id in slow_ids else ''}'>"
            f"<td>{result.request_id}</td>"
            f"<td><code>{esc(result.payload_summary)}</code></td>"
            f"<td>{result.status_code if not result.error else 'ERR'}</td>"
            f"<td>{result.length}</td>"
            f"<td>{esc(result.grep_match)}</td>"
            f"<td>{result.elapsed_ms} ms</td>"
            f"<td>{esc(result.error)}</td>"
            "</tr>"
            for result in self.results
        ) or "<tr><td colspan='7'>Sin resultados ejecutados.</td></tr>"

        status_summary = ", ".join(f"HTTP {status}: {count}" for status, count in sorted(status_counts.items())) or "Sin respuestas"
        raw_alerts = "\n".join(self.audit_alerts + ([self.lockout_alert] if self.lockout_alert else [])) or "Sin hallazgos reportados."
        if timing:
            timing_rows = (
                f"<tr><th>Muestras validas</th><td>{timing.count}</td></tr>"
                f"<tr><th>Minimo</th><td>{timing.minimum_ms} ms</td></tr>"
                f"<tr><th>Media</th><td>{timing.mean_ms:.1f} ms</td></tr>"
                f"<tr><th>Mediana</th><td>{timing.median_ms:.1f} ms</td></tr>"
                f"<tr><th>P95</th><td>{timing.p95_ms} ms</td></tr>"
                f"<tr><th>Maximo</th><td>{timing.maximum_ms} ms</td></tr>"
                f"<tr><th>Desviacion / CV</th><td>{timing.stdev_ms:.1f} ms / {timing.coefficient_variation_pct:.1f}%</td></tr>"
                f"<tr><th>Mediana inicial</th><td>{timing.first_window_median_ms:.1f} ms</td></tr>"
                f"<tr><th>Mediana final</th><td>{timing.last_window_median_ms:.1f} ms</td></tr>"
                f"<tr><th>Delta inicio-fin</th><td>{timing.trend_delta_ms:+.1f} ms ({timing.trend_delta_pct:+.1f}%)</td></tr>"
                f"<tr><th>Peticiones lentas</th><td>{esc(', '.join(str(item) for item in timing.slow_request_ids) or 'Ninguna')}</td></tr>"
                f"<tr><th>Evaluacion</th><td><strong>{esc(timing.verdict)}</strong></td></tr>"
            )
        else:
            timing_rows = "<tr><td colspan='2'>Sin respuestas validas para analizar.</td></tr>"

        return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Intruder Report - {esc(source_url)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f5f7fb; color: #111827; }}
    header {{ background: #111827; color: #f9fafb; padding: 28px 34px; }}
    main {{ padding: 24px 34px 42px; }}
    h1, h2 {{ margin: 0 0 12px; }}
    h2 {{ margin-top: 28px; border-bottom: 2px solid #d1d5db; padding-bottom: 6px; }}
    .summary {{ display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 12px; margin-top: 18px; }}
    .card {{ background: white; border: 1px solid #d1d5db; border-radius: 8px; padding: 14px; }}
    .metric {{ font-size: 26px; font-weight: 700; }}
    .muted {{ color: #6b7280; }}
    .vuln {{ background: #fee2e2; color: #7f1d1d; }}
    .ok {{ background: #dcfce7; color: #14532d; }}
    .pending {{ background: #fef3c7; color: #78350f; }}
    .info {{ background: #dbeafe; color: #1e3a8a; }}
    tr.slow td {{ background: #fef3c7; color: #78350f; font-weight: 600; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d1d5db; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #e5e7eb; }}
    code, pre {{ font-family: Consolas, monospace; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #111827; color: #e5e7eb; padding: 14px; border-radius: 8px; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 999px; font-weight: 700; }}
  </style>
</head>
<body>
  <header>
    <h1>Intruder - Reporte de Auditoria de Login</h1>
    <div>Generado: {esc(generated_at)}</div>
    <div>URL evaluada: {esc(source_url)}</div>
  </header>
  <main>
    <section class="summary">
      <div class="card"><div class="metric">{vuln_count}</div><div>Hallazgos VULN</div></div>
      <div class="card"><div class="metric">{ok_count}</div><div>Checks OK</div></div>
      <div class="card"><div class="metric">{pending_count}</div><div>Pendientes</div></div>
      <div class="card"><div class="metric">{len(self.results)}</div><div>Peticiones ejecutadas</div></div>
    </section>

    <h2>Objetivo y Captura</h2>
    <table>
      <tr><th>URL inicial</th><td>{esc(source_url)}</td></tr>
      <tr><th>Endpoint capturado</th><td>{esc(action_url)}</td></tr>
      <tr><th>Metodo</th><td>{esc(method)}</td></tr>
      <tr><th>Modo captura</th><td>{esc(capture_mode)}</td></tr>
      <tr><th>Respuesta base</th><td>HTTP {esc(self.capture_status)} | Length {esc(self.capture_length)}</td></tr>
      <tr><th>Resumen status</th><td>{esc(status_summary)}</td></tr>
    </table>

    <h2>Hallazgos</h2>
    <table>
      <tr><th>Check</th><th>Control</th><th>Resultado</th></tr>
      {audit_table_rows}
    </table>
    <h3>Texto de evidencia</h3>
    <pre>{esc(raw_alerts)}</pre>

    <h2>Parametros Capturados</h2>
    <table>
      <tr><th>Parametro</th><th>Tipo</th><th>Rol</th><th>Fuzz</th><th>Valor base</th></tr>
      {field_rows}
    </table>

    <h2>Configuracion de Ejecucion</h2>
    <table>{config_rows}</table>

    <h2>Analisis de Tiempos de Respuesta</h2>
    <p class="muted">Compara minimos, tendencia entre las primeras y ultimas respuestas, dispersion y peticiones lentas.</p>
    <table>{timing_rows}</table>

    <h2>Payloads Usados</h2>
    <p class="muted">Muestras de wordlists y payloads realmente ejecutados.</p>
    <table>
      <tr><th>Users sample</th><td><code>{esc(', '.join(user_samples))}</code></td></tr>
      <tr><th>Creds sample</th><td><code>{esc(', '.join(password_samples))}</code></td></tr>
    </table>
    <br>
    <table>
      <tr><th>#</th><th>Payload(s) ejecutado(s)</th></tr>
      {payload_rows}
    </table>

    <h2>Request Marcada</h2>
    <pre>{esc(request_preview)}</pre>

    <h2>Resultados</h2>
    <table>
      <tr><th>ID</th><th>Payload(s)</th><th>Status</th><th>Length</th><th>Grep-Match</th><th>Tiempo</th><th>Error</th></tr>
      {result_rows}
    </table>
  </main>
</body>
</html>
"""

    def write_audit(self, text: str) -> None:
        self.audit_text.configure(state="normal")
        self.audit_text.delete("1.0", "end")
        self.audit_text.insert("1.0", text)
        self.audit_text.configure(state="disabled")

    def append_audit(self, text: str) -> None:
        self.audit_text.configure(state="normal")
        current = self.audit_text.get("1.0", "end").strip()
        prefix = "\n\n" if current else ""
        self.audit_text.insert("end", f"{prefix}{text}")
        self.audit_text.see("end")
        self.audit_text.configure(state="disabled")


def run_gui() -> int:
    missing = []
    if ctk is None:
        missing.append("customtkinter")
    if BeautifulSoup is None:
        missing.append("beautifulsoup4")
    if missing:
        print("Faltan dependencias GUI: " + ", ".join(missing), file=sys.stderr)
        print("Ejecuta: pip install customtkinter beautifulsoup4 lxml", file=sys.stderr)
        return 2
    app = IntruderGuiApp()
    app.mainloop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--gui", action="store_true", help="Abre la interfaz grafica.")
    parser.add_argument("-r", "--request", help="Archivo con la peticion HTTP cruda con posiciones §...§.")
    parser.add_argument("-w", "--wordlist", action="append", default=[], help="Wordlist. Repetible por posicion.")
    parser.add_argument("--payload", action="append", default=[], help="Payload inline. Puede repetirse.")
    parser.add_argument(
        "--attack",
        default="sniper",
        choices=["sniper", "battering-ram", "pitchfork", "cluster-bomb"],
        help="Modo de iteracion.",
    )
    parser.add_argument("--scheme", default="https", choices=["http", "https"], help="Esquema si la peticion usa path relativo.")
    parser.add_argument("--base-url", help="Base URL si no existe Host o se desea forzar destino.")
    parser.add_argument("--threads", type=int, default=4, help="Hilos concurrentes.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout por peticion en segundos.")
    parser.add_argument("--delay", type=float, default=0.0, help="Retardo global entre peticiones.")
    parser.add_argument("--audit-limit", type=int, default=15, help="Umbral de respuestas para evaluar rate-limit/lockout.")
    parser.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Maximo de peticiones (0=sin limite). Por compatibilidad, si se omite usa --audit-limit.",
    )
    parser.add_argument("--url-encode", action="store_true", help="Codifica payloads con URL encoding.")
    parser.add_argument("--verify-ssl", action="store_true", help="Verifica certificados TLS.")
    parser.add_argument("--no-redirects", dest="allow_redirects", action="store_false", help="No seguir redirecciones.")
    parser.set_defaults(allow_redirects=True)
    parser.add_argument("--grep", action="append", default=[], help="Texto exacto a buscar en respuestas.")
    parser.add_argument("--grep-regex", action="append", default=[], help="Regex a buscar en respuestas.")
    parser.add_argument("--self-test", action="store_true", help="Ejecuta pruebas offline sin red.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if not raw_args:
        return run_gui()
    parser = build_parser()
    args = parser.parse_args(raw_args)
    if args.gui:
        return run_gui()
    if args.self_test:
        return run_self_test()
    if not args.request:
        parser.error("--request es obligatorio salvo con --self-test.")
    if not args.wordlist and not args.payload:
        parser.error("Debes indicar -w/--wordlist o --payload.")
    return run_attack(args)


if __name__ == "__main__":
    raise SystemExit(main())
