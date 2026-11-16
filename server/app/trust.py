"""Дополнительные доверенные сертификаты (корневые и промежуточные центры сертификации).

Нужны, когда сайт портала подписан центром, которого нет в Windows по умолчанию:
сертификаты Минцифры (Russian Trusted Root CA / Sub CA) или центр своего домена AD.
Администратор загружает их в общих настройках; дальше они:
- попадают в установщик FamilyTime-setup.cmd — он добавляет их в хранилище компьютера
  (корневые — в «Доверенные корневые», промежуточные — в «Промежуточные») до первого
  обращения к порталу;
- уходят агентам 1.4.1+ в политике — агент добавляет их туда же и доверяет им сам,
  поэтому смена сертификата сайта на такой центр не обрывает связь.
"""
from __future__ import annotations

import io
import zipfile
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

MAX_CERTS = 20


def _one(data: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificates(data)
    return [x509.load_der_x509_certificate(data)]


def parse(blobs: list[tuple[str, bytes]]) -> tuple[list[dict], list[str]]:
    """Файлы .cer/.crt/.pem (DER или PEM, в том числе несколько в одном) и zip с ними →
    описания сертификатов центров и список того, что не принято."""
    out, errors = [], []
    queue = list(blobs)
    while queue:
        name, data = queue.pop(0)
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    queue += [(f"{name}/{n}", z.read(n)) for n in z.namelist()
                              if n.lower().endswith((".cer", ".crt", ".pem", ".der"))]
            except zipfile.BadZipFile:
                errors.append(f"{name}: повреждённый zip")
            continue
        try:
            certs = _one(data)
        except Exception:  # noqa: BLE001 — в том числе ГОСТ, который здесь не читается
            errors.append(f"{name}: не читается (ГОСТ-сертификаты Windows без КриптоПро не "
                          "поддерживает — они и не нужны)")
            continue
        for c in certs:
            try:
                info = describe(c)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{name}: {e}")
                continue
            if not info["ca"]:
                errors.append(f"{name}: «{info['subject']}» — сертификат сайта, а не центра "
                              "сертификации; нужен корневой или промежуточный")
                continue
            out.append(info)
    return out, errors


def describe(c: x509.Certificate) -> dict:
    if c.signature_algorithm_oid.dotted_string.startswith("1.2.643"):
        raise ValueError("ГОСТ-сертификат — Windows без КриптоПро его не использует, он не нужен")
    try:
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        ca = c.subject == c.issuer          # старые корневые без расширения
    cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    icn = c.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return {
        "pem": c.public_bytes(serialization.Encoding.PEM).decode(),
        "sha1": c.fingerprint(hashes.SHA1()).hex(),
        "subject": cn[0].value if cn else c.subject.rfc4514_string(),
        "issuer": icn[0].value if icn else c.issuer.rfc4514_string(),
        "not_after": c.not_valid_after_utc.astimezone(timezone.utc).date().isoformat(),
        "root": c.subject == c.issuer,
        "ca": ca,
    }


def merge(current: list[dict], new: list[dict]) -> list[dict]:
    seen = {c["sha1"] for c in current}
    out = list(current)
    for c in new:
        if c["sha1"] not in seen:
            out.append(c)
            seen.add(c["sha1"])
    return out[:MAX_CERTS]


def for_agent(items: list[dict]) -> list[dict]:
    return [{"pem": c["pem"], "root": bool(c["root"]), "sha1": c["sha1"]} for c in items or []]
