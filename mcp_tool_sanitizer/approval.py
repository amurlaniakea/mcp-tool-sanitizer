# Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Approval Identity Binding (Fase 3).

Ata cada aprobacion humana a una identidad persistente del descriptor MCP,
calculada como sha256 sobre (campos canonicos del descriptor YA SANITIZADO
en Fase 1) + server_origin + descriptor_version. Cierra el TOCTOU entre
approval y ejecucion que WebAZ senalo en el post de dev.to de v0.1.0
(2026-08-26): un host que cachee aprobaciones por nombre de tool hereda
confianza sobre contenido que nunca vio.

Diseno completo en:
  vault: spec/features/003-approval-identity-binding/{spec.md, plan.md, tasks.md}
  spec.md AC-1 .. AC-13
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .bytefiel import canonical, verify_tool
from .sanitize import sanitize_tool

# Sentinel para descriptor_version ausente. Distinto de cualquier string que
# un servidor pueda pasar legitimamente, incluyendo el string vacio "".
# (Hallazgo 2 de auditoria: si colapsamos None con "" en el digest, dos
# casos semanticamente distintos producen el mismo hash, bug silencioso.)
# Es un literal de 9 bytes: NUL + NONE + NUL.
VERSION_NONE_SENTINEL = "\x00NONE\x00"


@dataclass(frozen=True)
class ApprovalRecord:
    """Registro de aprobacion humana persistido en un ApprovalStore.

    server_origin:    identificador del servidor MCP (URL completa o huella
                      del cert TLS; NUNCA solo el hostname por riesgo de
                      DNS rebinding).
    tool_name:        nombre de la tool tal como aparece en el descriptor.
    digest:           sha256 hex (64 chars) calculado por descriptor_digest.
    descriptor_version: la version que el servidor anuncio, o None si no
                      anuncio ninguna. None se serializa con VERSION_NONE_SENTINEL
                      en el digest, NO con "".
    """

    server_origin: str
    tool_name: str
    digest: str
    descriptor_version: str | None


class ApprovalStore(ABC):
    """Interfaz abstracta para almacenar aprobaciones.

    La libreria NO impone backend (0 deps runtime). El host implementa
    ApprovalStore sobre su propio storage (fichero, sqlite, redis, ...);
    InMemoryApprovalStore es la unica implementacion incluida, para tests
    y hosts que no necesiten persistencia entre reinicios.
    """

    @abstractmethod
    def get(self, server_origin: str, tool_name: str) -> ApprovalRecord | None: ...

    @abstractmethod
    def put(self, record: ApprovalRecord) -> None: ...

    @abstractmethod
    def invalidate(self, server_origin: str, tool_name: str) -> None: ...


class InMemoryApprovalStore(ApprovalStore):
    """Implementacion de referencia en memoria. NO thread-safe por diseno.

    Si un host necesita thread-safety o persistencia entre reinicios,
    implementa su propio ApprovalStore. Esta clase existe para tests y
    para hosts prototipo; cualquier uso en produccion deberia pasar por
    una implementacion que serialice (con su propio lock externo si
    hace falta concurrencia) y persista (a disco, sqlite, etc.).

    Se pierde al reiniciar el proceso. Esto NO es un fallo del paquete,
    es una decision explicita: la persistencia entre procesos es
    responsabilidad de integracion del host, documentada en el README
    de Fase 3.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ApprovalRecord] = {}

    def get(self, server_origin: str, tool_name: str) -> ApprovalRecord | None:
        return self._records.get((server_origin, tool_name))

    def put(self, record: ApprovalRecord) -> None:
        self._records[(record.server_origin, record.tool_name)] = record

    def invalidate(self, server_origin: str, tool_name: str) -> None:
        self._records.pop((server_origin, tool_name), None)


def descriptor_digest(
    clean_tool: dict,
    server_origin: str,
    descriptor_version: str | None = None,
) -> str:
    """sha256 hex de 64 chars sobre la identidad canonica del descriptor.

    Pasos (ver spec.md AC-1, AC-1a, AC-1b, AC-1c):

    1. Canonizar los tres campos textuales (name, description, schema) con
       `canonical(campo, aggressive=False)` de bytefiel.py. Esto aplica
       NFKC + strip de ocultos, sin heuristica mixed-script (que es
       trabajo de Fase 2, no del digest). Sin esta canonizacion, dos
       representaciones NFKC-equivalentes del mismo contenido (ej. \uFF41
       fullwidth vs 'a' ASCII) darian digests distintos con "changed"
       espurios (mismo tipo de friccion que KI-9b cerro en Fase 2).

    2. Sustituir descriptor_version=None por VERSION_NONE_SENTINEL para
       distinguir "sin version" de "version vacia explicita" en el digest.
       Si colapsamos ambos casos, un servidor que pase descriptor_version=""
       colisiona con "no se dio version" en el hash, bug silencioso.

    3. Serializar un UNICO objeto JSON con los cinco campos
       {name, description, schema, server_origin, descriptor_version} con
       sort_keys=True, separators=(",", ":"), ensure_ascii=False. El
       schema entra como STRING canonico pre-serializado (NO como objeto
       anidado), para que la canonizacion del schema sea un contrato
       explicito de Fase 3, no una dependencia del comportamiento por
       defecto de json.dumps. Si en el futuro alguien anade canonizacion
       especial al sub-schema (ej. campo pattern regex), basta con
       actualizar el canonizado del schema string; el resto de la receta
       no se entera.

    4. sha256 de la cadena UTF-8, hex.

    POR QUE serializacion JSON unica (no concatenacion con separadores
    literales): si concatenamos los campos con f"name={n}\\ndescription={d}\\n..."
    y un valor contiene el separador (ej. description con "\ndescription="
    dentro), dos descriptores con contenido semanticamente distinto
    producen el mismo payload y el mismo digest. Verificado con PoC
    (Hallazgo 4 de auditoria, 2026-09-05). El escapado de JSON cierra
    la ambiguedad porque ningun valor puede reproducir la sintaxis de
    clave-JSON que lo rodea sin ser el mismo escapado.
    """
    canon_name = canonical(clean_tool.get("name", ""), aggressive=False)
    canon_description = canonical(clean_tool.get("description", ""), aggressive=False)
    canon_schema_str = canonical(
        json.dumps(
            clean_tool.get("input_schema", {}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        aggressive=False,
    )
    version_token = (
        VERSION_NONE_SENTINEL if descriptor_version is None else descriptor_version
    )
    payload = json.dumps(
        {
            "name": canon_name,
            "description": canon_description,
            "schema": canon_schema_str,
            "server_origin": server_origin,
            "descriptor_version": version_token,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def check_tool_identity(
    tool: dict,
    server_origin: str,
    store: ApprovalStore,
    *,
    descriptor_version: str | None = None,
    mode: str = "strip",
) -> dict:
    """Compara la identidad del tool contra el store. NUNCA muta el store.

    Pasos en orden estricto (ver spec.md AC-3, AC-4, AC-5, AC-6):

    a) bf = verify_tool(tool). Si no bf["conforming"], devolver
       {"status": "rejected_by_bytefiel", "requires_reapproval": False,
        "digest": None, "prior_digest": None, "byte_fiel": bf, ...}.
       Sin calcular digest, sin consultar store, sin marcar re-aprobacion.
       Una divergencia byte-fiel es un rechazo directo, no un "cambio
       legitimo que requiere re-aprobacion": re-aprobar implicaria que el
       humano puede legitimamente consentir sobre bytes que no vio, y eso
       es exactamente la propiedad que Fase 2 garantiza que NO se puede
       consentir.

    b) san = sanitize_tool(tool, mode=mode).

    c) digest = descriptor_digest(san.clean, server_origin, descriptor_version).

    d) prev = store.get(server_origin, tool.get("name", "")).

    e) prev is None              -> status="new",       requires_reapproval=True.
    f) prev.digest == digest     -> status="approved",   requires_reapproval=False.
    g) prev.digest != digest     -> status="changed",    requires_reapproval=True,
       prior_digest = prev.digest.

    En NINGUN caso esta funcion llama a store.put() ni a store.invalidate().
    Esas mutaciones las hace el host, despues de obtener consentimiento
    humano fresco. Esto es el nucleo de la regla de WebAZ: un digest
    distinto nunca debe actualizar el store por si solo.

    Advertencia de consistencia de mode (AC-13): el host DEBE usar el
    mismo `mode` para todas las llamadas referidas al mismo
    (server_origin, tool_name). Si el host cambia de modo entre llamadas
    (p.ej. de "strip" a "replace"), el digest cambiara aunque el
    contenido "real" no haya cambiado, lo cual forzara re-aprobaciones
    espurias. La libreria no impone un modo unico porque la eleccion
    entre "strip" y "replace" es decision de UX del host; pero el host
    es responsable de mantener la consistencia.
    """
    name = tool.get("name", "")

    # (a) Fase 2 primero. Si diverge byte-fiel, NO continuamos.
    bf = verify_tool(tool)
    if not bf.get("conforming", False):
        return {
            "status": "rejected_by_bytefiel",
            "requires_reapproval": False,
            "digest": None,
            "prior_digest": None,
            "byte_fiel": bf,
            "server_origin": server_origin,
            "tool_name": name,
        }

    # (b) Fase 1 sobre el tool recibido (no sobre uno del store).
    san = sanitize_tool(tool, mode=mode)

    # (c) digest del .clean (Fase 1), no del tool crudo.
    digest = descriptor_digest(san.clean, server_origin, descriptor_version)

    # (d) consultar store. Ninguna mutacion.
    prev = store.get(server_origin, name)

    # (e) / (f) / (g)
    if prev is None:
        return {
            "status": "new",
            "requires_reapproval": True,
            "digest": digest,
            "prior_digest": None,
            "byte_fiel": bf,
            "server_origin": server_origin,
            "tool_name": name,
        }
    if prev.digest == digest:
        return {
            "status": "approved",
            "requires_reapproval": False,
            "digest": digest,
            "prior_digest": prev.digest,
            "byte_fiel": bf,
            "server_origin": server_origin,
            "tool_name": name,
        }
    # digest distinto
    return {
        "status": "changed",
        "requires_reapproval": True,
        "digest": digest,
        "prior_digest": prev.digest,
        "byte_fiel": bf,
        "server_origin": server_origin,
        "tool_name": name,
    }


__all__ = [
    "VERSION_NONE_SENTINEL",
    "ApprovalRecord",
    "ApprovalStore",
    "InMemoryApprovalStore",
    "check_tool_identity",
    "descriptor_digest",
]
