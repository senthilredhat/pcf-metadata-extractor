"""App, route, service extraction (ported from extract-pcf-inventory.sh)."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from pcf_inventory_extractor import sanitize
from pcf_inventory_extractor.client import fetch_all_paged, fetch_safe_body
from pcf_inventory_extractor.constants import CONFIG_API_MAX_RETRIES_OPTIONAL
from pcf_inventory_extractor.extraction import process
from pcf_inventory_extractor.types import ExtractorLike
from pcf_inventory_extractor.utils.helpers import util_append_to_list


def extract_apps_in_space(
    ex: ExtractorLike,
    space_guid: str,
    space_name: str,
    space_security_groups: str,
    org_security_groups: str,
    global_security_groups: str,
) -> None:
    path = f"/v3/apps?space_guids={space_guid}"
    apps_json = fetch_all_paged(
        ex.client, path, f"Apps listing for space {space_name!r}", critical=True
    )
    ac = int((apps_json.get("pagination") or {}).get("total_results", 0) or 0)
    if not ac:
        print(f"   No apps found in space {space_name!r}", file=sys.stderr)
        return
    print(f"   Found {ac} app(s) in space {space_name!r}", file=sys.stderr)
    for res in apps_json.get("resources") or []:
        ag = (res or {}).get("guid", "")
        if ag:
            extract_app_metadata(
                ex,
                str(ag),
                apps_json,
                space_name,
                space_security_groups,
                org_security_groups,
                global_security_groups,
            )


def extract_app_metadata(
    ex: ExtractorLike,
    app_guid: str,
    apps_json: dict[str, Any],
    space_name: str,
    space_security_groups: str,
    org_security_groups: str,
    global_security_groups: str,
) -> None:
    app_name = ""
    app_state = ""
    for res in apps_json.get("resources") or []:
        if (res or {}).get("guid") == app_guid:
            app_name = str((res or {}).get("name", ""))
            app_state = str((res or {}).get("state", ""))
            break
    ad = fetch_safe_body(ex.client, f"/v3/apps/{app_guid}")
    if not ex._validate(ad, f"App details for {app_name}"):
        print(
            f"   WARNING: Failed to retrieve app details for {app_name!r}",
            file=sys.stderr,
        )
    try:
        app_details_d = json.loads(ad) if ad and ad != "{}" else {}
    except json.JSONDecodeError:
        app_details_d = {}
    lifecycle_type = str(
        (app_details_d.get("lifecycle") or {}).get("type", "") or ""
    )
    buildpacks = ""
    buildpack_details = ""
    runtime_version = ""
    cr = ex.client.fetch_with_retry(
        f"/v3/apps/{app_guid}/relationships/current_droplet"
    )
    current_droplet_guid = ""
    if not cr.startswith("__ERROR"):
        try:
            current_droplet_guid = str(
                ((json.loads(cr).get("data") or {}) or {}).get("guid", "") or ""
            )
        except json.JSONDecodeError:
            current_droplet_guid = ""
    if lifecycle_type == "buildpack":
        bp, bpd, rt = _extract_buildpack_metadata(
            ex, current_droplet_guid, app_name
        )
        buildpacks, buildpack_details, runtime_version = bp, bpd, rt
    elif lifecycle_type == "docker":
        bp, bpd = _extract_docker_metadata(
            ex, current_droplet_guid, app_name
        )
        buildpacks, buildpack_details = bp, bpd
    else:
        if lifecycle_type:
            ex._debug(f"Unknown lifecycle {lifecycle_type!r} for {app_name!r}")
    if not buildpacks or buildpacks == "null":
        ld = (app_details_d.get("lifecycle") or {}).get("data") or {}
        bps = ld.get("buildpacks") or []
        if isinstance(bps, list):
            buildpacks = ";".join(str(b) for b in bps if b)
    if buildpack_details == "null":
        buildpack_details = ""
    if runtime_version == "null":
        runtime_version = ""
    routes, domains = _extract_routes_and_domains(ex, app_guid, app_name)
    (
        service_instances,
        service_bindings,
        volume_services,
        volume_size,
    ) = _extract_services_block(ex, app_guid, app_name)
    env_vars = ""
    if not ex.skip_env_vars:
        env_raw = ex.client.fetch_with_retry(
            f"/v3/apps/{app_guid}/env", CONFIG_API_MAX_RETRIES_OPTIONAL
        )
        if env_raw.startswith("__ERROR"):
            print(
                f"   Warning: Environment variables for {app_name} unavailable",
                file=sys.stderr,
            )
            env_raw = "{}"
        env_vars = sanitize.sanitize_env_vars_from_api(env_raw, ex._validate)
        if env_vars == "null":
            env_vars = ""
    process.extract_processes(
        ex,
        app_guid,
        app_name,
        app_state,
        buildpacks,
        buildpack_details,
        runtime_version,
        routes,
        domains,
        service_instances,
        service_bindings,
        volume_services,
        volume_size,
        env_vars,
        space_name,
        space_security_groups,
        org_security_groups,
        global_security_groups,
    )


def _extract_buildpack_metadata(
    ex: ExtractorLike, droplet_guid: str, app_name: str
) -> tuple[str, str, str]:
    if not droplet_guid:
        ex._debug(f"No current droplet GUID for {app_name!r}")
        return "", "", ""
    dj = ex.client.fetch_with_retry(f"/v3/droplets/{droplet_guid}")
    if dj.startswith("__ERROR") or not ex._validate(
        dj, f"Droplet {droplet_guid} for {app_name}"
    ):
        print(
            f"   WARNING: Failed droplet details for {app_name!r}",
            file=sys.stderr,
        )
        return "", "", ""
    d = json.loads(dj)
    bps = d.get("buildpacks") or []
    names: list[str] = []
    details: list[str] = []
    for bp in bps if isinstance(bps, list) else []:
        if not isinstance(bp, dict):
            continue
        n = str(bp.get("name", "") or "")
        if n:
            names.append(n)
        ver = str(bp.get("version", "") or "")
        det = str(bp.get("detect_output", "") or "")
        inner = " ".join(x for x in (n, ver, det) if x)
        if inner:
            details.append(inner)
    buildpacks = ";".join(names)
    buildpack_details = ";".join(details)
    env = d.get("environment_variables") or {}
    if not isinstance(env, dict):
        env = {}
    runtime_version = str(
        env.get("BP_JVM_VERSION")
        or env.get("BP_JAVA_VERSION")
        or env.get("JAVA_VERSION")
        or ""
    )
    return buildpacks, buildpack_details, runtime_version


def _extract_docker_metadata(
    ex: ExtractorLike, droplet_guid: str, app_name: str
) -> tuple[str, str]:
    if not droplet_guid:
        return "", ""
    dj = ex.client.fetch_with_retry(f"/v3/droplets/{droplet_guid}")
    if dj.startswith("__ERROR") or not ex._validate(
        dj, f"Droplet {droplet_guid} for {app_name}"
    ):
        print(
            f"   WARNING: Docker droplet for {app_name!r}",
            file=sys.stderr,
        )
        return "", ""
    d = json.loads(dj)
    docker_image = str(d.get("image", "") or "")
    if not docker_image:
        return "", ""
    registry = "docker.io" if "/" not in docker_image else docker_image.split("/")[0]
    return docker_image, f"registry:{registry}"


def _domain_guids_from_routes(routes_json: dict[str, Any]) -> set[str]:
    guids: set[str] = set()
    for res in routes_json.get("resources") or []:
        r = res or {}
        rel = (r.get("relationships") or {})
        dom = (rel.get("domain") or {}).get("data") or {}
        g = dom.get("guid")
        if g:
            guids.add(str(g))
    return guids


def _extract_domains_for_guids(
    ex: ExtractorLike, guids: set[str]
) -> str:
    names: list[str] = []
    for domain_guid in sorted(guids):
        dr = ex.client.fetch_with_retry(
            f"/v3/domains/{domain_guid}", CONFIG_API_MAX_RETRIES_OPTIONAL
        )
        if dr.startswith("__ERROR"):
            continue
        try:
            dn = str((json.loads(dr).get("name") or "") or "")
        except json.JSONDecodeError:
            dn = ""
        if dn:
            names.append(dn)
    return ";".join(names)


def _extract_routes_and_domains(
    ex: ExtractorLike, app_guid: str, app_name: str
) -> tuple[str, str]:
    routes_json = fetch_all_paged(
        ex.client,
        f"/v3/routes?app_guids={app_guid}",
        f"Routes for app {app_name!r}",
        critical=False,
    )
    if not ex._validate(
        json.dumps(routes_json), f"Routes for {app_name}"
    ):
        print(
            f"   WARNING: Routes for {app_name!r} incomplete",
            file=sys.stderr,
        )
        return "", ""
    urls: list[str] = []
    for res in routes_json.get("resources") or []:
        u = str((res or {}).get("url", "") or "")
        if u:
            urls.append(u)
    routes = ";".join(urls)
    domains = _extract_domains_for_guids(
        ex, _domain_guids_from_routes(routes_json)
    )
    return routes, domains


def _format_service_entry(
    instance_name: str,
    instance_guid: str,
    offering_name: str,
    plan_name: str,
    instance_type: str,
) -> str:
    entry = instance_name or instance_guid or ""
    details = ""
    if offering_name:
        details = offering_name
    if plan_name:
        details = util_append_to_list(details, plan_name, "/")
    if instance_type:
        details = f"{details} ({instance_type})" if details else instance_type
    if details:
        entry = f"{entry} [{details}]"
    return entry


def _extract_service_instance_details(
    ex: ExtractorLike, service_instance_guid: str
) -> str:
    si = ex.client.fetch_with_retry(
        f"/v3/service_instances/{service_instance_guid}",
        CONFIG_API_MAX_RETRIES_OPTIONAL,
    )
    if si.startswith("__ERROR") or not ex._validate(
        si, f"Service instance {service_instance_guid}"
    ):
        ex._debug(f"Missing service instance {service_instance_guid}")
        return ""
    sj = json.loads(si)
    sin = str(sj.get("name", "") or "")
    sit = str(sj.get("type", "") or "")
    plan_guid = str(
        ((sj.get("relationships") or {})
         .get("service_plan", {})
         .get("data") or {})
        .get("guid")
        or ""
    )
    plan_name = ""
    offering_name = ""
    if plan_guid:
        pj = ex.client.fetch_with_retry(
            f"/v3/service_plans/{plan_guid}",
            CONFIG_API_MAX_RETRIES_OPTIONAL,
        )
        if not pj.startswith("__ERROR"):
            try:
                pjd = json.loads(pj)
                plan_name = str(pjd.get("name", "") or "")
                off_guid = str(
                    ((pjd.get("relationships") or {})
                     .get("service_offering", {})
                     .get("data") or {})
                    .get("guid")
                    or ""
                )
                if off_guid:
                    oj = ex.client.fetch_with_retry(
                        f"/v3/service_offerings/{off_guid}",
                        CONFIG_API_MAX_RETRIES_OPTIONAL,
                    )
                    if not oj.startswith("__ERROR"):
                        offering_name = str(
                            (json.loads(oj).get("name") or "") or ""
                        )
            except json.JSONDecodeError:
                pass
    return _format_service_entry(
        sin, service_instance_guid, offering_name, plan_name, sit
    )


def _extract_services_block(
    ex: ExtractorLike, app_guid: str, app_name: str
) -> tuple[str, str, str, str]:
    sbj = fetch_all_paged(
        ex.client,
        f"/v3/service_credential_bindings?app_guids={app_guid}",
        f"Service bindings for {app_name!r}",
        critical=False,
    )
    if not ex._validate(
        json.dumps(sbj), f"Service bindings for {app_name}"
    ):
        print(
            f"   WARNING: Service bindings for {app_name!r} incomplete",
            file=sys.stderr,
        )
        return "", "", "", ""
    bindings = sbj.get("resources") or []
    bind_names: list[str] = []
    for res in bindings:
        n = str((res or {}).get("name", "") or "")
        if n:
            bind_names.append(n)
    service_bindings = ";".join(bind_names)
    instance_guids: set[str] = set()
    for res in bindings:
        g = (
            ((res or {}).get("relationships") or {})
            .get("service_instance", {})
            .get("data", {})
            .get("guid")
        )
        if g:
            instance_guids.add(str(g))
    ent_list: list[str] = []
    volume_services = ""
    volume_size = ""
    for sig in sorted(instance_guids):
        sij = ex.client.fetch_with_retry(
            f"/v3/service_instances/{sig}",
            CONFIG_API_MAX_RETRIES_OPTIONAL,
        )
        if sij.startswith("__ERROR") or not ex._validate(
            sij, f"Service instance {sig}"
        ):
            ex._debug(f"Could not read service instance {sig}")
            continue
        sj = json.loads(sij)
        instance_type = str(sj.get("type", "") or "")
        instance_name = str(sj.get("name", "") or "")
        ent = _extract_service_instance_details(ex, sig)
        if ent:
            ent_list.append(ent)
        if instance_type == "user-provided":
            tags = sj.get("tags") or []
            tag_s = (
                ",".join(str(t) for t in tags) if isinstance(tags, list) else ""
            )
            if "volume" in tag_s.lower() or "storage" in tag_s.lower():
                params = sj.get("parameters") or {}
                if not isinstance(params, dict):
                    params = {}
                vsz = str(params.get("size") or params.get("capacity") or "")
                if vsz:
                    m = re.search(r"([0-9.]+)", vsz)
                    vnum = m.group(1) if m else vsz
                    volume_services = util_append_to_list(
                        volume_services, instance_name
                    )
                    volume_size = util_append_to_list(volume_size, vnum)
                    ex._debug(
                        f"Volume service: {instance_name} ({vnum}GB)"
                    )
    return (
        ";".join(ent_list),
        service_bindings,
        volume_services,
        volume_size,
    )
