from __future__ import annotations

from pathlib import Path

from miniav.config import (
    DEFAULT_CONFIG,
    common_emule_incoming_dirs,
    default_pipeline_paths,
    load_config,
    save_config,
    validate_config,
)

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "monitor_config.json"


def main() -> int:
    cfg = load_config(CONFIG)
    found = common_emule_incoming_dirs()
    print("MiniAntivirus v0.3.0 - configuración del gatekeeper de Incoming\n")
    if found:
        print("Carpetas Incoming detectadas:")
        for i, p in enumerate(found, 1):
            print(f"  {i}. {p}")
    current = str(cfg.get("incoming_dir", "")).strip()
    if current:
        print(f"\nConfigurada actualmente: {current}")
    raw = input("\nRuta de Incoming (o número detectado): ").strip().strip('"')
    if raw.isdigit() and 1 <= int(raw) <= len(found):
        incoming = found[int(raw) - 1].resolve()
    else:
        incoming = Path(raw or current).expanduser().resolve() if (raw or current) else None
    if incoming is None or not incoming.is_dir():
        print("ERROR: Incoming no existe o no es una carpeta.")
        return 2

    cfg["incoming_dir"] = str(incoming)
    defaults = default_pipeline_paths(incoming)
    print("\nSe proponen carpetas hermanas de Incoming para evitar condiciones de carrera:")
    for key, proposed in defaults.items():
        old = str(cfg.get(key, "")).strip()
        prompt = f"{key} [{old or proposed}]: "
        value = input(prompt).strip().strip('"')
        cfg[key] = value or old or proposed

    try:
        validate_config(cfg, create_outputs=True)
    except Exception as exc:
        print(f"ERROR de configuración: {exc}")
        return 2
    save_config(CONFIG, cfg)
    print(f"\nConfiguración guardada en: {CONFIG}")
    print("El organizador del NAS deberá vigilar AV_Clean, NO Incoming, cuando actives esta integración.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
