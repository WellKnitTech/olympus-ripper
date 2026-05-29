#!/usr/bin/env python3
"""
Olympus Ripper — CLI Interface
(c) 2026 Olympus Cyber. All rights reserved.

Usage:
    oripper rip <target> [options]          Parse a single hive/artifact file
    oripper volume <path> [options]         Scan a mounted volume for all artifacts
    oripper list [options]                  List available plugins
    oripper info <plugin_name>              Show plugin details
    oripper rehash                          Re-baseline integrity manifest
"""

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import RipperEngine
from .plugin_base import ArtifactCategory, ArtifactPlatform
from .formatters import TextFormatter, JSONFormatter, CSVFormatter, TimelineFormatter
from .integrity import verify_self_integrity, hash_output_file, write_hash_index, save_manifest


def show_olympus_banner(script_label: str = "Olympus Ripper", classification: str = "CONFIDENTIAL") -> None:
    """Display the official Olympus Cyber banner — art floats free, box around info only."""
    import datetime

    B  = "\033[38;5;27m"    # dark blue  — frame + OLYMPUS bottom rows
    b  = "\033[38;5;33m"    # blue       — OLYMPUS mid rows
    c  = "\033[38;5;39m"    # cyan       — OLYMPUS top rows
    C  = "\033[38;5;45m"    # light cyan — CYBER top rows
    W  = "\033[38;5;231m"   # white      — tagline text
    d  = "\033[38;5;243m"   # dim gray   — script label, timestamp
    G  = "\033[38;5;178m"   # gold       — classification
    R  = "\033[0m"          # reset

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Center text within the 63-char box interior
    def center_text(text, width=63):
        pad_l = (width - len(text)) // 2
        pad_r = width - pad_l - len(text)
        return " " * pad_l + text + " " * pad_r

    title_line = f"{script_label}  v{__version__}"
    cent_title = center_text(title_line)
    cent_ts    = center_text(ts)
    cent_class = center_text(classification)

    lines = [
        "",
        f"  {c}██████╗ ██╗  ██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗███████╗{R}",
        f" {c}██╔═══██╗██║  ╚██╗ ██╔╝████╗ ████║██╔══██╗██║   ██║██╔════╝{R}",
        f" {b}██║   ██║██║   ╚████╔╝ ██╔████╔██║██████╔╝██║   ██║███████╗{R}",
        f" {b}██║   ██║██║    ╚██╔╝  ██║╚██╔╝██║██╔═══╝ ██║   ██║╚════██║{R}",
        f" {B}╚██████╔╝███████╗██║   ██║ ╚═╝ ██║██║     ╚██████╔╝███████║{R}",
        f"  {B}╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚═╝╚═╝      ╚═════╝ ╚══════╝{R}",
        "",
        f"           {C}██████╗██╗   ██╗██████╗ ███████╗██████╗{R}",
        f"          {C}██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗{R}",
        f"          {c}██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝{R}",
        f"          {b}██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗{R}",
        f"          {B}╚██████╗   ██║   ██████╔╝███████╗██║  ██║{R}",
        f"           {B}╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝{R}",
        "",
        f"  {W}Incident Response{R}  {d}|{R}  {W}Threat Hunting{R}  {d}|{R}  {W}Cyber Resilience{R}",
        "",
        f"  {B}╔═══════════════════════════════════════════════════════════════╗{R}",
        f"  {B}║{R}                                                               {B}║{R}",
        f"  {B}║{R}{W}{cent_title}{R}{B}║{R}",
        f"  {B}║{R}{d}{cent_ts}{R}{B}║{R}",
        f"  {B}║{R}{G}{cent_class}{R}{B}║{R}",
        f"  {B}║{R}                                                               {B}║{R}",
        f"  {B}╚═══════════════════════════════════════════════════════════════╝{R}",
        "",
    ]
    print("\n".join(lines))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oripper",
        description="Olympus Ripper — Hybrid Forensic Artifact Parser by Olympus Cyber",
    )
    parser.add_argument("--version", action="version", version=f"Olympus Ripper v{__version__}")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress messages")
    parser.add_argument(
        "--plugin-dir", "-P", action="append", default=[],
        help="Additional plugin directory (can be specified multiple times)",
    )

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # --- rip ---
    rip_p = sub.add_parser("rip", help="Parse a single hive or artifact file")
    rip_p.add_argument("target", help="Path to registry hive or macOS artifact")
    rip_p.add_argument(
        "--plugins", "-p", nargs="+",
        help="Specific plugin name(s) to run",
    )
    rip_p.add_argument(
        "--hive-type", "-H",
        choices=["SAM", "SYSTEM", "SOFTWARE", "SECURITY", "NTUSER", "USRCLASS", "DEFAULT"],
        help="Force hive type (auto-detected if omitted)",
    )
    rip_p.add_argument(
        "--platform",
        choices=["windows", "macos"],
        help="Filter plugins by platform",
    )
    rip_p.add_argument(
        "--category", "-c",
        choices=[c.value for c in ArtifactCategory],
        help="Filter plugins by artifact category",
    )
    rip_p.add_argument(
        "--format", "-f",
        choices=["text", "json", "csv", "timeline"],
        default="text",
        help="Output format (default: text)",
    )
    rip_p.add_argument("--output", "-o", help="Write output to file instead of stdout")
    rip_p.add_argument("--hostname", default="UNKNOWN", help="Hostname for timeline output")

    # --- volume ---
    vol_p = sub.add_parser("volume", help="Scan a mounted volume for all supported artifacts")
    vol_p.add_argument("path", help="Path to mounted volume or extracted image")
    vol_p.add_argument("--plugins", "-p", nargs="+", help="Specific plugin name(s) to run")
    vol_p.add_argument(
        "--format", "-f",
        choices=["text", "json", "csv", "timeline"],
        default="text",
    )
    vol_p.add_argument("--output", "-o", help="Write output to file")
    vol_p.add_argument("--hostname", default="UNKNOWN", help="Hostname for timeline output")

    # --- list ---
    list_p = sub.add_parser("list", help="List available plugins")
    list_p.add_argument(
        "--platform",
        choices=["windows", "macos"],
        help="Filter by platform",
    )
    list_p.add_argument(
        "--category",
        choices=[c.value for c in ArtifactCategory],
        help="Filter by category",
    )
    list_p.add_argument(
        "--hive-type",
        choices=["SAM", "SYSTEM", "SOFTWARE", "SECURITY", "NTUSER", "USRCLASS"],
        help="Filter registry plugins by hive type",
    )

    # --- info ---
    info_p = sub.add_parser("info", help="Show details about a specific plugin")
    info_p.add_argument("plugin_name", help="Plugin name to inspect")

    # --- rehash ---
    sub.add_parser("rehash", help="Re-baseline the integrity manifest (accept current file state)")

    return parser


def get_formatter(fmt: str, color: bool = True):
    return {
        "text": TextFormatter(color=color),
        "json": JSONFormatter(),
        "csv": CSVFormatter(),
        "timeline": TimelineFormatter(),
    }[fmt]


def _hash_and_index(output_path: str, target: str, hostname: str = "UNKNOWN") -> None:
    """Hash an output file and write a hash index alongside it."""
    entry = hash_output_file(output_path)
    index_path = write_hash_index([output_path], target=target, hostname=hostname)
    print(f"[*] SHA-256: {entry['sha256']}")
    print(f"[*] Hash index: {index_path}")


def cmd_rip(args, engine: RipperEngine) -> None:
    target = str(Path(args.target).resolve())
    platform = ArtifactPlatform(args.platform) if args.platform else None
    category = ArtifactCategory(args.category) if args.category else None

    findings = engine.rip(
        target=target,
        plugins=args.plugins,
        platform=platform,
        category=category,
        hive_type=args.hive_type,
    )

    formatter = get_formatter(args.format, color=not args.no_color)

    if args.output:
        if hasattr(formatter, "write_to_file"):
            kwargs = {"target": target}
            if args.format == "timeline":
                kwargs["hostname"] = args.hostname
            formatter.write_to_file(findings, args.output, **kwargs)
            print(f"[*] Output written to {args.output}")
            _hash_and_index(args.output, target, args.hostname)
        return

    if args.format == "text":
        formatter.write(findings, target=target)
    elif args.format == "timeline":
        print(formatter.format(findings, target=target, hostname=args.hostname))
    else:
        print(formatter.format(findings, target=target))


def cmd_volume(args, engine: RipperEngine) -> None:
    vol_path = str(Path(args.path).resolve())
    findings = engine.rip_volume(vol_path, plugins=args.plugins)

    formatter = get_formatter(args.format, color=not args.no_color)

    if args.output:
        kwargs = {"target": vol_path}
        if args.format == "timeline":
            kwargs["hostname"] = args.hostname
        formatter.write_to_file(findings, args.output, **kwargs)
        print(f"[*] Output written to {args.output}")
        _hash_and_index(args.output, vol_path, args.hostname)
        return

    if args.format == "text":
        formatter.write(findings, target=vol_path)
    elif args.format == "timeline":
        print(formatter.format(findings, target=vol_path, hostname=args.hostname))
    else:
        print(formatter.format(findings, target=vol_path))


def cmd_list(args, engine: RipperEngine) -> None:
    platform = ArtifactPlatform(args.platform) if args.platform else None
    category = ArtifactCategory(args.category) if args.category else None
    plugins = engine.registry.list_plugins(
        platform=platform,
        category=category,
        hive_type=args.hive_type if hasattr(args, "hive_type") else None,
    )

    if not plugins:
        print("[!] No plugins match the given filters.")
        return

    print(f"\n{'Name':<30} {'Platform':<10} {'Category':<18} {'Description'}")
    print("─" * 95)
    for p in plugins:
        mitre = ", ".join(p.mitre_references) if p.mitre_references else ""
        desc = p.description
        if mitre:
            desc += f" [{mitre}]"
        print(f"{p.name:<30} {p.platform.value:<10} {p.category.value:<18} {desc}")
    print(f"\n  Total: {len(plugins)} plugin(s)")


def cmd_info(args, engine: RipperEngine) -> None:
    plugin = engine.registry.get_plugin(args.plugin_name)
    if not plugin:
        print(f"[!] Plugin '{args.plugin_name}' not found.")
        sys.exit(1)

    from .plugin_base import RegistryPlugin, MacArtifactPlugin

    print(f"\n  Plugin: {plugin.name}")
    print(f"  Description: {plugin.description}")
    print(f"  Author: {plugin.author}")
    print(f"  Version: {plugin.version}")
    print(f"  Platform: {plugin.platform.value}")
    print(f"  Category: {plugin.category.value}")

    if isinstance(plugin, RegistryPlugin):
        print(f"  Hive Type: {plugin.hive_type}")
        print(f"  Registry Keys:")
        for k in plugin.registry_keys:
            print(f"    - {k}")

    if isinstance(plugin, MacArtifactPlugin):
        print(f"  Artifact Type: {plugin.artifact_type}")
        print(f"  Default Paths:")
        for p in plugin.default_paths:
            print(f"    - {p}")

    if plugin.mitre_references:
        print(f"  MITRE ATT&CK: {', '.join(plugin.mitre_references)}")
    print()


def cmd_rehash(args, engine: RipperEngine) -> None:
    """Re-baseline the integrity manifest."""
    manifest_path = save_manifest()
    print(f"[*] Integrity manifest regenerated.")
    print(f"[*] Manifest: {manifest_path}")
    print(f"[*] Current file state is now the accepted baseline.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        show_olympus_banner()
        parser.print_help()
        sys.exit(0)

    quiet = args.quiet if hasattr(args, "quiet") else False
    if not quiet:
        show_olympus_banner()

    # Self-integrity check (runs before every command)
    verify_self_integrity(quiet=quiet)

    engine = RipperEngine(
        plugin_dirs=args.plugin_dir if hasattr(args, "plugin_dir") else [],
        quiet=quiet,
    )

    commands = {
        "rip": cmd_rip,
        "volume": cmd_volume,
        "list": cmd_list,
        "info": cmd_info,
        "rehash": cmd_rehash,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, engine)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
