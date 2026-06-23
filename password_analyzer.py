#!/usr/bin/env python3
"""
password_analyzer.py
─────────────────────
Main entry point for the Password Strength Analyzer CLI.

Features:
  • Interactive menu (rich-powered, dark-mode friendly)
  • Masked password input via getpass
  • Full analysis report: score bar, complexity table, entropy, crack time,
    pattern warnings, HIBP breach check, actionable suggestions
  • Password generator (length, character classes, count)
  • Export results to JSON or CSV (passwords never stored)
  • CLI flags: --analyze, --generate, --no-hibp, --output, --show-password

Usage:
  python password_analyzer.py               # Interactive menu
  python password_analyzer.py --analyze     # Analyse one password then exit
  python password_analyzer.py --generate --length 20 --count 5
  python password_analyzer.py --analyze --no-hibp --output results.json
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

# ── Optional rich dependency ───────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False
    print(
        "[WARNING] 'rich' is not installed. "
        "Install it with:  pip install rich\n"
        "Falling back to plain-text output.\n"
    )

from password_utils import (
    full_analysis,
    generate_password,
)

# ══════════════════════════════════════════════════════════════════════════════
# Setup
# ══════════════════════════════════════════════════════════════════════════════

console: Optional[Console] = Console() if _HAS_RICH else None  # type: ignore[assignment]

VERSION = "1.0.0"

# ── Colour / emoji helpers ────────────────────────────────────────────────────

def _score_colour(score: int) -> str:
    """Map a 0–100 score to a rich colour string."""
    if score >= 80: return "bright_green"
    if score >= 60: return "green"
    if score >= 40: return "yellow"
    if score >= 20: return "orange1"
    return "red"


def _rating_emoji(rating: str) -> str:
    return {
        "Very Strong": "💪",
        "Strong":      "✅",
        "Medium":      "⚠️ ",
        "Weak":        "❌",
        "Very Weak":   "💀",
    }.get(rating, "❓")


def _entropy_label(entropy: float) -> str:
    if entropy >= 80: return "Excellent — very hard to crack"
    if entropy >= 60: return "Good — reasonably secure"
    if entropy >= 40: return "Fair — could be improved"
    if entropy >= 20: return "Poor — easy to crack"
    return "Critically low"


def _entropy_colour(entropy: float) -> str:
    if entropy >= 80: return "bright_green"
    if entropy >= 60: return "green"
    if entropy >= 40: return "yellow"
    return "red"


# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════

_PLAIN_BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║        🔐  PASSWORD STRENGTH ANALYZER  v1.0.0  🔐       ║
║      Analyse · Generate · Strengthen Your Security       ║
╚══════════════════════════════════════════════════════════╝
"""


def display_banner() -> None:
    if _HAS_RICH:
        assert console is not None
        console.print(
            Panel(
                "[bold cyan]🔐  PASSWORD STRENGTH ANALYZER  v{v}  🔐[/bold cyan]\n"
                "[dim]Analyse · Generate · Strengthen Your Security[/dim]".format(v=VERSION),
                border_style="cyan",
                expand=True,
                padding=(0, 4),
            )
        )
    else:
        print(_PLAIN_BANNER)


# ══════════════════════════════════════════════════════════════════════════════
# Analysis Display
# ══════════════════════════════════════════════════════════════════════════════

def _draw_score_bar_rich(score: int, rating: str) -> None:
    """Render a 40-char coloured block bar with score and rating."""
    assert console is not None
    colour   = _score_colour(score)
    filled   = int(40 * score / 100)
    bar      = "█" * filled + "░" * (40 - filled)
    emoji    = _rating_emoji(rating)
    console.print(
        f"\n  [{colour}]{bar}[/{colour}]  "
        f"[bold]{score}/100[/bold]  "
        f"{emoji} [bold {colour}]{rating}[/{colour}]\n"
    )


def display_analysis(
    password: str,
    result: Dict,
    mask: bool = True,
    label: Optional[str] = None,
) -> None:
    """
    Pretty-print the complete analysis result.

    Args:
        password: The analysed password (used for display only).
        result:   dict returned by full_analysis().
        mask:     If True, replace password chars with '●'.
        label:    Optional heading label (e.g. "Password 2/5").
    """
    complexity  = result["complexity"]
    entropy     = result["entropy"]
    crack_time  = result["crack_time"]
    patterns    = result["patterns"]
    score       = result["score"]
    rating      = result["rating"]
    suggestions = result["suggestions"]
    breach      = result["breach"]

    display_pwd = "●" * len(password) if mask else password

    if _HAS_RICH:
        assert console is not None
        heading = f"📊  ANALYSIS REPORT{f'  [{label}]' if label else ''}"
        console.rule(f"[bold cyan]{heading}[/bold cyan]")
        console.print(
            f"\n  [bold]Password:[/bold] [dim]{display_pwd}[/dim]  "
            f"[dim]({complexity['length']} characters, "
            f"{complexity['unique_chars']} unique)[/dim]"
        )

        # ── Score bar ────────────────────────────────────────────────────────
        _draw_score_bar_rich(score, rating)

        # ── Complexity table ─────────────────────────────────────────────────
        t = Table(
            title="🔍 Complexity Breakdown",
            border_style="blue",
            show_header=True,
            header_style="bold blue",
            expand=False,
        )
        t.add_column("Criterion",                     style="cyan",      min_width=32)
        t.add_column("Status",   justify="center",    style="",          min_width=10)
        t.add_column("Count",    justify="right",     style="dim",       min_width=6)

        checks = [
            ("Length ≥ 12 characters (16+ recommended)", complexity["length"] >= 12, complexity["length"]),
            ("Uppercase letters  (A–Z)",                 complexity["has_uppercase"],  complexity["uppercase_count"]),
            ("Lowercase letters  (a–z)",                 complexity["has_lowercase"],  complexity["lowercase_count"]),
            ("Digits  (0–9)",                            complexity["has_digits"],      complexity["digit_count"]),
            ("Special characters  (!@#$…)",             complexity["has_special"],     complexity["special_count"]),
        ]
        for name, passed, count in checks:
            status = "[green]✓ Pass[/green]" if passed else "[red]✗ Fail[/red]"
            t.add_row(name, status, str(count))
        console.print(t)

        # ── Entropy & crack time ─────────────────────────────────────────────
        e_colour = _entropy_colour(entropy)
        console.print(
            f"\n  🎲 [bold]Entropy:[/bold] [{e_colour}]{entropy} bits[/{e_colour}]"
            f"  ·  [dim]{_entropy_label(entropy)}[/dim]"
        )
        console.print(
            f"  ⏱  [bold]Crack time:[/bold] [cyan]{crack_time}[/cyan]"
            f"  [dim](offline GPU attack @ 10¹² guesses/sec)[/dim]"
        )

        # ── Pattern warnings ─────────────────────────────────────────────────
        if patterns:
            console.print(
                f"\n  ⚠️  [bold red]Weak Patterns Detected ({len(patterns)}):[/bold red]"
            )
            for p in patterns:
                console.print(f"       • [yellow]{p}[/yellow]")
        else:
            console.print("\n  ✅  [green]No common weak patterns detected[/green]")

        # ── Breach check result ──────────────────────────────────────────────
        if not breach["checked"] and breach["count"] == 0 and not breach["found"]:
            # check was disabled or not run
            pass
        elif not breach.get("api_available", False) and breach["checked"] is False:
            console.print(
                "\n  🌐 [yellow]HIBP API unavailable — breach check skipped[/yellow]"
            )
        elif breach["found"]:
            console.print(
                f"\n  💥 [bold red]⚠  DATA BREACH DETECTED![/bold red]"
                f"\n       This password appeared "
                f"[bold red]{breach['count']:,}[/bold red] times in known data breaches!"
                f"\n       [red]You must never use this password.[/red]"
            )
        elif breach["checked"]:
            console.print(
                "\n  🛡️  [green]Not found in any known data breaches[/green]"
            )

        # ── Suggestions ──────────────────────────────────────────────────────
        if suggestions:
            console.print(f"\n  💡 [bold cyan]Improvement Suggestions:[/bold cyan]")
            for s in suggestions:
                console.print(f"       {s}")

        console.rule()

    else:
        # ── Plain-text fallback ──────────────────────────────────────────────
        sep = "─" * 62
        print(f"\n{sep}")
        if label:
            print(f"  ANALYSIS REPORT [{label}]")
        else:
            print("  ANALYSIS REPORT")
        print(sep)
        print(f"  Password : {display_pwd}  ({complexity['length']} chars, "
              f"{complexity['unique_chars']} unique)")
        print(f"  Score    : {score}/100  —  {rating}")
        print(f"  Entropy  : {entropy} bits  ({_entropy_label(entropy)})")
        print(f"  Crack est: {crack_time}  (offline GPU @10¹²/sec)")
        print(f"\n  Complexity:")
        print(f"    Length ≥ 12  : {'✓' if complexity['length'] >= 12 else '✗'}  "
              f"({complexity['length']})")
        print(f"    Uppercase    : {'✓' if complexity['has_uppercase'] else '✗'}  "
              f"({complexity['uppercase_count']})")
        print(f"    Lowercase    : {'✓' if complexity['has_lowercase'] else '✗'}  "
              f"({complexity['lowercase_count']})")
        print(f"    Digits       : {'✓' if complexity['has_digits'] else '✗'}  "
              f"({complexity['digit_count']})")
        print(f"    Special      : {'✓' if complexity['has_special'] else '✗'}  "
              f"({complexity['special_count']})")
        if patterns:
            print(f"\n  Patterns detected ({len(patterns)}):")
            for p in patterns:
                print(f"    - {p}")
        else:
            print("\n  No common weak patterns detected.")
        if breach["found"]:
            print(f"\n  ⚠  BREACH: Found {breach['count']:,} times in HIBP!")
        elif breach["checked"]:
            print("\n  Not found in HIBP breach database.")
        if suggestions:
            print("\n  Suggestions:")
            for s in suggestions:
                print(f"    {s}")
        print(sep)


# ══════════════════════════════════════════════════════════════════════════════
# Menu Actions
# ══════════════════════════════════════════════════════════════════════════════

def _prompt(prompt_text: str) -> str:
    """Prompt for input, stripping whitespace."""
    if _HAS_RICH:
        assert console is not None
        return console.input(f"  [cyan]{prompt_text}[/cyan]").strip()
    return input(f"  {prompt_text}").strip()


def _yn(prompt_text: str, default: bool = True) -> bool:
    """Yes/no prompt. Returns True for yes."""
    default_hint = " (Y/n)" if default else " (y/N)"
    raw = _prompt(prompt_text + default_hint + ": ").lower()
    if not raw:
        return default
    return raw.startswith("y")


def action_analyze(results: List[Dict], check_hibp: bool, show_pwd: bool) -> None:
    """Prompt for a password and display a full analysis report."""
    if _HAS_RICH:
        assert console is not None
        console.print(
            "\n  [bold]Enter the password to analyse[/bold] "
            "[dim](input is hidden)[/dim]"
        )
    else:
        print("\n  Enter the password to analyse (input is hidden):")

    try:
        password = getpass.getpass("  Password: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return

    if not password:
        if _HAS_RICH:
            assert console is not None
            console.print("  [red]No password entered.[/red]")
        else:
            print("  No password entered.")
        return

    if _HAS_RICH:
        assert console is not None
        with console.status("[bold cyan]Analysing password…[/bold cyan]"):
            result = full_analysis(password, check_hibp=check_hibp)
    else:
        print("  Analysing…")
        result = full_analysis(password, check_hibp=check_hibp)

    display_analysis(password, result, mask=not show_pwd)

    # Store a safe (non-password) summary for optional export
    results.append({
        "analyzed_at":  datetime.now().isoformat(timespec="seconds"),
        "pwd_length":   result["complexity"]["length"],
        "score":        result["score"],
        "rating":       result["rating"],
        "entropy_bits": result["entropy"],
        "crack_time":   result["crack_time"],
        "patterns":     result["patterns"],
        "breach_found": result["breach"]["found"],
        "breach_count": result["breach"]["count"],
        "suggestions":  result["suggestions"],
    })


def action_analyze_multiple(results: List[Dict], check_hibp: bool, show_pwd: bool) -> None:
    """Analyse several passwords in sequence."""
    try:
        n_str = _prompt("How many passwords to analyse? ")
        n = int(n_str) if n_str else 1
        n = max(1, min(20, n))
    except ValueError:
        n = 1

    for i in range(1, n + 1):
        if _HAS_RICH:
            assert console is not None
            console.print(f"\n  [bold dim]— Password {i} of {n} —[/bold dim]")
        else:
            print(f"\n  — Password {i} of {n} —")
        action_analyze(results, check_hibp=check_hibp, show_pwd=show_pwd)


def action_generate() -> None:
    """Interactively generate one or more strong passwords."""
    if _HAS_RICH:
        assert console is not None
        console.rule("[bold cyan]🔑  PASSWORD GENERATOR[/bold cyan]")

    # Collect options
    try:
        length_raw = _prompt("Desired length    [default 16]: ")
        length = int(length_raw) if length_raw else 16
        length = max(8, min(128, length))

        count_raw = _prompt("How many to gen   [default  1]: ")
        count = int(count_raw) if count_raw else 1
        count = max(1, min(50, count))
    except (ValueError, KeyboardInterrupt):
        length, count = 16, 1

    use_upper   = _yn("Include uppercase  (A–Z)", default=True)
    use_lower   = _yn("Include lowercase  (a–z)", default=True)
    use_digits  = _yn("Include digits     (0–9)", default=True)
    use_special = _yn("Include special    (!@#…)", default=True)

    if _HAS_RICH:
        assert console is not None
        table = Table(
            title=f"Generated Password{'s' if count > 1 else ''}",
            border_style="green",
            header_style="bold green",
            show_lines=True,
        )
        table.add_column("#",         style="dim",        width=4)
        table.add_column("Password",  style="bold cyan",  min_width=20)
        table.add_column("Score",     justify="center",   min_width=10)
        table.add_column("Entropy",   justify="center",   min_width=10)
        table.add_column("Rating",    justify="center",   min_width=14)
        table.add_column("Crack est", justify="center",   min_width=18)

        with console.status("[bold cyan]Generating passwords…[/bold cyan]"):
            for i in range(1, count + 1):
                pwd    = generate_password(length, use_upper, use_lower, use_digits, use_special)
                result = full_analysis(pwd, check_hibp=False)
                colour = _score_colour(result["score"])
                table.add_row(
                    str(i),
                    pwd,
                    f"[{colour}]{result['score']}/100[/{colour}]",
                    f"{result['entropy']} bits",
                    f"{_rating_emoji(result['rating'])} {result['rating']}",
                    result["crack_time"],
                )
        console.print(table)
        console.print(
            "  [dim]Tip: copy one of these into your password manager.[/dim]\n"
        )
    else:
        print("\n  Generated passwords:")
        for i in range(1, count + 1):
            pwd    = generate_password(length, use_upper, use_lower, use_digits, use_special)
            result = full_analysis(pwd, check_hibp=False)
            print(
                f"  {i:>2}. {pwd}  "
                f"[{result['score']}/100 — {result['rating']}  "
                f"entropy:{result['entropy']}b  {result['crack_time']}]"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Save Results
# ══════════════════════════════════════════════════════════════════════════════

def save_results(results: List[Dict], filename: str, fmt: str = "json") -> None:
    """
    Write analysis results to disk.

    Passwords are NEVER included — only metadata (score, rating, etc.)
    is serialised.

    Args:
        results:   List of result dicts collected during the session.
        filename:  Output file path.
        fmt:       "json" or "csv".
    """
    if not results:
        _print("No results to save.")
        return

    try:
        if fmt == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=results[0].keys())
                writer.writeheader()
                for row in results:
                    # Flatten list fields for CSV
                    flat = {
                        k: ("; ".join(v) if isinstance(v, list) else v)
                        for k, v in row.items()
                    }
                    writer.writerow(flat)
        else:  # json
            payload = {
                "tool":         f"Password Strength Analyzer v{VERSION}",
                "exported_at":  datetime.now().isoformat(timespec="seconds"),
                "total":        len(results),
                "results":      results,
            }
            with open(filename, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)

        if _HAS_RICH:
            assert console is not None
            console.print(
                f"\n  ✅ Results saved → [bold cyan]{filename}[/bold cyan]"
            )
        else:
            print(f"\n  Results saved to: {filename}")

    except OSError as exc:
        _print(f"Save failed: {exc}")


def _print(msg: str) -> None:
    if _HAS_RICH:
        assert console is not None
        console.print(f"  {msg}")
    else:
        print(f"  {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# Interactive Menu
# ══════════════════════════════════════════════════════════════════════════════

def interactive_menu() -> None:
    """Run the main interactive CLI menu loop."""
    display_banner()

    session_results: List[Dict] = []
    check_hibp  = True
    show_pwd    = False

    while True:
        hibp_flag = (
            "[green]ON[/green]"  if check_hibp else "[red]OFF[/red]"
        ) if _HAS_RICH else ("ON" if check_hibp else "OFF")
        pwd_flag = (
            "[green]visible[/green]" if show_pwd else "[dim]masked[/dim]"
        ) if _HAS_RICH else ("visible" if show_pwd else "masked")

        if _HAS_RICH:
            assert console is not None
            console.print("\n[bold cyan]MAIN MENU[/bold cyan]")
            console.print(f"  [1] Analyse a password")
            console.print(f"  [2] Analyse multiple passwords")
            console.print(f"  [3] Generate strong password(s)")
            console.print(f"  [4] Save session results  "
                          f"[dim]({len(session_results)} stored)[/dim]")
            console.print(f"  [5] Toggle HIBP breach check  [{hibp_flag}]")
            console.print(f"  [6] Toggle password display  [{pwd_flag}]")
            console.print(f"  [7] Clear session results")
            console.print(f"  [0] Exit")
            choice = console.input("\n  [bold]Choice:[/bold] ").strip()
        else:
            print(f"\nMAIN MENU")
            print(f"  1  Analyse a password")
            print(f"  2  Analyse multiple passwords")
            print(f"  3  Generate strong password(s)")
            print(f"  4  Save session results  ({len(session_results)} stored)")
            print(f"  5  Toggle HIBP breach check  [{hibp_flag}]")
            print(f"  6  Toggle password display  [{pwd_flag}]")
            print(f"  7  Clear session results")
            print(f"  0  Exit")
            choice = input("\n  Choice: ").strip()

        if choice == "1":
            action_analyze(session_results, check_hibp, show_pwd)

        elif choice == "2":
            action_analyze_multiple(session_results, check_hibp, show_pwd)

        elif choice == "3":
            action_generate()

        elif choice == "4":
            if not session_results:
                _print("No results in this session yet.")
                continue
            fmt_raw  = _prompt("Format? [json/csv] (default: json): ").lower() or "json"
            fmt      = fmt_raw if fmt_raw in ("json", "csv") else "json"
            default_name = f"psa_results_{datetime.now():%Y%m%d_%H%M%S}.{fmt}"
            fname    = _prompt(f"Filename (default: {default_name}): ") or default_name
            save_results(session_results, fname, fmt)

        elif choice == "5":
            check_hibp = not check_hibp
            status = "enabled" if check_hibp else "disabled"
            _print(f"HIBP breach check {status}.")

        elif choice == "6":
            show_pwd = not show_pwd
            status = "visible" if show_pwd else "masked"
            _print(f"Password display set to {status}.")

        elif choice == "7":
            session_results.clear()
            _print("Session results cleared.")

        elif choice == "0":
            if _HAS_RICH:
                assert console is not None
                console.print(
                    "\n  [bold cyan]Thanks for using Password Strength Analyzer."
                    " Stay secure! 🔐[/bold cyan]\n"
                )
            else:
                print("\n  Thanks for using Password Strength Analyzer. Stay secure!")
            break

        else:
            _print("Invalid choice — please enter a number from the menu.")


# ══════════════════════════════════════════════════════════════════════════════
# CLI Arguments
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="password_analyzer",
        description="🔐 Password Strength Analyzer — analyse and generate secure passwords",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_analyzer.py                          # interactive menu
  python password_analyzer.py --analyze                # analyse one password
  python password_analyzer.py --analyze --no-hibp      # skip breach check
  python password_analyzer.py --analyze --show-password
  python password_analyzer.py --generate               # generate 1 password
  python password_analyzer.py --generate -l 24 -c 5   # 5 × 24-char passwords
  python password_analyzer.py --generate --no-special  # no special chars
  python password_analyzer.py --analyze -o report.json # save JSON report
        """,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--analyze", "-a",  action="store_true",
                      help="Analyse a single password then exit")
    mode.add_argument("--generate", "-g", action="store_true",
                      help="Generate password(s) then exit")

    parser.add_argument("--length", "-l",  type=int, default=16,
                        help="Generated password length (default: 16, min: 8, max: 128)")
    parser.add_argument("--count", "-c",   type=int, default=1,
                        help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-hibp",       action="store_true",
                        help="Skip the HaveIBeenPwned breach check")
    parser.add_argument("--no-upper",      action="store_true",
                        help="Exclude uppercase letters when generating")
    parser.add_argument("--no-lower",      action="store_true",
                        help="Exclude lowercase letters when generating")
    parser.add_argument("--no-digits",     action="store_true",
                        help="Exclude digits when generating")
    parser.add_argument("--no-special",    action="store_true",
                        help="Exclude special characters when generating")
    parser.add_argument("--output", "-o",  metavar="FILE",
                        help="Save analysis results to FILE (.json or .csv)")
    parser.add_argument("--show-password", action="store_true",
                        help="Show the actual password in the report (not recommended)")
    parser.add_argument("--version", "-V", action="version",
                        version=f"%(prog)s {VERSION}")

    return parser.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    args = parse_args()

    if args.analyze:
        display_banner()
        session: List[Dict] = []
        action_analyze(session, check_hibp=not args.no_hibp, show_pwd=args.show_password)
        if args.output and session:
            fmt = "csv" if str(args.output).endswith(".csv") else "json"
            save_results(session, args.output, fmt)

    elif args.generate:
        display_banner()
        check_hibp = not args.no_hibp
        session = []

        if _HAS_RICH:
            assert console is not None
            table = Table(
                title="Generated Passwords",
                border_style="green",
                header_style="bold green",
                show_lines=True,
            )
            table.add_column("#",         style="dim",       width=4)
            table.add_column("Password",  style="bold cyan", min_width=20)
            table.add_column("Score",     justify="center",  min_width=10)
            table.add_column("Entropy",   justify="center",  min_width=10)
            table.add_column("Rating",    justify="center",  min_width=14)
            table.add_column("Crack est", justify="center",  min_width=18)

            with console.status("[bold cyan]Generating passwords…[/bold cyan]"):
                for i in range(1, args.count + 1):
                    pwd = generate_password(
                        length      = args.length,
                        use_uppercase = not args.no_upper,
                        use_lowercase = not args.no_lower,
                        use_digits    = not args.no_digits,
                        use_special   = not args.no_special,
                    )
                    result = full_analysis(pwd, check_hibp=False)
                    colour = _score_colour(result["score"])
                    table.add_row(
                        str(i), pwd,
                        f"[{colour}]{result['score']}/100[/{colour}]",
                        f"{result['entropy']} bits",
                        f"{_rating_emoji(result['rating'])} {result['rating']}",
                        result["crack_time"],
                    )
                    session.append({
                        "generated_at": datetime.now().isoformat(timespec="seconds"),
                        "pwd_length":   result["complexity"]["length"],
                        "score":        result["score"],
                        "rating":       result["rating"],
                        "entropy_bits": result["entropy"],
                        "crack_time":   result["crack_time"],
                    })
            console.print(table)

        else:
            print("\n  Generated passwords:")
            for i in range(1, args.count + 1):
                pwd = generate_password(
                    length      = args.length,
                    use_uppercase = not args.no_upper,
                    use_lowercase = not args.no_lower,
                    use_digits    = not args.no_digits,
                    use_special   = not args.no_special,
                )
                result = full_analysis(pwd, check_hibp=False)
                print(
                    f"  {i:>2}. {pwd}  "
                    f"[{result['score']}/100 — {result['rating']}]"
                )

        if args.output and session:
            fmt = "csv" if str(args.output).endswith(".csv") else "json"
            save_results(session, args.output, fmt)

    else:
        interactive_menu()


if __name__ == "__main__":
    main()
