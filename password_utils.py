"""
password_utils.py
─────────────────
Core utility functions for the Password Strength Analyzer.

Provides:
  - Entropy calculation (Shannon / charset model)
  - Crack-time estimation (offline GPU attack scenario)
  - Complexity analysis (character-class breakdown)
  - Pattern & weakness detection (sequences, names, leet, keyboard, etc.)
  - HaveIBeenPwned k-anonymity breach lookup
  - Strength scoring (0–100) + text rating
  - Actionable improvement suggestions
  - Cryptographically secure password generation (Python secrets module)
  - Unified full_analysis() convenience wrapper
"""

from __future__ import annotations

import re
import math
import hashlib
import secrets
import string
from typing import Dict, List, Tuple

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

# Top commonly used / leaked passwords (sourced from HIBP / SecLists)
COMMON_PASSWORDS: List[str] = [
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "p@ssword", "pa$$word", "pass@123", "12345678", "123456789",
    "1234567890", "123456", "111111", "000000", "qwerty", "qwerty123",
    "abc123", "iloveyou", "admin", "admin123", "letmein", "monkey",
    "dragon", "master", "sunshine", "princess", "shadow", "superman",
    "michael", "football", "baseball", "welcome", "login", "hello",
    "pass", "root", "test", "trustno1", "charlie", "donald", "jessica",
    "654321", "123123", "google", "starwars", "mustang", "access",
    "batman", "1q2w3e4r", "qazwsx", "zxcvbn", "asdfgh", "qwertyui",
    "1qaz2wsx", "summer", "winter", "spring", "autumn", "monday",
    "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december",
]

# Common English first names to detect inside passwords
COMMON_NAMES: List[str] = [
    "james", "john", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
    "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
    "kevin", "brian", "george", "timothy", "ronald", "edward", "jason",
    "mary", "patricia", "jennifer", "linda", "barbara", "elizabeth",
    "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty",
    "margaret", "sandra", "ashley", "emily", "amanda", "melissa",
    "dorothy", "helen", "carol", "michelle", "laura", "kimberly",
]

# QWERTY keyboard rows for adjacency pattern detection
KEYBOARD_ROWS: List[str] = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

_ALPHA  = "abcdefghijklmnopqrstuvwxyz"
_DIGITS = "0123456789"

# Common leet-speak substitution map (char → real letter)
LEET_MAP: Dict[str, str] = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
    "8": "b",
}

# Rating thresholds (highest first)
_RATINGS: List[Tuple[int, str]] = [
    (80, "Very Strong"),
    (60, "Strong"),
    (40, "Medium"),
    (20, "Weak"),
    (0,  "Very Weak"),
]

# Pre-compiled regex patterns for performance
_RE_LOWER   = re.compile(r"[a-z]")
_RE_UPPER   = re.compile(r"[A-Z]")
_RE_DIGIT   = re.compile(r"\d")
_RE_SPECIAL = re.compile(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]")
_RE_REPEAT  = re.compile(r"(.)\1{2,}")
_RE_YEAR    = re.compile(r"(19|20)\d{2}")


# ══════════════════════════════════════════════════════════════════════════════
# Entropy
# ══════════════════════════════════════════════════════════════════════════════

def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits using the character-set model.

    Formula: E = L × log₂(N)
      where L = length and N = total size of the character classes used.

    Character classes and sizes:
      lowercase  a–z  →  26
      uppercase  A–Z  →  26
      digits     0–9  →  10
      special         →  32

    Args:
        password: The password string to evaluate.

    Returns:
        Entropy in bits, rounded to 2 decimal places.
        Returns 0.0 for an empty or unrecognised-charset string.
    """
    n = 0
    if _RE_LOWER.search(password):   n += 26
    if _RE_UPPER.search(password):   n += 26
    if _RE_DIGIT.search(password):   n += 10
    if _RE_SPECIAL.search(password): n += 32

    return 0.0 if n == 0 else round(len(password) * math.log2(n), 2)


# ══════════════════════════════════════════════════════════════════════════════
# Crack-Time Estimate
# ══════════════════════════════════════════════════════════════════════════════

def estimate_crack_time(entropy: float) -> str:
    """
    Convert entropy bits to a human-readable brute-force time estimate.

    Assumes an offline attack at 10¹² guesses/second — roughly what a
    modern GPU cluster achieves against a fast hash (MD5/SHA-1).
    Real-world times for bcrypt/Argon2 would be orders of magnitude longer.

    Args:
        entropy: Password entropy in bits (from calculate_entropy).

    Returns:
        Human-readable string, e.g. "~3.2 hours", "~14 million years".
    """
    if entropy <= 0:
        return "Instantly"

    GUESSES_PER_SEC = 1e12          # 10^12 / second (high-end offline attack)
    seconds = (2 ** entropy) / GUESSES_PER_SEC

    if seconds < 1:
        return "< 1 second"
    elif seconds < 60:
        return f"~{seconds:.0f} seconds"
    elif seconds < 3_600:
        return f"~{seconds / 60:.0f} minutes"
    elif seconds < 86_400:
        return f"~{seconds / 3_600:.1f} hours"
    elif seconds < 86_400 * 30:
        return f"~{seconds / 86_400:.1f} days"
    elif seconds < 86_400 * 365:
        return f"~{seconds / (86_400 * 30):.1f} months"
    elif seconds < 86_400 * 365 * 1_000:
        return f"~{seconds / (86_400 * 365):.1f} years"
    elif seconds < 86_400 * 365 * 1_000_000:
        return f"~{seconds / (86_400 * 365 * 1_000):.0f} thousand years"
    elif seconds < 86_400 * 365 * 1e9:
        return f"~{seconds / (86_400 * 365 * 1e6):.0f} million years"
    else:
        return "Practically uncrackable"


# ══════════════════════════════════════════════════════════════════════════════
# Complexity Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_complexity(password: str) -> Dict:
    """
    Return a detailed breakdown of the password's character composition.

    Args:
        password: The password to inspect.

    Returns:
        dict with keys:
          length, has_uppercase, has_lowercase, has_digits, has_special,
          uppercase_count, lowercase_count, digit_count, special_count,
          unique_chars.
    """
    return {
        "length":          len(password),
        "has_uppercase":   bool(_RE_UPPER.search(password)),
        "has_lowercase":   bool(_RE_LOWER.search(password)),
        "has_digits":      bool(_RE_DIGIT.search(password)),
        "has_special":     bool(_RE_SPECIAL.search(password)),
        "uppercase_count": len(_RE_UPPER.findall(password)),
        "lowercase_count": len(_RE_LOWER.findall(password)),
        "digit_count":     len(_RE_DIGIT.findall(password)),
        "special_count":   len(_RE_SPECIAL.findall(password)),
        "unique_chars":    len(set(password)),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Pattern Detection
# ══════════════════════════════════════════════════════════════════════════════

def _reverse_leet(text: str) -> str:
    """Replace leet-speak characters with their alphabetic equivalents."""
    result = text.lower()
    for leet_char, real_char in LEET_MAP.items():
        result = result.replace(leet_char, real_char)
    return result


def detect_patterns(password: str) -> List[str]:
    """
    Identify common weak patterns inside the password.

    Checks performed (in order):
      1. Exact match against common/breached password list (+ leet variants)
      2. Keyboard-row adjacency sequences (forward & reversed, len ≥ 4)
      3. Alphabetical run sequences (forward & reversed, len ≥ 3)
      4. Digit run sequences (forward & reversed, len ≥ 3)
      5. Repeated characters (3+ identical in a row)
      6. Year patterns (1900–2029)
      7. Common first names embedded in the password
      8. Passwords composed entirely of digits
      9. Palindrome structure

    Args:
        password: The password to inspect.

    Returns:
        Deduplicated list of human-readable issue descriptions.
        Empty list means no obvious patterns were detected.
    """
    issues: List[str] = []
    pwd_lower  = password.lower()
    unleet_pwd = _reverse_leet(password)

    # ── 1. Common password list ─────────────────────────────────────────────
    if pwd_lower in COMMON_PASSWORDS or unleet_pwd in COMMON_PASSWORDS:
        issues.append(
            "Password (or its leet-speak variant) is in the most-common passwords list"
        )

    # ── 2. Keyboard row sequences ────────────────────────────────────────────
    for row in KEYBOARD_ROWS:
        found = False
        for run_len in range(min(6, len(row)), 3, -1):
            if found:
                break
            for i in range(len(row) - run_len + 1):
                chunk = row[i : i + run_len]
                if chunk in pwd_lower:
                    issues.append(f"Contains keyboard sequence: '{chunk}'")
                    found = True
                    break
                if chunk[::-1] in pwd_lower:
                    issues.append(f"Contains reversed keyboard sequence: '{chunk[::-1]}'")
                    found = True
                    break

    # ── 3. Alphabetical sequences ────────────────────────────────────────────
    found = False
    for run_len in range(min(6, len(password)), 2, -1):
        if found:
            break
        for i in range(len(_ALPHA) - run_len + 1):
            chunk = _ALPHA[i : i + run_len]
            if chunk in pwd_lower:
                issues.append(f"Contains alphabetical sequence: '{chunk}'")
                found = True
                break
            if chunk[::-1] in pwd_lower:
                issues.append(f"Contains reverse alphabetical sequence: '{chunk[::-1]}'")
                found = True
                break

    # ── 4. Digit sequences ───────────────────────────────────────────────────
    found = False
    for run_len in range(min(6, len(password)), 2, -1):
        if found:
            break
        for i in range(len(_DIGITS) - run_len + 1):
            chunk = _DIGITS[i : i + run_len]
            if chunk in password:
                issues.append(f"Contains digit sequence: '{chunk}'")
                found = True
                break
            if chunk[::-1] in password:
                issues.append(f"Contains reverse digit sequence: '{chunk[::-1]}'")
                found = True
                break

    # ── 5. Repeated characters ───────────────────────────────────────────────
    rep = _RE_REPEAT.search(password)
    if rep:
        issues.append(f"Contains repeated characters: '{rep.group()}'")

    # ── 6. Year patterns ─────────────────────────────────────────────────────
    yr = _RE_YEAR.search(password)
    if yr:
        issues.append(f"Contains a year: '{yr.group()}' (easily guessable)")

    # ── 7. Common names ──────────────────────────────────────────────────────
    for name in COMMON_NAMES:
        if len(name) >= 4 and name in pwd_lower:
            issues.append(f"Contains a common name: '{name}'")
            break

    # ── 8. All digits ────────────────────────────────────────────────────────
    if password.isdigit():
        issues.append("Password is entirely numeric (trivially crackable)")

    # ── 9. Palindrome ────────────────────────────────────────────────────────
    if len(password) >= 5 and pwd_lower == pwd_lower[::-1]:
        issues.append("Password is a palindrome (mirror structure is predictable)")

    # Deduplicate while preserving detection order
    seen: set = set()
    unique: List[str] = []
    for issue in issues:
        if issue not in seen:
            seen.add(issue)
            unique.append(issue)
    return unique


# ══════════════════════════════════════════════════════════════════════════════
# HaveIBeenPwned Breach Check
# ══════════════════════════════════════════════════════════════════════════════

def check_breach(password: str) -> Tuple[bool, int]:
    """
    Check whether the password appears in known data breaches.

    Uses the HIBP Pwned Passwords API with k-anonymity: only the
    first 5 hex characters of the SHA-1 hash are sent over the network.
    The full hash — and the plaintext password — never leave this machine.

    Args:
        password: The password to check.

    Returns:
        Tuple (is_breached: bool, count: int).
          count > 0  → number of times seen in breach data.
          count == 0 → not found.
          count == -1 → API unavailable (treat as unknown, not safe).
    """
    if not _HAS_REQUESTS:
        return False, -1

    sha1  = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "PasswordStrengthAnalyzer-Educational-v1.0"},
            timeout=6,
        )
        resp.raise_for_status()

        for line in resp.text.splitlines():
            line_suffix, count_str = line.split(":")
            if line_suffix == suffix:
                return True, int(count_str)

        return False, 0

    except Exception:
        return False, -1


# ══════════════════════════════════════════════════════════════════════════════
# Scoring
# ══════════════════════════════════════════════════════════════════════════════

def calculate_score(
    complexity: Dict,
    patterns: List[str],
    entropy: float,
    breach_count: int = 0,
) -> Tuple[int, str]:
    """
    Compute an overall 0–100 strength score and a text rating label.

    Scoring breakdown:
      Length contribution   0–30 pts
      Complexity criteria   0–28 pts  (4 criteria × 7 pts each)
      Entropy contribution  0–22 pts
      Pattern penalties    –5 pts per detected issue  (max –25)
      Breach penalty       –30 pts if found in HIBP

    Args:
        complexity:   Result of analyze_complexity().
        patterns:     Result of detect_patterns().
        entropy:      Result of calculate_entropy().
        breach_count: HIBP occurrence count (0 if not breached or unchecked).

    Returns:
        Tuple of (score: int, rating: str).
    """
    score = 0
    length = complexity["length"]

    # ── Length ───────────────────────────────────────────────────────────────
    if length >= 20:     score += 30
    elif length >= 16:   score += 25
    elif length >= 12:   score += 20
    elif length >= 10:   score += 14
    elif length >= 8:    score += 8
    elif length >= 6:    score += 4

    # ── Character-class complexity ───────────────────────────────────────────
    if complexity["has_uppercase"]:  score += 7
    if complexity["has_lowercase"]:  score += 7
    if complexity["has_digits"]:     score += 7
    if complexity["has_special"]:    score += 7

    # ── Entropy ──────────────────────────────────────────────────────────────
    if entropy >= 90:    score += 22
    elif entropy >= 70:  score += 18
    elif entropy >= 50:  score += 12
    elif entropy >= 35:  score += 6
    elif entropy >= 20:  score += 3

    # ── Penalties ────────────────────────────────────────────────────────────
    score -= min(len(patterns) * 5, 25)   # weak pattern penalty
    if breach_count > 0:
        score -= 30                        # breach penalty

    score = max(0, min(100, score))

    # Determine label
    rating = "Very Weak"
    for threshold, label in _RATINGS:
        if score >= threshold:
            rating = label
            break

    return score, rating


# ══════════════════════════════════════════════════════════════════════════════
# Improvement Suggestions
# ══════════════════════════════════════════════════════════════════════════════

def suggest_improvements(
    complexity: Dict,
    patterns: List[str],
    breach_found: bool,
) -> List[str]:
    """
    Generate prioritised, actionable tips for strengthening the password.

    Args:
        complexity:   Result of analyze_complexity().
        patterns:     Detected weakness patterns.
        breach_found: True if the password appeared in HIBP.

    Returns:
        List of suggestion strings ordered by priority.
    """
    tips: List[str] = []

    if breach_found:
        tips.append(
            "⚠️  This password appeared in known data breaches — stop using it immediately!"
        )
    if complexity["length"] < 12:
        tips.append("📏 Increase length to at least 12 characters (16+ is strongly recommended)")
    if not complexity["has_uppercase"]:
        tips.append("🔠 Add uppercase letters (A–Z)")
    if not complexity["has_lowercase"]:
        tips.append("🔡 Add lowercase letters (a–z)")
    if not complexity["has_digits"]:
        tips.append("🔢 Add digits (0–9)")
    if not complexity["has_special"]:
        tips.append("🔣 Add special characters (!@#$%^&* etc.)")
    if patterns:
        tips.append("🚫 Remove predictable words, sequences, and patterns")
        tips.append(
            "💡 Consider a passphrase: 4+ random words with numbers/symbols "
            "(e.g. 'coral-lamp-forest-7!')"
        )
    if (
        complexity["length"] > 4
        and complexity["unique_chars"] < max(int(complexity["length"] * 0.6), 6)
    ):
        tips.append("🔀 Increase character variety — too many repeated characters")
    if not tips:
        tips.append("✅ Password looks solid! Store it in a reputable password manager.")

    return tips


# ══════════════════════════════════════════════════════════════════════════════
# Password Generator
# ══════════════════════════════════════════════════════════════════════════════

def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
) -> str:
    """
    Generate a cryptographically secure random password.

    Uses Python's `secrets` module (backed by the OS CSPRNG). Guarantees
    at least one character from each enabled category and performs a
    secure shuffle so the required characters are not predictably placed.

    Args:
        length:        Desired length (clamped to 8–128).
        use_uppercase: Include A–Z.
        use_lowercase: Include a–z.
        use_digits:    Include 0–9.
        use_special:   Include punctuation / symbols.

    Returns:
        A securely generated password string.
    """
    length = max(8, min(128, length))
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    pool:     str       = ""
    required: List[str] = []

    if use_lowercase:
        pool += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if use_special:
        pool += SPECIAL_CHARS
        required.append(secrets.choice(SPECIAL_CHARS))

    # Fallback: ensure we always have a pool
    if not pool:
        pool     = string.ascii_letters + string.digits
        required = [secrets.choice(pool)]

    # Fill remaining slots then securely shuffle
    remainder = [secrets.choice(pool) for _ in range(length - len(required))]
    chars = required + remainder
    secrets.SystemRandom().shuffle(chars)

    return "".join(chars)


# ══════════════════════════════════════════════════════════════════════════════
# Unified Analysis Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def full_analysis(password: str, check_hibp: bool = True) -> Dict:
    """
    Run every analysis step and return a unified result dictionary.

    Pipeline:
      1. Complexity breakdown
      2. Entropy calculation
      3. Crack-time estimate
      4. Pattern & weakness detection
      5. HIBP breach check (optional)
      6. Strength score + rating
      7. Improvement suggestions

    The plaintext password is NEVER included in the returned dictionary.

    Args:
        password:    The password to analyse.
        check_hibp:  If True, query the HIBP API for breach data.

    Returns:
        dict with keys:
          complexity  – output of analyze_complexity()
          entropy     – float (bits)
          crack_time  – human-readable estimate string
          patterns    – list of weakness descriptions
          breach      – dict {checked, found, count, api_available}
          score       – int 0–100
          rating      – str label
          suggestions – list of tip strings
    """
    complexity = analyze_complexity(password)
    entropy    = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    patterns   = detect_patterns(password)

    breach_info: Dict = {
        "checked":       False,
        "found":         False,
        "count":         0,
        "api_available": False,
    }

    if check_hibp:
        found, count = check_breach(password)
        breach_info = {
            "checked":       count != -1,
            "found":         found,
            "count":         max(count, 0),
            "api_available": count != -1,
        }

    score, rating = calculate_score(
        complexity,
        patterns,
        entropy,
        breach_count=breach_info["count"] if breach_info["found"] else 0,
    )

    suggestions = suggest_improvements(
        complexity, patterns, breach_found=breach_info["found"]
    )

    return {
        "complexity":  complexity,
        "entropy":     entropy,
        "crack_time":  crack_time,
        "patterns":    patterns,
        "breach":      breach_info,
        "score":       score,
        "rating":      rating,
        "suggestions": suggestions,
    }
