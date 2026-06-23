/**
 * passwordUtils.js
 * ────────────────
 * Port of password_utils.py to JavaScript.
 * Implements real-time analysis, cryptographic generation, and HaveIBeenPwned API interface.
 */

// Top commonly used / leaked passwords (sourced from HIBP / SecLists)
export const COMMON_PASSWORDS = [
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
  "september", "october", "november", "december"
];

// Common English first names to detect inside passwords
export const COMMON_NAMES = [
  "james", "john", "robert", "michael", "william", "david", "richard",
  "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
  "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
  "kevin", "brian", "george", "timothy", "ronald", "edward", "jason",
  "mary", "patricia", "jennifer", "linda", "barbara", "elizabeth",
  "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty",
  "margaret", "sandra", "ashley", "emily", "amanda", "melissa",
  "dorothy", "helen", "carol", "michelle", "laura", "kimberly"
];

// QWERTY keyboard rows for adjacency pattern detection
export const KEYBOARD_ROWS = [
  "qwertyuiop",
  "asdfghjkl",
  "zxcvbnm",
  "1234567890"
];

const ALPHA = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";

// Common leet-speak substitution map (char -> real letter)
export const LEET_MAP = {
  "@": "a", "4": "a",
  "3": "e",
  "1": "i", "!": "i",
  "0": "o",
  "$": "s", "5": "s",
  "7": "t",
  "8": "b"
};

// Rating thresholds
export const RATINGS = [
  { threshold: 80, label: "Very Strong" },
  { threshold: 60, label: "Strong" },
  { threshold: 40, label: "Medium" },
  { threshold: 20, label: "Weak" },
  { threshold: 0,  label: "Very Weak" }
];

// Regex filters
const RE_LOWER = /[a-z]/;
const RE_UPPER = /[A-Z]/;
const RE_DIGIT = /\d/;
const RE_SPECIAL = /[!@#$%^&*()_\-=\+\[\]\{\};:'",\.<>\/?\\\|`~]/;
const RE_REPEAT = /(.)\1{2,}/;
const RE_YEAR = /(19|20)\d{2}/;

/**
 * Estimate password entropy in bits using the character-set model.
 */
export function calculateEntropy(password) {
  if (!password) return 0;
  let n = 0;
  if (RE_LOWER.test(password)) n += 26;
  if (RE_UPPER.test(password)) n += 26;
  if (RE_DIGIT.test(password)) n += 10;
  if (RE_SPECIAL.test(password)) n += 32;

  if (n === 0) return 0;
  const entropy = password.length * Math.log2(n);
  return parseFloat(entropy.toFixed(2));
}

/**
 * Convert entropy bits to a human-readable brute-force time estimate.
 */
export function estimateCrackTime(entropy) {
  if (entropy <= 0) return "Instantly";

  const GUESSES_PER_SEC = 1e12; // 10^12 / second (high-end offline attack)
  const seconds = Math.pow(2, entropy) / GUESSES_PER_SEC;

  if (seconds < 1) {
    return "< 1 second";
  } else if (seconds < 60) {
    return `~${Math.round(seconds)} seconds`;
  } else if (seconds < 3600) {
    return `~${Math.round(seconds / 60)} minutes`;
  } else if (seconds < 86400) {
    return `~${(seconds / 3600).toFixed(1)} hours`;
  } else if (seconds < 86400 * 30) {
    return `~${(seconds / 86400).toFixed(1)} days`;
  } else if (seconds < 86400 * 365) {
    return `~${(seconds / (86400 * 30)).toFixed(1)} months`;
  } else if (seconds < 86400 * 365 * 1000) {
    return `~${(seconds / (86400 * 365)).toFixed(1)} years`;
  } else if (seconds < 86400 * 365 * 1000000) {
    return `~${Math.round(seconds / (86400 * 365 * 1000))} thousand years`;
  } else if (seconds < 86400 * 365 * 1e9) {
    return `~${Math.round(seconds / (86400 * 365 * 1e6))} million years`;
  } else {
    return "Practically uncrackable";
  }
}

/**
 * Return a detailed breakdown of the password's character composition.
 */
export function analyzeComplexity(password) {
  return {
    length: password.length,
    hasUppercase: RE_UPPER.test(password),
    hasLowercase: RE_LOWER.test(password),
    hasDigits: RE_DIGIT.test(password),
    hasSpecial: RE_SPECIAL.test(password),
    uppercaseCount: (password.match(/[A-Z]/g) || []).length,
    lowercaseCount: (password.match(/[a-z]/g) || []).length,
    digitCount: (password.match(/\d/g) || []).length,
    specialCount: (password.match(/[!@#$%^&*()_\-=\+\[\]\{\};:'",\.<>\/?\\\|`~]/g) || []).length,
    uniqueChars: new Set(password).size
  };
}

/**
 * Replace leet-speak characters with their alphabetic equivalents.
 */
function reverseLeet(text) {
  let result = text.toLowerCase();
  for (const [leetChar, realChar] of Object.entries(LEET_MAP)) {
    result = result.replaceAll(leetChar, realChar);
  }
  return result;
}

/**
 * Identify common weak patterns inside the password.
 */
export function detectPatterns(password) {
  const issues = [];
  const pwdLower = password.toLowerCase();
  const unleetPwd = reverseLeet(password);

  // 1. Common password list
  if (COMMON_PASSWORDS.includes(pwdLower) || COMMON_PASSWORDS.includes(unleetPwd)) {
    issues.push("Password (or its leet-speak variant) is in the most-common passwords list");
  }

  // 2. Keyboard row sequences
  for (const row of KEYBOARD_ROWS) {
    let found = false;
    for (let runLen = Math.min(6, row.length); runLen > 3; runLen--) {
      if (found) break;
      for (let i = 0; i <= row.length - runLen; i++) {
        const chunk = row.substring(i, i + runLen);
        const reversedChunk = chunk.split("").reverse().join("");
        if (pwdLower.includes(chunk)) {
          issues.push(`Contains keyboard sequence: '${chunk}'`);
          found = true;
          break;
        }
        if (pwdLower.includes(reversedChunk)) {
          issues.push(`Contains reversed keyboard sequence: '${reversedChunk}'`);
          found = true;
          break;
        }
      }
    }
  }

  // 3. Alphabetical sequences
  let alphaFound = false;
  for (let runLen = Math.min(6, password.length); runLen > 2; runLen--) {
    if (alphaFound) break;
    for (let i = 0; i <= ALPHA.length - runLen; i++) {
      const chunk = ALPHA.substring(i, i + runLen);
      const reversedChunk = chunk.split("").reverse().join("");
      if (pwdLower.includes(chunk)) {
        issues.push(`Contains alphabetical sequence: '${chunk}'`);
        alphaFound = true;
        break;
      }
      if (pwdLower.includes(reversedChunk)) {
        issues.push(`Contains reverse alphabetical sequence: '${reversedChunk}'`);
        alphaFound = true;
        break;
      }
    }
  }

  // 4. Digit sequences
  let digitFound = false;
  for (let runLen = Math.min(6, password.length); runLen > 2; runLen--) {
    if (digitFound) break;
    for (let i = 0; i <= DIGITS.length - runLen; i++) {
      const chunk = DIGITS.substring(i, i + runLen);
      const reversedChunk = chunk.split("").reverse().join("");
      if (pwdLower.includes(chunk)) {
        issues.push(`Contains digit sequence: '${chunk}'`);
        digitFound = true;
        break;
      }
      if (pwdLower.includes(reversedChunk)) {
        issues.push(`Contains reverse digit sequence: '${reversedChunk}'`);
        digitFound = true;
        break;
      }
    }
  }

  // 5. Repeated characters
  const repMatch = password.match(RE_REPEAT);
  if (repMatch) {
    issues.push(`Contains repeated characters: '${repMatch[0]}'`);
  }

  // 6. Year patterns
  const yearMatch = password.match(RE_YEAR);
  if (yearMatch) {
    issues.push(`Contains a year: '${yearMatch[0]}' (easily guessable)`);
  }

  // 7. Common names
  for (const name of COMMON_NAMES) {
    if (name.length >= 4 && pwdLower.includes(name)) {
      issues.push(`Contains a common name: '${name}'`);
      break;
    }
  }

  // 8. All digits
  if (/^\d+$/.test(password)) {
    issues.push("Password is entirely numeric (trivially crackable)");
  }

  // 9. Palindrome
  if (password.length >= 5 && pwdLower === pwdLower.split("").reverse().join("")) {
    issues.push("Password is a palindrome (mirror structure is predictable)");
  }

  // Deduplicate
  return Array.from(new Set(issues));
}

/**
 * Compute an overall 0–100 strength score and rating label.
 */
export function calculateScore(complexity, patterns, entropy, breachCount = 0) {
  let score = 0;
  const length = complexity.length;

  // Length contribution (0–30 pts)
  if (length >= 20) score += 30;
  else if (length >= 16) score += 25;
  else if (length >= 12) score += 20;
  else if (length >= 10) score += 14;
  else if (length >= 8) score += 8;
  else if (length >= 6) score += 4;

  // Complexity contribution (0-28 pts)
  if (complexity.hasUppercase) score += 7;
  if (complexity.hasLowercase) score += 7;
  if (complexity.hasDigits) score += 7;
  if (complexity.hasSpecial) score += 7;

  // Entropy contribution (0-22 pts)
  if (entropy >= 90) score += 22;
  else if (entropy >= 70) score += 18;
  else if (entropy >= 50) score += 12;
  else if (entropy >= 35) score += 6;
  else if (entropy >= 20) score += 3;

  // Penalties
  score -= Math.min(patterns.length * 5, 25);
  if (breachCount > 0) {
    score -= 30; // breach penalty
  }

  score = Math.max(0, Math.min(100, score));

  let rating = "Very Weak";
  for (const r of RATINGS) {
    if (score >= r.threshold) {
      rating = r.label;
      break;
    }
  }

  return { score, rating };
}

/**
 * Generate prioritised actionable tips.
 */
export function suggestImprovements(complexity, patterns, breachFound) {
  const tips = [];

  if (breachFound) {
    tips.push("⚠️ This password appeared in known data breaches — stop using it immediately!");
  }
  if (complexity.length < 12) {
    tips.push("📏 Increase length to at least 12 characters (16+ is strongly recommended)");
  }
  if (!complexity.hasUppercase) {
    tips.push("🔠 Add uppercase letters (A–Z)");
  }
  if (!complexity.hasLowercase) {
    tips.push("🔡 Add lowercase letters (a–z)");
  }
  if (!complexity.hasDigits) {
    tips.push("🔢 Add digits (0–9)");
  }
  if (!complexity.hasSpecial) {
    tips.push("🔣 Add special characters (!@#$%^&* etc.)");
  }
  if (patterns.length > 0) {
    tips.push("🚫 Remove predictable words, sequences, and patterns");
    tips.push("💡 Consider a passphrase: 4+ random words with numbers/symbols (e.g. 'coral-lamp-forest-7!')");
  }
  if (complexity.length > 4 && complexity.uniqueChars < Math.max(Math.floor(complexity.length * 0.6), 6)) {
    tips.push("🔀 Increase character variety — too many repeated characters");
  }

  if (tips.length === 0) {
    tips.push("✅ Password looks solid! Store it in a reputable password manager.");
  }

  return tips;
}

/**
 * HaveIBeenPwned API check using SHA-1 and k-anonymity.
 * Returns { checked: boolean, found: boolean, count: number }
 */
export async function checkBreach(password) {
  if (!password) {
    return { checked: false, found: false, count: 0 };
  }

  try {
    // Calculate SHA-1 hash of the password
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();

    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);

    // Call HaveIBeenPwned Range API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        // Range API does not require auth, but HIBP recommends a generic User-Agent
        "User-Agent": "PasswordStrengthAnalyzer-Web-v1.0"
      }
    });

    if (!response.ok) {
      throw new Error("HIBP API request failed");
    }

    const text = await response.text();
    const lines = text.split("\n");

    for (const line of lines) {
      const parts = line.trim().split(":");
      if (parts[0] === suffix) {
        return {
          checked: true,
          found: true,
          count: parseInt(parts[1], 10)
        };
      }
    }

    return {
      checked: true,
      found: false,
      count: 0
    };
  } catch (error) {
    console.error("HaveIBeenPwned API error:", error);
    return {
      checked: false,
      found: false,
      count: 0,
      error: error.message
    };
  }
}

/**
 * Generate a cryptographically secure random password.
 */
export function generatePassword(
  length = 16,
  useUppercase = true,
  useLowercase = true,
  useDigits = true,
  useSpecial = true
) {
  // Clamp length between 8 and 128
  const actualLength = Math.max(8, Math.min(128, length));
  const SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  let pool = "";
  const required = [];

  // Helper to pick a secure random element from a string
  const pickRandom = (str) => {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    const index = array[0] % str.length;
    return str[index];
  };

  if (useLowercase) {
    pool += ALPHA;
    required.push(pickRandom(ALPHA));
  }
  if (useUppercase) {
    pool += ALPHA.toUpperCase();
    required.push(pickRandom(ALPHA.toUpperCase()));
  }
  if (useDigits) {
    pool += DIGITS;
    required.push(pickRandom(DIGITS));
  }
  if (useSpecial) {
    pool += SPECIAL_CHARS;
    required.push(pickRandom(SPECIAL_CHARS));
  }

  // Fallback
  if (!pool) {
    pool = ALPHA + ALPHA.toUpperCase() + DIGITS;
    required.push(pickRandom(pool));
  }

  const remainderLength = actualLength - required.length;
  const remainder = [];
  const randomValues = new Uint32Array(remainderLength);
  window.crypto.getRandomValues(randomValues);

  for (let i = 0; i < remainderLength; i++) {
    const poolIndex = randomValues[i] % pool.length;
    remainder.push(pool[poolIndex]);
  }

  const chars = required.concat(remainder);

  // Secure shuffle using Fisher-Yates and cryptographic values
  for (let i = chars.length - 1; i > 0; i--) {
    const randomArray = new Uint32Array(1);
    window.crypto.getRandomValues(randomArray);
    const j = randomArray[0] % (i + 1);
    const temp = chars[i];
    chars[i] = chars[j];
    chars[j] = temp;
  }

  return chars.join("");
}

/**
 * Unified full analysis wrapper.
 */
export async function fullAnalysis(password, checkHibp = true) {
  const complexity = analyzeComplexity(password);
  const entropy = calculateEntropy(password);
  const crackTime = estimateCrackTime(entropy);
  const patterns = detectPatterns(password);

  let breachInfo = { checked: false, found: false, count: 0 };
  if (checkHibp) {
    breachInfo = await checkBreach(password);
  }

  const { score, rating } = calculateScore(
    complexity,
    patterns,
    entropy,
    breachInfo.found ? breachInfo.count : 0
  );

  const suggestions = suggestImprovements(complexity, patterns, breachInfo.found);

  return {
    complexity,
    entropy,
    crackTime,
    patterns,
    breach: breachInfo,
    score,
    rating,
    suggestions
  };
}
