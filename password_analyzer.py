"""A small, privacy-friendly command-line password strength checker."""

from __future__ import annotations

import getpass
import math
import secrets
import string
from dataclasses import dataclass


MINIMUM_LENGTH = 9
GENERATED_PASSWORD_LENGTH = 9
SYMBOLS = "!@#$%^&*_-+=?"


@dataclass(frozen=True)
class PasswordReport:
    """The result of analysing a password without retaining it."""

    label: str
    feedback: tuple[str, ...]
    length: int
    character_types: int
    estimated_search_space_bits: float


def ask_for_name() -> str:
    """Return a validated first name for a friendly greeting."""
    while True:
        full_name = input("Enter your full name: ").strip()
        name_parts = full_name.split()
        if len(name_parts) < 2:
            print("Please enter both your first and last name.")
        elif not all(part.isalpha() for part in name_parts):
            print("Names may contain letters only.")
        else:
            return name_parts[0].title()


def read_password() -> str:
    """Read a non-empty password without echoing it to the terminal."""
    while True:
        password = getpass.getpass("Enter a password to analyse: ")
        if password:
            return password
        print("A password cannot be empty.")


def character_pool_size(password: str) -> tuple[int, int]:
    """Return the available character pool and number of types used."""
    pools = (
        (any(character.islower() for character in password), len(string.ascii_lowercase)),
        (any(character.isupper() for character in password), len(string.ascii_uppercase)),
        (any(character.isdigit() for character in password), len(string.digits)),
        (any(character in SYMBOLS for character in password), len(SYMBOLS)),
    )
    used_pools = [(is_used, size) for is_used, size in pools if is_used]
    return sum(size for _, size in used_pools), len(used_pools)


def analyse_password(password: str) -> PasswordReport:
    """Assess length and variety; the estimate is guidance, not a guarantee."""
    pool_size, character_types = character_pool_size(password)
    feedback: list[str] = []

    if len(password) < MINIMUM_LENGTH:
        feedback.append(f"Use at least {MINIMUM_LENGTH} characters.")
    if character_types < 3:
        feedback.append("Mix upper-case, lower-case, numbers, and symbols.")
    if password.lower() in {"password", "password123", "qwerty", "admin"}:
        feedback.append("Avoid common passwords and predictable patterns.")
    if password != password.strip():
        feedback.append("Avoid leading or trailing spaces; websites may remove them.")

    estimated_bits = len(password) * math.log2(pool_size) if pool_size else 0.0
    if len(password) >= 20 and character_types >= 3 and not feedback:
        label = "Strong"
    elif len(password) >= MINIMUM_LENGTH and character_types >= 2:
        label = "Good"
    else:
        label = "Weak"

    if not feedback:
        feedback.append("Use a unique password for every account.")

    return PasswordReport(
        label=label,
        feedback=tuple(feedback),
        length=len(password),
        character_types=character_types,
        estimated_search_space_bits=estimated_bits,
    )


def generate_password(length: int = GENERATED_PASSWORD_LENGTH) -> str:
    """Create a secure password containing all four common character types."""
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    password_characters = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(SYMBOLS),
    ]
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    password_characters.extend(
        secrets.choice(alphabet) for _ in range(length - len(password_characters))
    )
    secrets.SystemRandom().shuffle(password_characters)
    return "".join(password_characters)


def ask_to_generate_password() -> None:
    """Offer a secure generated password after displaying the report."""
    while True:
        choice = input("Generate a secure 9-character password? (y/n): ").strip().lower()
        if choice == "y":
            print(f"\nGenerated password: {generate_password()}")
            print("Save it in a password manager; it will not be shown again.\n")
            return
        if choice == "n":
            return
        print("Please enter 'y' or 'n'.")


def display_report(report: PasswordReport) -> None:
    """Print a readable password-strength summary."""
    print(f"\nStrength: {report.label}")
    print(f"Length: {report.length} characters")
    print(f"Character types used: {report.character_types}/4")
    print(f"Estimated random search space: {report.estimated_search_space_bits:.0f} bits")
    print("Advice:")
    for item in report.feedback:
        print(f"- {item}")


def main() -> None:
    """Run the interactive password analyser."""
    print("Password Analyzer\n-----------------")
    first_name = ask_for_name()
    print(f"Welcome, {first_name}. Your password is not stored.\n")
    password = read_password()
    display_report(analyse_password(password))
    ask_to_generate_password()
    print("Thanks for using Password Analyzer.")


if __name__ == "__main__":
    main()
