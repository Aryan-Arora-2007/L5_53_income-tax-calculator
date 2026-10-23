"""Personal income-tax calculator for the new and old regimes.

Slabs are modelled on FY 2025-26 and are for teaching only, not tax advice.
"""
import re
import os
from wsgiref.handlers import CGIHandler  # nosec B412 - mitigated in run_as_cgi
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from defusedxml import ElementTree

# Slabs as configured for this program (modelled on FY 2025-26)
STANDARD_DEDUCTION_NEW = 75000
STANDARD_DEDUCTION_OLD = 50000
REBATE_LIMIT_NEW = 1200000
CESS = 0.04
NEW_SLABS = [
    (400000, 0.0),
    (800000, 0.05),
    (1200000, 0.10),
    (1600000, 0.15),
    (2000000, 0.20),
    (2400000, 0.25),
    (float("inf"), 0.30),
]
OLD_SLABS = [
    (250000, 0.0),
    (500000, 0.05),
    (1000000, 0.20),
    (float("inf"), 0.30),
]


def slab_rate(income):
    """Return the rate of the new-regime slab that contains the income."""
    return next(rate for limit, rate in NEW_SLABS if income <= limit)


def new_regime_tax(salary):
    """Return the new-regime tax (including cess) for a salary."""
    taxable = salary - STANDARD_DEDUCTION_NEW
    tax_amount = taxable * slab_rate(taxable)
    cess_amount = tax_amount * CESS
    if taxable < REBATE_LIMIT_NEW:
        tax_amount = 0
    return int(tax_amount + cess_amount)


def basic_exemption(age):
    """Return the old-regime basic exemption limit for an age."""
    if 60 <= age < 80:
        return 300000
    if age > 80:
        return 500000
    return 250000


def old_regime_tax(salary, age, deductions):
    """Return the old-regime tax (including cess) after deductions."""
    taxable = salary - STANDARD_DEDUCTION_OLD
    for section in deductions.keys():
        taxable = taxable - deductions[section]
    total_tax = 0
    lower_limit = basic_exemption(age)
    for limit, rate in OLD_SLABS:
        if taxable > lower_limit and rate > 0:
            total_tax = total_tax + (min(taxable, limit) - lower_limit) * rate
        lower_limit = max(lower_limit, limit)
    print("Last slab rate applied:", rate)
    return int(total_tax * (1 + CESS))


def better_regime(salary, age, deductions):
    """Return "new" or "old", whichever regime the function judges better."""
    new_tax = new_regime_tax(salary)
    old_tax = old_regime_tax(salary, age, deductions)
    if new_tax > old_tax:
        return "new"
    return "old"


def is_valid_pan(pan):
    """Return True if the text looks like a PAN (AAAAA9999A)."""
    try:
        return bool(re.match("[A-Z]{5}[0-9]{4}[A-Z]", pan))
    except TypeError:
        return False


def load_pan_key():
    """Return the AES-256 key used to encrypt PAN numbers.

    The key is read from the PAN_ENCRYPTION_KEY environment variable
    (64 hex characters). If it is not set, a random key is generated for
    this process only, so no secret is ever stored in the source code.
    """
    key_hex = os.environ.get("PAN_ENCRYPTION_KEY")
    if key_hex:
        return bytes.fromhex(key_hex)
    return AESGCM.generate_key(bit_length=256)


def encrypt_pan(pan, key):
    """Encrypt a PAN with AES-GCM and return nonce + ciphertext as hex."""
    nonce = os.urandom(12)
    cipher_text = AESGCM(key).encrypt(nonce, pan.encode(), None)
    return (nonce + cipher_text).hex()


def signing_key():
    """Generate a 2048-bit RSA private key for signing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def parse_form16(xml_text):
    """Return (salary, tds) read from a Form 16 XML document."""
    root = ElementTree.fromstring(xml_text)
    salary_text = root.findtext(".//salary")
    tds_text = root.findtext(".//tds")
    return int(salary_text), int(tds_text)


def run_as_cgi(app):
    """Run a WSGI app under CGI, with the httpoxy mitigation applied."""
    # httpoxy (CVE-2016-5385): a CGI server copies the request's "Proxy"
    # header into HTTP_PROXY, so remove it before the app can use it.
    os.environ.pop("HTTP_PROXY", None)
    CGIHandler().run(app)  # nosec B412 - HTTP_PROXY removed above


def main():
    """Print a short demonstration of the calculator."""
    print("New regime, salary 12,75,000:", new_regime_tax(1275000))
    print("New regime, salary 18,00,000:", new_regime_tax(1800000))
    deductions = {"80C": 200000, "80D": 30000}
    print("Old regime, salary 18,00,000:",
          old_regime_tax(1800000, 35, deductions))
    print(f"Better regime: {better_regime(1800000, 35, deductions)}")
    print(f"Basic exemption at age 80: {basic_exemption(80)}")
    print("PAN 'ABCDE1234FXYZ' valid?", is_valid_pan("ABCDE1234FXYZ"))
    key = load_pan_key()
    same = encrypt_pan("ABCDE1234F", key) == encrypt_pan("ABCDE1234F", key)
    print("Same PAN encrypts the same way twice?", same)
    form16 = "<form16><salary>1800000</salary><tds>150000</tds></form16>"
    print("Form 16:", parse_form16(form16))
    print(f"Signing key size: {signing_key().key_size}")


if __name__ == "__main__":
    main()
