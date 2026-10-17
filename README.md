# cookie-consent-bitfield

Encodes and decodes IAB TCF v2 base64 consent strings into structured fields.

```python
from cookie_consent_bitfield import decode, encode, TCString

# Construct a consent record by hand
from cookie_consent_bitfield.core import _BitWriter
import base64

writer = _BitWriter()
writer.write(2, 6)          # version
writer.write(0, 36)         # created
writer.write(0, 36)         # last_updated
writer.write(0, 12)        # cmp_id
writer.write(0, 12)        # cmp_version
writer.write(0, 6)         # consent_screen
writer.write(2, 6)         # policy_version
writer.write(0, 12)        # vendor_list_version
writer.write(2, 6)         # tcf_policy_version
writer.write(0, 1)         # service_specific
writer.write(0, 1)         # use_non_standard_texts
for _ in range(12):        # special features
    writer.write(0, 1)
for _ in range(24):        # purposes consent
    writer.write(0, 1)
for _ in range(24):        # purposes LI
    writer.write(0, 1)
writer.write(0, 16)        # max vendor id consent
writer.write(0, 16)        # max vendor id LI
s = base64.urlsafe_b64encode(
    writer.to_bytes()
).decode("ascii").rstrip("=")

tc = decode(s)
print(tc.version)            # 2
print(tc.purposes_consent)   # list of purpose IDs the user consented to
print(tc.vendors_consent)    # list of vendor IDs the user consented to

# Re-encode to a base64url string
s = encode(tc)
```

## Why this exists

Working with raw IAB TCF strings means parsing a compact bit-field format by hand every time you want to know which purposes or vendors a user consented to. This library does that parsing once and gives you plain Python lists and ints. The trade-off: only TCF v2 is supported, and the publisher-specific tail section is not parsed. If you need publisher constraints or TCF v1 support, this is not the right tool.

## Edge cases

- **Not round-trip identical.** `encode(decode(s))` will not reproduce the original string byte-for-byte. The decoder ignores the publisher tail, and the encoder always uses the bitfield (non-range) encoding for vendor sections. The decoded *fields* survive a round-trip; the raw bytes may differ.
- **Version check.** Strings whose version field is not `2` raise `ValueError` immediately. TCF v1 has a different layout and is not handled.
- **Truncated strings.** If the base64 payload is too short to contain the core fields, decoding raises `ValueError`.
- **`consent_language` is not parsed** from the core string; it is always an empty string. The two-letter language code lives in a publisher section this library does not decode.
