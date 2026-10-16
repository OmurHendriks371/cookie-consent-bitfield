from __future__ import annotations

import base64
import struct
from typing import Dict, List, Optional, Tuple

# --- Why a bit-level reader instead of struct.unpack ---
# IAB TCF strings pack fields at arbitrary bit offsets that rarely align to
# byte boundaries.  Using struct.unpack would require manual shifting and
# masking anyway, so we read bits sequentially from a single bit-stream.
# The reader treats the bit-stream as big-endian (MSB first), which is what
# the IAB TCF v2 specification mandates.


class _BitReader:
    """Sequential big-endian bit reader over a bytes payload."""

    __slots__ = ("_data", "_pos", "_nbits")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self._nbits = len(data) * 8

    def read(self, n: int) -> int:
        if n <= 0:
            raise ValueError("number of bits to read must be positive")
        if self._pos + n > self._nbits:
            raise ValueError(
                f"attempt to read {n} bits past end of {self._nbits}-bit stream"
            )
        value = 0
        for _ in range(n):
            byte_index = self._pos >> 3
            bit_index = 7 - (self._pos & 7)
            bit = (self._data[byte_index] >> bit_index) & 1
            value = (value << 1) | bit
            self._pos += 1
        return value

    def remaining(self) -> int:
        return self._nbits - self._pos


class _BitWriter:
    """Sequential big-endian bit writer producing a bytes payload."""

    __slots__ = ("_bytes", "_nbits")

    def __init__(self) -> None:
        self._bytes: List[int] = []
        self._nbits = 0

    def write(self, value: int, n: int) -> None:
        if n <= 0:
            raise ValueError("number of bits to write must be positive")
        if value < 0:
            raise ValueError("cannot write a negative value")
        if value.bit_length() > n:
            raise ValueError(
                f"value {value} does not fit in {n} bits (needs {value.bit_length()})"
            )
        for i in range(n - 1, -1, -1):
            bit = (value >> i) & 1
            if self._nbits % 8 == 0:
                self._bytes.append(0)
            if bit:
                self._bytes[-1] |= 1 << (7 - (self._nbits % 8))
            self._nbits += 1

    def to_bytes(self) -> bytes:
        return bytes(self._bytes)


class _RangeReader:
    """Reads an IAB "range section" used for purposes, vendors, etc.

    A range section starts with a 1-bit flag.  When the flag is 0 the section is
    a simple bitfield with one bit per entry up to ``max_id``.  When the flag is 1
    the section is a list of (start, end) inclusive ranges, preceded by a count.
    """

    @staticmethod
    def read_set(reader: _BitReader, max_id: int) -> List[int]:
        if max_id <= 0:
            return []
        range_encoding = reader.read(1)
        if range_encoding == 0:
            result: List[int] = []
            for entry_id in range(1, max_id + 1):
                if reader.read(1) == 1:
                    result.append(entry_id)
            return result
        num_ranges = reader.read(12)
        result = []
        for _ in range(num_ranges):
            # A range may be a single ID ("range" of length one) encoded in
            # 16 bits, or an interval encoded as 16-bit start + 16-bit end.
            # The TCF spec uses a discriminator: if the next 16 bits equal
            # the first ID of a pair, it is a singleton; otherwise it is a
            # pair.  In practice, encoders emit singletons as (start, start)
            # and intervals as (start, end) with start < end.  We decode
            # both forms uniformly.
            start = reader.read(16)
            end = reader.read(16)
            if start > end:
                raise ValueError(
                    f"invalid range: start {start} > end {end}"
                )
            if end > max_id:
                raise ValueError(
                    f"range end {end} exceeds max id {max_id}"
                )
            result.extend(range(start, end + 1))
        return result


class _RangeWriter:
    """Writes a set of integer IDs as an IAB range section.

    We always emit the bitfield encoding (flag=0) because it is simpler and
    deterministic, and is always valid regardless of how sparse the set is.
    A production encoder might switch to the range encoding when the set is
    sparse, but correctness and simplicity are preferred here.
    """

    @staticmethod
    def write_set(writer: _BitWriter, ids: List[int], max_id: int) -> None:
        writer.write(0, 1)  # bitfield encoding
        id_set = set(ids)
        for entry_id in range(1, max_id + 1):
            writer.write(1 if entry_id in id_set else 0, 1)


class TCString:
    """Parsed representation of an IAB TCF v2 consent string.

    Only the fields needed to interpret consent are stored.  Unknown or
    version-specific tail fields are ignored, which means a string encoded
    with a future minor version will still parse so long as the header fields
    remain stable.
    """

    def __init__(
        self,
        version: int,
        created: int,
        last_updated: int,
        cmp_id: int,
        cmp_version: int,
        consent_screen: str,
        consent_language: str,
        vendor_list_version: int,
        policy_version: int,
        service_specific: bool,
        use_non_standard_texts: bool,
        special_feature_optins: List[int],
        purposes_consent: List[int],
        purposes_li_transparency: List[int],
        vendors_consent: List[int],
        vendors_li_transparency: List[int],
    ) -> None:
        self.version = version
        self.created = created
        self.last_updated = last_updated
        self.cmp_id = cmp_id
        self.cmp_version = cmp_version
        self.consent_screen = consent_screen
        self.consent_language = consent_language
        self.vendor_list_version = vendor_list_version
        self.policy_version = policy_version
        self.service_specific = service_specific
        self.use_non_standard_texts = use_non_standard_texts
        self.special_feature_optins = special_feature_optins
        self.purposes_consent = purposes_consent
        self.purposes_li_transparency = purposes_li_transparency
        self.vendors_consent = vendors_consent
        self.vendors_li_transparency = vendors_li_transparency

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "created": self.created,
            "last_updated": self.last_updated,
            "cmp_id": self.cmp_id,
            "cmp_version": self.cmp_version,
            "consent_screen": self.consent_screen,
            "consent_language": self.consent_language,
            "vendor_list_version": self.vendor_list_version,
            "policy_version": self.policy_version,
            "service_specific": self.service_specific,
            "use_non_standard_texts": self.use_non_standard_texts,
            "special_feature_optins": self.special_feature_optins,
            "purposes_consent": self.purposes_consent,
            "purposes_li_transparency": self.purposes_li_transparency,
            "vendors_consent": self.vendors_consent,
            "vendors_li_transparency": self.vendors_li_transparency,
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TCString):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __repr__(self) -> str:
        return f"TCString(version={self.version!r})"


# Field widths defined by the IAB TCF v2 core string specification.
# Keeping them as module constants makes the encode/decode paths easy to audit.
_CORE_FIELDS = {
    "version": 6,
    "created": 36,
    "last_updated": 36,
    "cmp_id": 12,
    "cmp_version": 12,
    "consent_screen": 6,
    "policy_version": 6,
    "vendor_list_version": 12,
    "tcf_policy_version": 6,
    "service_specific": 1,
    "use_non_standard_texts": 1,
    "special_features": 12,
    "purposes_consent": 24,
    "purposes_li_transparency": 24,
}
_MAX_SPECIAL_FEATURE_ID = 12
_MAX_PURPOSE_ID = 24


def decode(encoded: str) -> TCString:
    """Decode a base64url IAB TCF v2 consent string into a :class:`TCString`.

    Only TCF v2 (version field == 2) is supported.  A different version raises
    :class:`ValueError` with the offending version number so callers can branch.
    """
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("consent string must be a non-empty string")

    # IAB TCF strings use base64url **without** padding.  Python's base64
    # module rejects missing padding, so we re-add it before decoding.
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"consent string is not valid base64url: {exc}") from exc

    reader = _BitReader(raw)

    version = reader.read(_CORE_FIELDS["version"])
    if version != 2:
        raise ValueError(
            f"unsupported TCF version: {version} (only version 2 is supported)"
        )

    created = reader.read(_CORE_FIELDS["created"])
    last_updated = reader.read(_CORE_FIELDS["last_updated"])
    cmp_id = reader.read(_CORE_FIELDS["cmp_id"])
    cmp_version = reader.read(_CORE_FIELDS["cmp_version"])
    consent_screen = reader.read(_CORE_FIELDS["consent_screen"])
    policy_version = reader.read(_CORE_FIELDS["policy_version"])
    vendor_list_version = reader.read(_CORE_FIELDS["vendor_list_version"])
    tcf_policy_version = reader.read(_CORE_FIELDS["tcf_policy_version"])
    service_specific = reader.read(_CORE_FIELDS["service_specific"]) == 1
    use_non_standard_texts = reader.read(
        _CORE_FIELDS["use_non_standard_texts"]
    ) == 1

    # Special features and purposes are fixed-width bitfields.
    special_feature_optins = [
        i + 1
        for i in range(_MAX_SPECIAL_FEATURE_ID)
        if reader.read(1) == 1
    ]
    purposes_consent = [
        i + 1 for i in range(_MAX_PURPOSE_ID) if reader.read(1) == 1
    ]
    purposes_li_transparency = [
        i + 1 for i in range(_MAX_PURPOSE_ID) if reader.read(1) == 1
    ]

    # The "max vendor id" fields determine the width of the vendor sections.
    # If a string is truncated, reading these may raise; we let that propagate
    # as a ValueError because a truncated string is genuinely malformed.
    max_vendor_id_consent = reader.read(16)
    vendors_consent = _RangeReader.read_set(reader, max_vendor_id_consent)
    max_vendor_id_li = reader.read(16)
    vendors_li_transparency = _RangeReader.read_set(reader, max_vendor_id_li)

    # We intentionally do not parse the publisher-specific tail.  Storing it
    # would bloat the object and it is not meaningful without publisher CC.
    return TCString(
        version=version,
        created=created,
        last_updated=last_updated,
        cmp_id=cmp_id,
        cmp_version=cmp_version,
        consent_screen=str(consent_screen),
        consent_language="",
        vendor_list_version=vendor_list_version,
        policy_version=policy_version,
        service_specific=service_specific,
        use_non_standard_texts=use_non_standard_texts,
        special_feature_optins=special_feature_optins,
        purposes_consent=purposes_consent,
        purposes_li_transparency=purposes_li_transparency,
        vendors_consent=vendors_consent,
        vendors_li_transparency=vendors_li_transparency,
    )


def encode(tc: TCString) -> str:
    """Encode a :class:`TCString` back into a base64url IAB TCF v2 string.

    The output is unpadded base64url, matching how browsers store the value.
    Round-tripping ``encode(decode(s)) == s`` is **not** guaranteed because
    the decoder ignores the publisher tail and the encoder always uses the
    bitfield range encoding.  The decoded *fields*, however, are preserved.
    """
    writer = _BitWriter()
    writer.write(tc.version, _CORE_FIELDS["version"])
    writer.write(tc.created, _CORE_FIELDS["created"])
    writer.write(tc.last_updated, _CORE_FIELDS["last_updated"])
    writer.write(tc.cmp_id, _CORE_FIELDS["cmp_id"])
    writer.write(tc.cmp_version, _CORE_FIELDS["cmp_version"])
    writer.write(int(tc.consent_screen), _CORE_FIELDS["consent_screen"])
    writer.write(tc.policy_version, _CORE_FIELDS["policy_version"])
    writer.write(tc.vendor_list_version, _CORE_FIELDS["vendor_list_version"])
    # tcf_policy_version is stored in the wire format but not exposed on the
    # object because it duplicates policy_version in practice.  We write the
    # same value to keep the layout correct.
    writer.write(tc.policy_version, _CORE_FIELDS["tcf_policy_version"])
    writer.write(1 if tc.service_specific else 0, _CORE_FIELDS["service_specific"])
    writer.write(
        1 if tc.use_non_standard_texts else 0,
        _CORE_FIELDS["use_non_standard_texts"],
    )

    for i in range(1, _MAX_SPECIAL_FEATURE_ID + 1):
        writer.write(1 if i in tc.special_feature_optins else 0, 1)
    for i in range(1, _MAX_PURPOSE_ID + 1):
        writer.write(1 if i in tc.purposes_consent else 0, 1)
    for i in range(1, _MAX_PURPOSE_ID + 1):
        writer.write(1 if i in tc.purposes_li_transparency else 0, 1)

    max_vendor_id_consent = max(tc.vendors_consent, default=0)
    writer.write(max_vendor_id_consent, 16)
    _RangeWriter.write_set(writer, tc.vendors_consent, max_vendor_id_consent)

    max_vendor_id_li = max(tc.vendors_li_transparency, default=0)
    writer.write(max_vendor_id_li, 16)
    _RangeWriter.write_set(writer, tc.vendors_li_transparency, max_vendor_id_li)

    raw = writer.to_bytes()
    # urlsafe_b64encode produces padding; strip it to match IAB convention.
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
