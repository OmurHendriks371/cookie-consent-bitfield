import base64
import unittest

from cookie_consent_bitfield import encode, decode, TCString
from cookie_consent_bitfield.core import _BitReader, _BitWriter


class TestBitReader(unittest.TestCase):
    def test_reads_big_endian(self):
        # 0b10000000 = 128 in one byte
        reader = _BitReader(bytes([0b10000000]))
        self.assertEqual(reader.read(1), 1)
        self.assertEqual(reader.read(7), 0)

    def test_read_across_byte_boundary(self):
        # 0b10101010 0b11001100
        reader = _BitReader(bytes([0b10101010, 0b11001100]))
        self.assertEqual(reader.read(4), 0b1010)
        self.assertEqual(reader.read(4), 0b1010)
        self.assertEqual(reader.read(4), 0b1100)
        self.assertEqual(reader.read(4), 0b1100)

    def test_read_past_end_raises(self):
        reader = _BitReader(bytes([0xFF]))
        with self.assertRaises(ValueError):
            reader.read(9)

    def test_zero_bits_raises(self):
        reader = _BitReader(bytes([0xFF]))
        with self.assertRaises(ValueError):
            reader.read(0)


class TestBitWriter(unittest.TestCase):
    def test_writes_big_endian(self):
        writer = _BitWriter()
        writer.write(1, 1)
        writer.write(0, 7)
        self.assertEqual(writer.to_bytes(), bytes([0b10000000]))

    def test_value_too_large_raises(self):
        writer = _BitWriter()
        with self.assertRaises(ValueError):
            writer.write(8, 3)  # 8 needs 4 bits

    def test_negative_raises(self):
        writer = _BitWriter()
        with self.assertRaises(ValueError):
            writer.write(-1, 4)

    def test_roundtrip(self):
        writer = _BitWriter()
        writer.write(0b1010, 4)
        writer.write(0b1100, 4)
        reader = _BitReader(writer.to_bytes())
        self.assertEqual(reader.read(4), 0b1010)
        self.assertEqual(reader.read(4), 0b1100)


class TestDecode(unittest.TestCase):
    def test_rejects_empty_string(self):
        with self.assertRaises(ValueError):
            decode("")

    def test_rejects_wrong_version(self):
        # version=1 in first 6 bits, rest zeros
        writer = _BitWriter()
        writer.write(1, 6)
        # pad to a full base64 block
        while writer._nbits % 24 != 0:
            writer.write(0, 1)
        raw = writer.to_bytes()
        encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        with self.assertRaises(ValueError) as ctx:
            decode(encoded)
        self.assertIn("version", str(ctx.exception))

    def test_rejects_non_base64(self):
        with self.assertRaises(ValueError):
            decode("not!valid!base64@@")

    def test_parses_minimal_v2_string(self):
        # Build a minimal valid v2 string with no consents.
        writer = _BitWriter()
        writer.write(2, 6)          # version
        writer.write(0, 36)        # created
        writer.write(0, 36)        # last_updated
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
        # no bitfield bits because max is 0
        writer.write(0, 16)        # max vendor id LI
        encoded = base64.urlsafe_b64encode(
            writer.to_bytes()
        ).decode("ascii").rstrip("=")

        tc = decode(encoded)
        self.assertEqual(tc.version, 2)
        self.assertEqual(tc.created, 0)
        self.assertEqual(tc.cmp_id, 0)
        self.assertEqual(tc.special_feature_optins, [])
        self.assertEqual(tc.purposes_consent, [])
        self.assertEqual(tc.vendors_consent, [])

    def test_parses_set_bits(self):
        writer = _BitWriter()
        writer.write(2, 6)
        writer.write(0, 36)
        writer.write(0, 36)
        writer.write(0, 12)
        writer.write(0, 12)
        writer.write(0, 6)
        writer.write(2, 6)
        writer.write(0, 12)
        writer.write(2, 6)
        writer.write(0, 1)
        writer.write(0, 1)
        # special features: turn on feature 1 and 3
        for i in range(1, 13):
            writer.write(1 if i in (1, 3) else 0, 1)
        # purposes consent: turn on 2 and 5
        for i in range(1, 25):
            writer.write(1 if i in (2, 5) else 0, 1)
        # purposes LI: none
        for _ in range(24):
            writer.write(0, 1)
        # vendors consent: max=5, bits for 2 and 4
        writer.write(5, 16)
        writer.write(0, 1)       # bitfield encoding flag
        for i in range(1, 6):
            writer.write(1 if i in (2, 4) else 0, 1)
        # vendors LI: max=0
        writer.write(0, 16)
        encoded = base64.urlsafe_b64encode(
            writer.to_bytes()
        ).decode("ascii").rstrip("=")

        tc = decode(encoded)
        self.assertEqual(tc.special_feature_optins, [1, 3])
        self.assertEqual(tc.purposes_consent, [2, 5])
        self.assertEqual(tc.vendors_consent, [2, 4])
        self.assertEqual(tc.vendors_li_transparency, [])

    def test_parses_range_encoded_vendors(self):
        writer = _BitWriter()
        writer.write(2, 6)
        writer.write(0, 36)
        writer.write(0, 36)
        writer.write(0, 12)
        writer.write(0, 12)
        writer.write(0, 6)
        writer.write(2, 6)
        writer.write(0, 12)
        writer.write(2, 6)
        writer.write(0, 1)
        writer.write(0, 1)
        for _ in range(12):
            writer.write(0, 1)
        for _ in range(24):
            writer.write(0, 1)
        for _ in range(24):
            writer.write(0, 1)
        # vendors consent: max=100, range encoding, one range (10..12)
        writer.write(100, 16)
        writer.write(1, 1)       # range encoding flag
        writer.write(1, 12)      # num ranges
        writer.write(10, 16)     # start
        writer.write(12, 16)     # end
        # vendors LI: max=0
        writer.write(0, 16)
        encoded = base64.urlsafe_b64encode(
            writer.to_bytes()
        ).decode("ascii").rstrip("=")

        tc = decode(encoded)
        self.assertEqual(tc.vendors_consent, [10, 11, 12])

    def test_range_start_greater_than_end_raises(self):
        writer = _BitWriter()
        writer.write(2, 6)
        writer.write(0, 36)
        writer.write(0, 36)
        writer.write(0, 12)
        writer.write(0, 12)
        writer.write(0, 6)
        writer.write(2, 6)
        writer.write(0, 12)
        writer.write(2, 6)
        writer.write(0, 1)
        writer.write(0, 1)
        for _ in range(12):
            writer.write(0, 1)
        for _ in range(24):
            writer.write(0, 1)
        for _ in range(24):
            writer.write(0, 1)
        writer.write(100, 16)
        writer.write(1, 1)       # range encoding
        writer.write(1, 12)       # num ranges
        writer.write(20, 16)     # start
        writer.write(10, 16)     # end (invalid)
        encoded = base64.urlsafe_b64encode(
            writer.to_bytes()
        ).decode("ascii").rstrip("=")
        with self.assertRaises(ValueError):
            decode(encoded)


class TestEncode(unittest.TestCase):
    def _minimal_tc(self) -> TCString:
        return TCString(
            version=2,
            created=0,
            last_updated=0,
            cmp_id=0,
            cmp_version=0,
            consent_screen="0",
            consent_language="",
            vendor_list_version=0,
            policy_version=2,
            service_specific=False,
            use_non_standard_texts=False,
            special_feature_optins=[],
            purposes_consent=[],
            purposes_li_transparency=[],
            vendors_consent=[],
            vendors_li_transparency=[],
        )

    def test_encode_produces_valid_base64url(self):
        encoded = encode(self._minimal_tc())
        # Must be unpadded base64url
        self.assertNotIn("=", encoded)
        padded = encoded + "=" * (-len(encoded) % 4)
        # Should not raise
        base64.urlsafe_b64decode(padded)

    def test_roundtrip_preserves_fields(self):
        tc = self._minimal_tc()
        tc.cmp_id = 42
        tc.purposes_consent = [1, 3, 5]
        tc.vendors_consent = [2, 4, 6]
        tc.special_feature_optins = [1]
        encoded = encode(tc)
        decoded = decode(encoded)
        self.assertEqual(decoded.cmp_id, 42)
        self.assertEqual(decoded.purposes_consent, [1, 3, 5])
        self.assertEqual(decoded.vendors_consent, [2, 4, 6])
        self.assertEqual(decoded.special_feature_optins, [1])

    def test_encode_rejects_oversized_values(self):
        tc = self._minimal_tc()
        tc.cmp_id = 5000  # exceeds 12-bit max of 4095
        with self.assertRaises(ValueError):
            encode(tc)


class TestTCString(unittest.TestCase):
    def test_to_dict_roundtrip(self):
        tc = TCString(
            version=2,
            created=1,
            last_updated=2,
            cmp_id=3,
            cmp_version=4,
            consent_screen="5",
            consent_language="en",
            vendor_list_version=6,
            policy_version=2,
            service_specific=True,
            use_non_standard_texts=False,
            special_feature_optins=[1],
            purposes_consent=[2],
            purposes_li_transparency=[3],
            vendors_consent=[4],
            vendors_li_transparency=[5],
        )
        d = tc.to_dict()
        self.assertEqual(d["cmp_id"], 3)
        self.assertEqual(d["service_specific"], True)
        self.assertEqual(d["purposes_consent"], [2])

    def test_equality(self):
        a = TCString(
            version=2, created=0, last_updated=0, cmp_id=1,
            cmp_version=0, consent_screen="0", consent_language="",
            vendor_list_version=0, policy_version=2,
            service_specific=False, use_non_standard_texts=False,
            special_feature_optins=[], purposes_consent=[],
            purposes_li_transparency=[], vendors_consent=[],
            vendors_li_transparency=[],
        )
        b = TCString(
            version=2, created=0, last_updated=0, cmp_id=1,
            cmp_version=0, consent_screen="0", consent_language="",
            vendor_list_version=0, policy_version=2,
            service_specific=False, use_non_standard_texts=False,
            special_feature_optins=[], purposes_consent=[],
            purposes_li_transparency=[], vendors_consent=[],
            vendors_li_transparency=[],
        )
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
