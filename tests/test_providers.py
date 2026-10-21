import unittest
from selfhosted.select_providers import select


class ProviderTests(unittest.TestCase):
    def test_modes(self):
        for value, expected in [
            ("SELFHOSTED", ([], True)),
            ("NEXTDNS", (["NEXTDNS"], False)),
            ("NEXTDNS,SELFHOSTED", (["NEXTDNS"], True)),
            (" selfhosted, nextdns ", (["NEXTDNS"], True)),
            ("NEXTDNS,SELFHOSTED,CLOUDFLARE,NEXTDNS",
             (["NEXTDNS", "CLOUDFLARE", "NEXTDNS"], True)),
            ("", ([], False)),
        ]:
            with self.subTest(value=value):
                self.assertEqual(select(value), expected)

    def test_typo_fails(self):
        with self.assertRaises(ValueError):
            select("NEXTDNS,SELFHOSTEDD")
