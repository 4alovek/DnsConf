import unittest
from selfhosted.build_filter import build_filter


class FilterTests(unittest.TestCase):
    def test_sections_aliases_and_priority(self):
        text = '# Naukri\n1.2.3.4 naukri.com\n# AMD\n2.3.4.5 amd.com www.amd.com\n# Intel\n3.4.5.6 intel.com\n'
        result = build_filter([text, '9.9.9.9 amd.com'], [], {'naukri'})
        self.assertNotIn('naukri.com', result)
        self.assertIn('||intel.com^$dnsrewrite=NOERROR;A;3.4.5.6', result)
        self.assertEqual(result.count('||amd.com^'), 1)
        self.assertNotIn('9.9.9.9', result)

    def test_ipv6_blocks_and_exceptions(self):
        result = build_filter(['1.2.3.4 example.com\n2.3.4.5 sub.example.com\n2001:db8::1 ipv6.test\n1.1.1.1 notexample.com'], ['0.0.0.0 ads.test\n::1 tracker.test'], ignored=['sub.example.com'])
        self.assertIn('||ipv6.test^$dnsrewrite=NOERROR;AAAA;2001:db8::1', result)
        self.assertIn('@@||sub.example.com^$dnsrewrite', result)
        self.assertNotIn('2.3.4.5', result)
        self.assertIn('||notexample.com^', result)
        self.assertIn('||ads.test^\n', result)
        self.assertIn('||tracker.test^\n', result)

    def test_bad_or_empty_download_does_not_generate_filter(self):
        for text in ['', '<html>error</html>', 'not-an-ip example.com', '1.2.3.4 example.com$badfilter']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                build_filter([text], [])


if __name__ == '__main__':
    unittest.main()
