# Copyright 2020 Steven Kroh
#
# This file is part of rpz-manager.
#
# rpz-manager is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# rpz-manager is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with rpz-manager.  If not, see <https://www.gnu.org/licenses/>.

import tempfile
from http import HTTPStatus
from unittest.case import TestCase
from unittest.mock import MagicMock, patch

from rpz_manager import *
from test.test_data import test_data

logger.setLevel(logging.ERROR)


class PipelineCollapseSubdomainsTest(TestCase):
    def test_duplicate(self):
        domains = ["example.com", "example.com"]
        result = pl_collapse_subdomains(domains, {"window_length": 4})
        self.assertListEqual(["example.com"], list(result))

    def test_subdomain_encountered_before(self):
        domains = ["www.example.com", "example.com"]
        result = pl_collapse_subdomains(domains, {"window_length": 4})
        self.assertListEqual(["example.com"], list(result))

    def test_subdomain_encountered_after(self):
        domains = ["example.com", "www.example.com"]
        result = pl_collapse_subdomains(domains, {"window_length": 4})
        self.assertListEqual(["example.com"], list(result))

    def test_empty(self):
        domains = []
        result = pl_collapse_subdomains(domains, {"window_length": 4})
        self.assertListEqual([], list(result))

    def test_many(self):
        domains = ["example.com", "example.net", "example.org",
                   "example.xyz", "example.biz", "example.gov"]
        result = pl_collapse_subdomains(domains, {"window_length": 4})
        self.assertListEqual(domains, list(result))


class PipelineGeneralTests(TestCase):
    def test_pl_omit_ip_addresses(self):
        items = ["0.0.0.0"]
        result = pl_omit_ip_addresses(items, {})
        self.assertFalse(list(result))

    def test_pl_omit_wildcards(self):
        items = ["*.example.com"]
        result = pl_omit_wildcards(items, {})
        self.assertFalse(list(result))

    def test_pl_omit_invalid_top_level_domains(self):
        items = ["example.not"]
        result = pl_omit_invalid_top_level_domains(items, {"tld_list": ["COM"]})
        self.assertFalse(list(result))


class PipelineSortByReverseDomainNotationTest(TestCase):
    def test_pl_sort_by_rdn(self):
        domains = [
            "foo.bar.example.net",
            "bar.example.net",
            "example.net",
            "example.com",
            "bar.example.com",
            "foo.bar.example.com"
        ]
        result = pl_sort_by_rdn(domains, {})
        self.assertListEqual([
            "example.com",
            "bar.example.com",
            "foo.bar.example.com",
            "example.net",
            "bar.example.net",
            "foo.bar.example.net"
        ], list(result))


class PipelineOmitLongTokensTest(TestCase):
    """
    https://en.wikipedia.org/wiki/Hostname#Syntax
    """
    def test_when_subdomains_are_enabled(self):
        settings = MagicMock(origin="rpz.example.com", subdomains=True)
        domains = ("a" * i + ".example.net" for i in range(256))
        pl_options = {"max_token_length": max_token_length(settings)}

        result = list("*." + domain + ".rpz.example.com"
                      for domain in pl_omit_long_tokens(domains, pl_options))

        self.assertTrue(all(len(domain) <= 253 for domain in result))
        self.assertTrue(any(len(domain) == 253 for domain in result))

    def test_when_subdomains_are_disabled(self):
        settings = MagicMock(origin="rpz.example.com", subdomains=False)
        domains = ("a" * i + ".example.net" for i in range(256))
        pl_options = {"max_token_length": max_token_length(settings)}

        result = list(domain + ".rpz.example.com"
                      for domain in pl_omit_long_tokens(domains, pl_options))

        self.assertTrue(all(len(domain) <= 253 for domain in result))
        self.assertTrue(any(len(domain) == 253 for domain in result))


class PipelineTokenizeTest(TestCase):
    def test_simple(self):
        result = pl_tokenize(["example.com example.net example.org"], {})
        expected = ["example.com", "example.net", "example.org"]
        self.assertListEqual(expected, list(result))

    def test_multiple_spaces(self):
        result = pl_tokenize(["example.com  example.net  example.org"], {})
        expected = ["example.com", "example.net", "example.org"]
        self.assertListEqual(expected, list(result))

    def test_ignore_after_comment(self):
        result = pl_tokenize(["example.com  example.net  # example.org"], {})
        expected = ["example.com", "example.net"]
        self.assertListEqual(expected, list(result))

        result = pl_tokenize(["example.com  example.net  #example.org"], {})
        expected = ["example.com", "example.net"]
        self.assertListEqual(expected, list(result))


class PipelineCompositionTest(TestCase):
    def test_download_block_lists(self):
        pipeline = compose([
            pl_omit_wildcards,
            pl_omit_invalid_top_level_domains,
            pl_omit_ip_addresses,
            pl_tokenize,
            pl_omit_line_comments,
            pl_normalize
        ], {
            "tld_list": ["COM", "ORG", "NET"]
        })
        text = test_data["http://lists.example.com/example_list_one.txt"]
        result = pipeline(text.splitlines())
        expected = [
            "example.net",
            "foo.bar.example.net",
            "foo.example.net",
            "example.com"
        ]
        self.assertListEqual(expected, list(result))


@patch("rpz_manager.urlopen")
class IntegrationTests(TestCase):
    OK = HTTPStatus.OK
    NOT_MODIFIED = HTTPStatus.NOT_MODIFIED

    def setUp(self):
        self.cache_dir = Path(tempfile.mkdtemp())
        self.settings = MagicMock(
            debug_pipelines=[],
            tld_list_url="http://lists.example.com/example_list_tld.txt",
            block_list_urls=["http://lists.example.com/example_list_one.txt",
                             "http://lists.example.com/example_list_two.txt"])

    def tearDown(self):
        shutil.rmtree(self.cache_dir)

    @staticmethod
    def _side_effect(headers=None, code=200, changed=False):
        headers = headers or {}

        def _get_response(request):
            result = MagicMock()
            if code == 200:
                text = test_data[request.full_url]
                if changed and "tld" not in request.full_url:
                    text += os.linesep + "extra.example.com"
                result.__enter__.return_value.read.return_value = text.encode()
                result.__enter__.return_value.headers = headers
            else:
                error = HTTPError(request.full_url, code, "", headers, fp=None)
                result.__enter__.side_effect = error
            return result

        return _get_response

    def _download_lists_first(self, urlopen_mock):
        urlopen_mock.side_effect = self._side_effect(code=self.OK)
        download_block_lists(self.settings, self.cache_dir, disable_cache=False)
        paths = list(self.cache_dir.glob("*.list"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            self.assertLess(8, path.stat().st_size)
        return {path: path.stat().st_mtime for path in paths}

    def _assert_n_lists_unchanged(self, mtimes, unchanged):
        paths = list(self.cache_dir.glob("*.list"))
        self.assertEqual(len(paths), 3)
        actual_unchanged = 0
        for path in paths:
            self.assertLess(8, path.stat().st_size)
            if mtimes[path] == path.stat().st_mtime:
                actual_unchanged += 1
        self.assertEqual(unchanged, actual_unchanged)

    def test_download_lists_twice_sources_unchanged(self, urlopen_mock):
        mtimes = self._download_lists_first(urlopen_mock)

        urlopen_mock.side_effect = self._side_effect(code=self.NOT_MODIFIED)
        download_block_lists(self.settings, self.cache_dir, disable_cache=False)
        self._assert_n_lists_unchanged(mtimes, 3)

    def test_download_lists_twice_sources_with_changes(self, urlopen_mock):
        mtimes = self._download_lists_first(urlopen_mock)

        urlopen_mock.side_effect = self._side_effect(code=self.OK, changed=True)
        download_block_lists(self.settings, self.cache_dir, disable_cache=False)
        self._assert_n_lists_unchanged(mtimes, 1)  # only tld list unchanged

    def test_collect_domains(self, urlopen_mock):
        self.settings.subdomains = False
        self._download_lists_first(urlopen_mock)
        domains = collect_domains(self.settings, self.cache_dir)
        self.assertListEqual([
            "example.com",
            "example.net",
            "bar.example.net",
            "foo.bar.example.net",
            "foo.example.net"
        ], list(domains))
