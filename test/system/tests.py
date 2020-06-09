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

import logging
import os
import shutil
import socket
import subprocess
import unittest
import urllib.parse
from distutils.spawn import find_executable as find
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from subprocess import Popen
from tempfile import mkdtemp
from textwrap import dedent
from threading import Thread
from unittest import TestCase, TestSuite
from urllib.parse import urlparse

from test.test_data import test_data

logging.basicConfig(format="%(message)s")
logger = logging.getLogger(__name__)

test_data_by_path = {urlparse(url).path: text
                     for url, text in test_data.items()}

rpz_manager = find("rpz_manager.py") or find("rpz-manager")

cache_dir = os.getenv("CACHE_DIR", "/var/cache/rpz-manager")
named_user = os.getenv("NAMED_USER", "named")

test_origin = "rpz.example.com."


class LoggingRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info("%s - - [%s] %s" %
                    (self.address_string(),
                     self.log_date_time_string(),
                     format%args))


@unittest.skipUnless(rpz_manager, "rpz_manager not installed")
@unittest.skipUnless(find("named-checkzone"), "bind-utils not installed")
@unittest.skipUnless(find("named-compilezone"), "bind-utils not installed")
class FunctionalTestCase(TestCase):
    port = 8000

    serve_dir = None
    cache_dir = None
    named_dir = None

    example_list_tld = "http://localhost:8000/example_list_tld.txt"
    example_list_one = "http://localhost:8000/example_list_one.txt"
    example_list_two = "http://localhost:8000/example_list_two.txt"

    etc_rpz_manager_ini = Path("/etc/rpz-manager.ini")

    def setUp(self):
        self.serve_dir = self.serve_dir or Path(mkdtemp(prefix="functional"))
        self.cache_dir = self.cache_dir or Path(mkdtemp(prefix="functional"))
        self.named_dir = self.named_dir or Path(mkdtemp(prefix="functional"))

        self.zone_path = self.named_dir / (test_origin + "zone")

        os.chdir(self.serve_dir)

        handler = LoggingRequestHandler
        self._server = HTTPServer(("", self.port), handler)
        self._server_thread = Thread(target=self._server.serve_forever)
        self._server_thread.start()

        self.install_list(self.example_list_tld)
        self.install_list(self.example_list_one)
        self.install_list(self.example_list_two)

        if self.etc_rpz_manager_ini.exists():
            self.etc_rpz_manager_ini.unlink()

    def tearDown(self):
        self._server.shutdown()
        self._server_thread.join(timeout=2)
        self._server.server_close()

        if "functional" in str(self.serve_dir):
            shutil.rmtree(self.serve_dir)
        if "functional" in str(self.cache_dir):
            shutil.rmtree(self.cache_dir)
        if "functional" in str(self.named_dir):
            shutil.rmtree(self.named_dir)

    def install_list(self, url, update=None):
        path = urlparse(url).path
        text = test_data_by_path[path].strip()
        if update:
            text += os.linesep + update
        parts = urllib.parse.urlparse(url)
        with open(self.serve_dir / parts.path.lstrip("/"), "w") as file:
            file.write(text)

    def assert_zone_prelude(self, text):
        self.assertIn(test_origin, text)
        self.assertIn("SOA", text)
        self.assertIn("NS", text)
        self.assertIn("CNAME", text)


class T1CommandLineTests(FunctionalTestCase):
    def _run_rpz_manager(self, args, noise="--silent", origin=test_origin,
                         success=True):
        proc = subprocess.run([rpz_manager,
                               noise,
                               "-u", named_user,
                               "-g", named_user,
                               "-t", self.example_list_tld,
                               "-l", self.example_list_one,
                               "-l", self.example_list_two,
                               "--cache-dir", cache_dir,
                               "--origin", origin] + args,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)
        self.assertEqual(success, proc.returncode == 0)
        return proc

    def test_invalid_origin(self):
        self._run_rpz_manager(["--preview"], origin="rpz.example.com",
                              success=False)

    def test_preview(self):
        proc = self._run_rpz_manager(["--preview"])
        self.assert_zone_prelude(proc.stdout)
        self.assertIn("foo.example.net", proc.stdout)
        self.assertIn("bar.example.net", proc.stdout)

    def test_preview_after_update(self):
        proc = self._run_rpz_manager(["--preview"])
        self.assert_zone_prelude(proc.stdout)
        self.assertIn("foo.example.net", proc.stdout)
        self.assertIn("bar.example.net", proc.stdout)

        self.install_list(self.example_list_one, update="baz.example.net")
        proc = self._run_rpz_manager(["--preview"])
        self.assert_zone_prelude(proc.stdout)
        self.assertIn("foo.example.net", proc.stdout)
        self.assertIn("bar.example.net", proc.stdout)
        self.assertIn("baz.example.net", proc.stdout)

    def test_preview_with_block_subdomains(self):
        proc = self._run_rpz_manager(["--preview", "--subdomains"])
        self.assert_zone_prelude(proc.stdout)
        self.assertIn("example.net", proc.stdout)
        self.assertIn("*.example.net", proc.stdout)
        self.assertNotIn("foo.example.net", proc.stdout)

    def test_preview_with_custom_serial(self):
        proc = self._run_rpz_manager(["--preview", "--serial", "1337"])
        self.assert_zone_prelude(proc.stdout)
        self.assertIn("1337", proc.stdout)

    def test_output(self):
        self._run_rpz_manager(["-z", self.zone_path])
        with self.zone_path.open("r") as zone_file:
            self.assert_zone_prelude(zone_file.read())

    def test_output_in_raw_format(self):
        self._run_rpz_manager(["-z", self.zone_path, "-f", "raw"])

    def test_output_in_map_format(self):
        self._run_rpz_manager(["-z", self.zone_path, "-f", "map"])

    def test_silent(self):
        proc = self._run_rpz_manager(["-z", self.zone_path], noise="--silent")
        self.assertEqual("", proc.stdout)
        self.assertEqual("", proc.stderr)

    def test_verbose(self):
        proc = self._run_rpz_manager(["-z", self.zone_path], noise="--verbose")
        self.assertNotEqual("", proc.stderr)


def write_config(text, path):
    with path.open("w") as file:
        file.write(dedent(text.strip()))


class T2ConfigFileTests(FunctionalTestCase):
    def setUp(self):
        super().setUp()
        self.rpz_manager_ini = self.named_dir / "rpz-manager.ini"

    def _run_rpz_manager(self, success=True):
        proc = subprocess.run([rpz_manager,
                               "--verbose",
                               "--config", self.rpz_manager_ini],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)
        self.assertEqual(success, proc.returncode == 0)
        return proc

    def _install_config(self, format="text"):
        text = f"""
            [main]
            zone_file     = {self.zone_path}
            tld_list_url  = {self.example_list_tld}
            cache_dir     = {self.cache_dir}
            format        = {format}
            reload        = off
            zone_uid_name = {named_user}
            zone_gid_name = {named_user}
            
            [zone]
            origin        = {test_origin}
    
            [list]
            {self.example_list_one}
            {self.example_list_two}
        """
        write_config(text, self.rpz_manager_ini)

    def test_output(self):
        self._install_config()
        self._run_rpz_manager()
        with self.zone_path.open("r") as zone_file:
            self.assert_zone_prelude(zone_file.read())

    def test_output_in_raw_format(self):
        self._install_config()
        self._run_rpz_manager()

    def test_output_in_map_format(self):
        self._install_config()
        self._run_rpz_manager()


# noinspection PyMethodParameters
class T3AcceptanceTests(FunctionalTestCase):
    """
    Simulate a user setting up rpz_manager by first playing with the
    command line arguments, then installing a config file, and finally
    by testing name resolutions are actually blocked.
    """
    cache_dir = Path(os.getenv("CACHE_DIR", "/var/cache/rpz-manager"))
    named_dir = Path(os.getenv("NAMED_DIR", "/var/named"))

    resolv_conf = Path("/etc/resolv.conf")

    @classmethod
    def setUpClass(cls):
        cls.contents = cls.resolv_conf.read_text()
        cls.resolv_conf.write_text("nameserver 127.0.0.1")

    @classmethod
    def tearDownClass(cls):
        cls.resolv_conf.write_text(cls.contents)

    def _run_named(self):
        return Popen(["named", "-u", named_user, "-f"])

    def _run_rpz_manager(self, args=None, noise="--silent", success=True):
        proc = subprocess.run([rpz_manager, noise] + (args or []),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)
        self.assertEqual(success, proc.returncode == 0)
        return proc

    def _test_command_line_preview(self):
        proc = self._run_rpz_manager(["-t", self.example_list_tld,
                                      "-l", self.example_list_one,
                                      "-l", self.example_list_two,
                                      "--origin", test_origin,
                                      "--preview"])
        self.assertFalse(self.etc_rpz_manager_ini.exists())
        self.assert_zone_prelude(proc.stdout)
        self.assertIn("foo.example.net", proc.stdout)
        self.assertIn("bar.example.net", proc.stdout)

    def _test_command_line_output(self, args):
        proc = self._run_rpz_manager(["-t", self.example_list_tld,
                                      "-l", self.example_list_one,
                                      "-l", self.example_list_two,
                                      "--origin", test_origin] + args)
        with self.zone_path.open("r") as zone_file:
            self.assert_zone_prelude(zone_file.read())

    def _test_init_config(self):
        self._run_rpz_manager(["--init"])
        self.assertTrue(self.etc_rpz_manager_ini.exists())

    def _test_init_config_again(self):
        self._run_rpz_manager(["--init"], success=False)
        self.assertTrue(self.etc_rpz_manager_ini.exists())

    def _test_config_file_output(self):
        text = f"""
            [main]
            zone_file     = {self.zone_path}
            tld_list_url  = {self.example_list_tld}
            format        = text
            reload        = off
            zone_uid_name = {named_user}
            zone_gid_name = {named_user}

            [zone]
            origin        = {test_origin}

            [list]
            {self.example_list_one}
            {self.example_list_two}
        """
        write_config(text, self.etc_rpz_manager_ini)
        self._run_rpz_manager()

    def _test_reload(self):
        self._run_rpz_manager(["--reload"])

    def _test_resolve_nxdomain(self):
        with self.assertRaises(socket.gaierror):
            socket.gethostbyname("example.com")

    def test_cron_workflow(self):
        """
        The most common use case should be a user who downloads
        rpz-manager, plays with the command line flags, settles on a
        particular config file, then runs rpz-manager as root - Possibly
        as a cron job.
        """
        proc = None
        try:
            self._test_command_line_preview()
            self._test_command_line_output(["-z", self.zone_path,
                                            "-u", named_user,
                                            "-g", named_user])
            self._test_init_config()
            self._test_init_config_again()
            self._test_config_file_output()
            proc = self._run_named()
            self._test_reload()
            self._test_resolve_nxdomain()
        finally:
            if proc:
                proc.terminate()
                proc.wait(1)

    def test_user_workflow(self):
        """
        A user may want to run rpz-manager as an unprivileged user, so
        they may limit time spent as root. Or they may want to compile
        the zone on an Ansible master and copy the resulting zone file
        over.
        """
        user_zone_path = "/home/unprivileged/rpz.example.com.zone"
        user_cache_path = "/home/unprivileged"
        proc = None
        try:
            self._test_command_line_preview()
            self._test_command_line_output(["-z", user_zone_path,
                                            "-d", user_cache_path,
                                            "-u", "unprivileged",
                                            "-g", "unprivileged",
                                            "-m", "664"])
            # A zone file already exists with the correct permissions
            # from the previous test
            shutil.copy(user_zone_path, self.zone_path)
            proc = self._run_named()
            self._test_resolve_nxdomain()
        finally:
            if proc:
                proc.terminate()
                proc.wait(1)
