#!/usr/bin/python3

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

import collections
import functools
import grp
import hashlib
import ipaddress
import logging
import logging.config
import os
import pwd
import shutil
import subprocess
import sys
import time
from argparse import ArgumentParser
from collections import namedtuple
from configparser import ConfigParser
from datetime import datetime, timezone
from distutils.spawn import find_executable
from email.utils import format_datetime
from filecmp import cmp as compare
from itertools import islice
from pathlib import Path
from subprocess import PIPE, STDOUT
from tempfile import NamedTemporaryFile
from textwrap import indent
from typing import List, Iterable
from urllib.error import HTTPError
from urllib.request import Request, urlopen

VERSION = "0.2"

logging.basicConfig(format="%(message)s")
logger = logging.getLogger("rpz-manager")
logger.setLevel(logging.INFO)

IANA_TLD_LIST = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

blurb = """
This program allows you to build and maintain RPZ zones from domain 
block list feeds. The resulting zones can be used with ISC bind (and 
other compatible DNS servers).
"""

default_pihole_adlists = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://mirror1.malwaredomains.com/files/justdomains",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"
]

default_template = """
$TTL 7720
$ORIGIN %(origin)s
@ IN SOA localhost. zone-admin.localhost. %(serial)s 3600 600 604800 1800
@ IN NS  localhost.
"""

default_config_file = f"""
[main]
cache_dir     = /var/cache/rpz-manager
disable_cache = off
zone_file     = /var/named/rpz.example.com.zone
zone_uid_name = root
zone_gid_name = named
zone_mode     = 664
format        = text
reload        = off

#
# Additionally block all subdomains.
# The zone will include two entries per domain. For example:
#
# example.com IN CNAME .
# *.example.com IN CNAME .
#
subdomains    = off

#
# A list of top level domains is required for validation purposes.
# IANA is preferred, though you may choose an alternate provider.
#
tld_list_url  = https://data.iana.org/TLD/tlds-alpha-by-domain.txt

#
# You may provide your own log config to customize message formats,
# destinations, levels, etc.
#
# See: https://docs.python.org/3/library/logging.config.html
#
# This log config is a great starting point:
# https://github.com/stevekroh/rpz-manager/blob/version-0.x/config/rpz-loggers.ini
#
#log_config    = /etc/rpz-loggers.ini

[zone]
origin        = rpz.example.com.

#
# You may provide your own zone template. Variables in the zone section 
# are available for interpolation. The template must be indented. Domain
# entries will be appended to this template. 
#
#template      = {indent(default_template.rstrip(), "#  ")}

#
# rpz-manager will fetch these urls on each run. If a url contains
# the `=` character, you must provide a unique key for the list item,
# such as:
#
#  list.0 = https://example.com/list.txt
#
[list]
{os.linesep.join("#" + item for item in default_pihole_adlists)}
"""


class CommandExitSuccess(Exception):
    """
    Raised to end execution early while indicating success.
    This is used to implement secondary workflows like --init.
    """
    pass


class CommandExitFailure(Exception):
    """
    Raised to end execution early while indicating failure.
    Any applicable error messages should be logged before raising this.
    """
    pass


class Settings:
    """
    The Settings class overlays a traditional python ArgumentParser on
    top of a traditional ConfigParser. Sources are consulted in order
    of precedence: program arguments first, then a config file if that
    exists, and finally the defaults provided here.

    This class will look for the config file at /etc/rpz-manager.ini by
    default. The user may specify an alternate config file with the
    --config flag. The config file uses multiple sections, described
    below.

    A setting may be required. In that case, the user must specify it
    in the config file or else on the command line. Some settings are
    sourced from the command line only. Others are sourced from the
    config file only.
    """
    main_section = "main"  # settings which apply globally
    zone_section = "zone"  # settings related to zone file contents
    list_section = "list"  # each item in this section is a block list

    make_available_for_interpolation = ["origin", "serial"]

    octal = functools.partial(int, base=8)

    def __init__(self):
        """
        Create the ArgumentParser, ConfigParser, and related metadata.

        The ConfigParser is passed allow_no_value=True so that block
        lists may be provided under the list section without a key.
        This looks cleaner, but only works if your block lists do
        not contain the `=` character.

        Each setting in `ensure` is retrieved then saved back to the
        cfg_parser. This ensures all relevant settings are available
        for interpolation when the zone template is retrieved.

        :param ensure: a list of settings to save back to cfg_parser
        """
        self.metadata = {}  # built up with each call to add_setting
        self.timestamp = time.time()
        self.arg_parser = ArgumentParser(description=blurb)
        self.cfg_parser = ConfigParser(allow_no_value=True, delimiters=("=",))
        self.cfg_parser.optionxform = str
        self.cfg_parser.add_section(self.main_section)
        self.cfg_parser.add_section(self.zone_section)
        self.cfg_parser.add_section(self.list_section)
        self.catalog()
        self.args = self.arg_parser.parse_args()
        if self.args.config_path.is_file():
            self.cfg_parser.read(self.args.config_path)
        for dest in self.make_available_for_interpolation:
            meta = self.metadata[dest]
            value = self.get_setting(dest)
            self.cfg_parser.set(meta.section, dest,
                                None if value is None else str(value))

    def __getattr__(self, item):
        return self.get_setting(item)

    def catalog(self):
        self.add_setting("--init", dest="init", type=bool, default=False,
                         help="write the default config file",
                         action="store_true")
        self.add_setting("-c", "--config", dest="config_path", type=Path,
                         default="/etc/rpz-manager.ini",
                         help="config file path")
        self.add_setting("--log-config", dest="log_config", type=Path,
                         default="/etc/rpz-loggers.ini",
                         section=self.main_section)
        self.add_setting("-v", "--verbose", dest="verbose", type=bool,
                         default=False, action="store_true",
                         help="log all messages")
        self.add_setting("-s", "--silent", dest="silent", type=bool,
                         default=False, action="store_true",
                         help="do not log any messages")
        self.add_setting("-G", "--debug-pipeline", dest="debug_pipelines",
                         type=list, default=[], action="append")
        self.add_setting("-p", "--preview", dest="preview", type=bool,
                         default=False, action="store_true",
                         help="preview a portion of the zone")
        self.add_setting("-d", "--cache-dir", dest="cache_dir", type=Path,
                         default="/var/cache/rpz-manager",
                         section=self.main_section)
        self.add_setting("-D", "--disable-cache", dest="disable_cache",
                         type=bool, default=False, action="store_true",
                         help="always download and process lists",
                         section=self.main_section)
        self.add_setting("-t", "--tld-list-url", dest="tld_list_url", type=str,
                         default=IANA_TLD_LIST,
                         help="specify a provider of top level domains",
                         section=self.main_section)
        self.add_setting("-l", "--block-list-url", dest="block_list_urls",
                         type=list, action="append", default=[],
                         help="specify a domain block list provider",
                         section=self.list_section)
        self.add_setting("--serial", dest="serial", type=int,
                         default=int(self.timestamp),
                         help="specify your own preferred zone serial",
                         section=self.zone_section)
        self.add_setting("--subdomains", dest="subdomains",
                         type=bool, default=False, action="store_true",
                         help="additionally block all subdomains",
                         section=self.main_section)
        self.add_setting("-z", "--zone-file", dest="zone_file", type=Path,
                         default=None,
                         help="write the zone file to this location",
                         section=self.main_section)
        self.add_setting("-u", "--zone-uid-name", dest="zone_uid_name",
                         type=str, default="root",
                         help="owner of the zone file to be written",
                         section=self.main_section)
        self.add_setting("-g", "--zone-gid-name", dest="zone_gid_name",
                         type=str, default="named",
                         help="group of the zone file to be written",
                         section=self.main_section)
        self.add_setting("-m", "--zone-mode", dest="zone_mode", type=self.octal,
                         default=self.octal("664"),
                         help="mode of the zone file to be written")
        self.add_setting("-r", "--reload", dest="reload", type=bool,
                         default=False, action="store_true",
                         help="reload the zone automatically (requires rndc)",
                         section=self.main_section)
        self.add_setting("-f", "--format", dest="format", type=str,
                         choices=("text", "raw", "map"), default="text",
                         help="specify a zone format",
                         section=self.main_section)
        self.add_setting("-o", "--origin", dest="origin", type=str,
                         default=None,
                         help="specify a zone origin",
                         section=self.zone_section)
        self.add_setting(dest="template", type=str, default=default_template,
                         section=self.zone_section)

    Metadata = namedtuple("metadata", ["type", "section", "required"])

    def add_setting(self, *args, dest=None, section=None, required=False,
                    **kwargs):
        """
        Prepare arg_parser and cfg_parser to accommodate a new setting.

        If section= is provided, the config file will be consulted. The
        setting will be looked up under that section. If flag arguments
        are not provided, only the config file will be consulted.

        If both the program arguments and the config file should be
        consulted for this setting, we store the setting default in
        cfg_parser. Otherwise we store the default in arg_parser.

        action= and type= are incompatible. If both are present, omit
        type from the call to arg_parser.add_argument().

        The default value of block_list_urls is set by converting that
        list to a dictionary. The whole dictionary is stored under the
        list section.
        """
        type = kwargs["type"]
        self.metadata[dest] = self.Metadata(type, section, required)
        if "action" in kwargs:
            kwargs.pop("type")

        default = kwargs.pop("default")

        if args and section:
            self.arg_parser.add_argument(*args, dest=dest, default=None,
                                         **kwargs)
        elif args:
            self.arg_parser.add_argument(*args, dest=dest, default=default,
                                         **kwargs)

        if section and type == list:
            self.cfg_parser[section] = {hash(it): it for it in default}
        elif section and default is None:
            self.cfg_parser[section][dest] = None
        elif section:
            self.cfg_parser[section][dest] = str(default)

    def get_setting(self, item):
        """
        Get the setting value by consulting sources in order of
        precedence: program arguments, then config file, then program
        defaults.

        If there is a value in the program arguments, use that. Then
        handle special cases (lists and required settings). Finally
        retrieve a value from the config file and ensure that value is
        of the correct type.
        """
        if item not in self.metadata:
            raise CommandExitFailure

        type, section, required = self.metadata[item]

        if getattr(self.args, item, None) is not None:
            return getattr(self.args, item)
        elif type == list:
            return [v or k for k, v in self.cfg_parser.items(section)]
        elif required and not self.cfg_parser.has_option(section, item):
            raise CommandExitFailure

        try:
            value = self.cfg_parser[section].get(item)
        except TypeError as ex:
            logger.exception("could not interpolate %s", item)
            raise CommandExitFailure from ex

        if value is None and required:
            logger.error("you must specify %s", item)
            raise CommandExitFailure(item)
        if value is None:
            return value
        elif type == bool:
            return self.cfg_parser[section].getboolean(item)
        elif type == int:
            return self.cfg_parser[section].getint(item)
        else:
            return type(value)


def reverse_domain_notation(domain: str) -> List[str]:
    parts = domain.split(".")
    parts.reverse()
    return parts


#
# Pipeline Functions
#


def pipeline_debugger(pipeline, debug_pipelines):
    """
    Each `-G <pipeline>` logs all items yielded by that pipeline
    """
    pipeline_name = pipeline.__name__
    if pipeline_name in debug_pipelines:
        pl_logger = logging.getLogger("rpz-manager.pipeline." + pipeline_name)
        pl_logger.setLevel(logging.DEBUG)

        def wrapper(*args, **kwargs):
            for item in pipeline(*args, **kwargs):
                pl_logger.debug(item)
                yield item

        return wrapper
    else:
        return pipeline


def compose(functions, debug_pipelines):
    functions = [pipeline_debugger(fn, debug_pipelines) for fn in functions]

    def compose2(f, g):
        return lambda x: f(g(x))
    return functools.reduce(compose2, functions, lambda x: x)


def pl_normalize(lines):
    for line in lines:
        yield line.strip()


def pl_omit_line_comments(lines):
    for line in lines:
        if not line.startswith("#"):
            yield line


def pl_tokenize(lines):
    for line in lines:
        for token in line.split():
            if not token:
                continue
            elif token.startswith("#"):
                break
            else:
                yield token


def pl_omit_ip_addresses(tokens):
    for token in tokens:
        try:
            ipaddress.ip_address(token)
        except ValueError:
            yield token


def pl_omit_invalid_top_level_domains(tld_list):
    def pipeline(tokens):
        for token in tokens:
            tld = reverse_domain_notation(token)[0]
            if tld.upper() in tld_list:
                yield token
    return pipeline


def pl_omit_wildcards(tokens):
    for token in tokens:
        if not token.startswith("*"):
            yield token


class WindowToken:
    def __init__(self, token, do_yield):
        self.token = token
        self.do_yield = do_yield
        self.rdn = reverse_domain_notation(token)

    def subdomain_of(self, that):
        if len(self.rdn) > len(that.rdn):
            return self.rdn[:len(that.rdn)] == that.rdn
        return False


def pl_collapse_subdomains(window_length=4):
    """
    When a subdomain and its parent domain are both included in a list,
    keep only the parent domain. This pipeline is used with --subdomains
    as there is no point blocking *.example.com and *.www.example.com.

    A sliding window is used for efficiency.
    """
    def pipeline(tokens):
        window = collections.deque()
        for this_token in tokens:
            this = WindowToken(this_token, do_yield=True)
            for that in window:
                # example.com
                # example.com
                if this.token == that.token:
                    that.do_yield = False
                # example.com
                # www.example.com
                elif this.subdomain_of(that):
                    this.do_yield = False
                # www.example.com
                # google.com
                elif that.subdomain_of(this):
                    that.do_yield = False
            window.append(this)
            if len(window) > window_length:
                item = window.popleft()
                if item.do_yield:
                    yield item.token
        for item in window:  # flush window
            if item.do_yield:
                yield item.token
    return pipeline


def pl_omit_long_tokens(max_token_length=200):
    """
    Omit tokens longer than max_token_length characters.
    See derive_max_token_length() for details.
    """
    def pipeline(tokens):
        for token in tokens:
            if len(token) <= max_token_length:
                yield token
    return pipeline


def pl_omit_xn_top_level_domains(tokens):
    """
    Omit internationalized top level domains until we can handle them.
    TODO: handle internationalized top level domains
    """
    for token in tokens:
        if not token.startswith("XN--"):
            yield token


def pl_to_uppercase(tokens):
    for token in tokens:
        yield token.upper()


def pl_sort_by_rdn(tokens):
    return sorted(tokens, key=reverse_domain_notation)


def pl_block_subdomains(tokens):
    """
    For each domain, block all of its subdomains.
    """
    for token in tokens:
        yield token
        yield "*." + token


#
# List Management
#


def get_lines(text):
    """
    Yield non-empty lines from a blob of text.
    """
    for line in text.splitlines():
        if line:
            yield line


def _get_cache_path(url, cache_dir: Path) -> Path:
    h = hashlib.md5(url.encode())
    return cache_dir / (h.hexdigest() + ".list")


def get_list(cache_dir, list_url) -> List[str]:
    """
    Get a list from the cache on disk.
    """
    result = []
    cache_path = _get_cache_path(list_url, cache_dir)
    if cache_path.is_file():
        with cache_path.open("r") as cache_file:
            for line in get_lines(cache_file.read()):
                result.append(line)
    return result


modi, modl = "If-Modified-Since", "Last-Modified"


def _create_request(cache_path, disable_cache, list_url):
    req_headers = {}
    if cache_path.is_file() and not disable_cache:
        stat = cache_path.stat()
        dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        req_headers[modi] = format_datetime(dt, usegmt=True)
    logger.info("requesting %s", list_url)
    req = Request(list_url, headers=req_headers)
    return req, req_headers


def _handle_response(cache_path, pipeline, req_headers, res, temp_file):
    body = res.read()
    items = pipeline(get_lines(body.decode()))
    for item in items:
        temp_file.write(item + os.linesep)
    temp_file.flush()

    if cache_path.is_file() and compare(temp_file.name, cache_path):
        logger.debug(modi + ": %s", req_headers.get(modi, "N/A"))
        logger.debug(modl + ": %s", res.headers.get(modl, "N/A"))
        verb = "unmodified"
    elif cache_path.is_file():
        shutil.copyfile(temp_file.name, cache_path)
        verb = "updated"
    else:
        shutil.copyfile(temp_file.name, cache_path)
        verb = "created"
    logger.info("%s %s", cache_path, verb)


def download_lists(pipeline, cache_dir, disable_cache, *list_urls):
    """
    Request each url, pass each response through the specified pipeline,
    then save each result to the cache.

    Does not write anything to the cache if we get 304 NOT MODIFIED.
    Does not trust a 200 response. Results are always compared against
    current cache contents before updating the cache. (Some servers are
    not configured to handle the 'If-Modified-Since' header).

    NOTE: this function is used to download the tld list from IANA in
    addition to to user specified block lists.
    """
    for list_url in list_urls:
        cache_path = _get_cache_path(list_url, cache_dir)

        req, req_headers = _create_request(cache_path, disable_cache, list_url)

        try:
            with urlopen(req) as res, NamedTemporaryFile("w") as temp_file:
                _handle_response(cache_path, pipeline, req_headers, res,
                                 temp_file)
        except HTTPError:
            pass


def download_block_lists(settings, cache_dir, disable_cache):
    """
    Download all block lists to the cache after configuring pipelines
    and their dependencies.

    The pipelines used here are not expected to change behavior when
    different settings are applied. Therefore it is safe to cache the
    pipeline result.
    """
    pipeline = compose([
        pl_to_uppercase,
        pl_omit_xn_top_level_domains,
        pl_normalize
    ], settings.debug_pipelines)
    download_lists(pipeline, cache_dir, disable_cache,
                   settings.tld_list_url)

    tld_list = get_list(cache_dir, settings.tld_list_url)

    pipeline = compose([
        pl_omit_wildcards,
        pl_omit_invalid_top_level_domains(tld_list),
        pl_omit_ip_addresses,
        pl_tokenize,
        pl_omit_line_comments,
        pl_normalize
    ], settings.debug_pipelines)
    download_lists(pipeline, cache_dir, disable_cache,
                   *settings.block_list_urls)


# https://en.wikipedia.org/wiki/Hostname#Syntax
# https://devblogs.microsoft.com/oldnewthing/?p=7873
ASCII_DNS_NAME_MAX_LENGTH = 253


def derive_max_token_length(settings):
    """
    Determine the max length of tokens we can accommodate.

    Consider each resource record concatenates a token with the zone
    origin and other text. The combination cannot exceed 253 characters
    ignoring the root label (trailing dot).

    TODO: account for other encodings
    """
    result = ASCII_DNS_NAME_MAX_LENGTH
    result -= len("." + settings.origin.rstrip("."))
    result -= len("*.") * settings.subdomains
    logger.debug("max_token_length: %s", result)
    return result


def collect_domains(settings, cache_dir):
    """
    Read all domains from the specified block lists into memory.

    Domains are deduplicated and passed through a processing pipeline.
    """
    domains = set()
    count = 0
    for url in settings.block_list_urls:
        logger.info("collecting %s", url)
        for item in get_list(cache_dir, url):
            count += 1
            domains.add(item)
    if count > len(domains):
        logger.debug("removed %d duplicates", count - len(domains))
    num_lists = len(settings.block_list_urls)
    logger.info("obtained %d domains from %d %s",
                len(domains), num_lists, "list" if num_lists == 1 else "lists")

    max_token_length = derive_max_token_length(settings)
    window_length = 4

    pipeline = compose([
        pl_block_subdomains,
        pl_collapse_subdomains(window_length),
        pl_omit_long_tokens(max_token_length),
        pl_sort_by_rdn
    ] if settings.subdomains else [
        pl_omit_long_tokens(max_token_length),
        pl_sort_by_rdn
    ], settings.debug_pipelines)
    return pipeline(domains)


#
# Zone Management
#


Zone = Iterable[str]


def generate_rpz_zone(domains, template) -> Zone:
    """
    Generate component lines of the RPZ zone file.
    """
    yield template.strip() + os.linesep
    for domain in domains:
        yield domain + " IN CNAME ." + os.linesep


def _get_command(command_name):
    command = find_executable(command_name)
    if command is None:
        logger.error("could not find %s", command_name)
        raise CommandExitFailure
    return command


def _run_command(command_list):
    proc = subprocess.run(command_list, stdout=PIPE, stderr=STDOUT,
                          universal_newlines=True)
    for line in get_lines(proc.stdout):
        logger.debug(line.rstrip())
    if proc.returncode != 0:
        logger.error("%s failed", command_list[0])
        raise CommandExitFailure


def write_zone_preview(zone: Zone):
    """
    Write the first few lines of the zone to stdout.
    """
    for line in islice(zone, 10):
        sys.stdout.write(line)


def _run_command_on_staged_zone(zone, zone_path, command_list, copy=False):
    """
    Write the zone to a temporary file, then run our command on it.

    named-compilezone will write its output to the final location.
    named-checkzone does not, so the temporary file must be copied to
    the final location.
    """
    with NamedTemporaryFile("w", prefix="zone") as zone_file:
        for line in zone:
            zone_file.write(line)
        zone_file.flush()
        _run_command(command_list + [zone_file.name])
        if copy:
            shutil.copy(zone_file.name, zone_path)


def write_zone(settings, zone: Zone, zone_name, zone_path):
    """
    Verify and write the entire zone to disk, with an optional
    compilation step.

    The zone file owner, group, and mode are set based on program
    settings.
    """
    format = settings.format
    if zone_path is not None and format == "text":
        command_list = [_get_command("named-checkzone"),
                        zone_name]
        logger.info("writing %s", zone_path)
        _run_command_on_staged_zone(zone, zone_path, command_list, copy=True)
    elif zone_path is not None:
        command_list = [_get_command("named-compilezone"),
                        "-F", format,
                        "-o", zone_path,
                        zone_name]
        logger.info("compiling %s", zone_path)
        _run_command_on_staged_zone(zone, zone_path, command_list)
    os.chmod(zone_path, settings.zone_mode)
    os.chown(zone_path,
             pwd.getpwnam(settings.zone_uid_name).pw_uid,
             grp.getgrnam(settings.zone_gid_name).gr_gid)


def reload_zone(settings, zone_path, zone_name):
    if zone_path is not None and settings.reload:
        rndc = _get_command("rndc")
        _run_command([rndc, "reload", zone_name])


#
# Main Procedure and Helpers
#


def _ensure_cache_dir(cache_dir):
    try:
        cache_dir.mkdir(parents=False, exist_ok=True)
    except (FileNotFoundError, OSError) as ex:
        logger.exception("cache_dir %s does not exist or could not be created",
                         cache_dir)
        raise CommandExitFailure from ex


def _setup_config_file(settings):
    if settings.init and settings.config_path.is_file():
        logger.error("%s already exists", settings.config_path)
        raise CommandExitFailure
    elif settings.init:
        logger.info("writing %s", settings.config_path)
        with settings.config_path.open("w") as config_file:
            config_file.write(default_config_file.lstrip())
        raise CommandExitSuccess


def _setup_logging(settings):
    if settings.log_config.is_file():
        logging.config.fileConfig(settings.log_config)
    elif settings.verbose:
        logger.setLevel(logging.DEBUG)
    elif settings.silent:
        logger.setLevel(logging.ERROR)


def _validate_origin(settings):
    if settings.origin is None:
        logger.error("you must specify an origin")
        raise CommandExitFailure
    if not settings.origin.endswith("."):
        logger.error("origin must end with a trailing dot")
        raise CommandExitFailure


def _act_on_domains(settings, domains):
    zone_path, zone_name = settings.zone_file, settings.origin
    zone_text = generate_rpz_zone(domains, settings.template)

    preview = settings.preview or (zone_path is None)

    if preview:
        logger.info("preview mode, specify --zone-file to write zone")
        write_zone_preview(zone_text)
    else:
        write_zone(settings, zone_text, zone_name, zone_path)
        reload_zone(settings, zone_path, zone_name)
        logger.info("complete")


def exit_code_wrapper(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
            return os.EX_OK
        except CommandExitSuccess:
            return os.EX_OK
        except CommandExitFailure:
            return os.EX_SOFTWARE
    return wrapper


@exit_code_wrapper
def main():
    """
    Download block lists then generate an RPZ zone file.

    Each step assumes it will succeed. Error checking and validation is
    lazy. Exceptions will be raised as something goes wrong.
    """
    settings = Settings()

    _setup_config_file(settings)
    _setup_logging(settings)

    _validate_origin(settings)

    _ensure_cache_dir(settings.cache_dir)

    disable_cache = settings.disable_cache or len(settings.debug_pipelines) > 0

    download_block_lists(settings, settings.cache_dir, disable_cache)
    domains = collect_domains(settings, settings.cache_dir)

    _act_on_domains(settings, domains)


if __name__ == "__main__":
    sys.exit(main())
