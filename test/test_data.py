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

from textwrap import dedent

test_data = {
    "http://lists.example.com/example_list_tld.txt": dedent(
        """
        COM
        ORG
        NET
        """
    ),
    "http://lists.example.com/example_list_one.txt": dedent(
        """
        # Example List One
        127.0.0.1   localhost
        127.0.0.1
        0.0.0.0     example.net  # Example domain
        0.0.0.0     example.bad
        0.0.0.0     foo.bar.example.net
        0.0.0.0     foo.example.net
        0.0.0.0     example.com
        """
    ),
    "http://lists.example.com/example_list_two.txt": dedent(
        """
        # Example List Two
        example.net
        bar.example.net
        example.com
        example.bad
        *.example.org
        *.foo.example.org
        """
    )
}
