/* physlock: options.c
 * Copyright (c) 2013 Bert Muennich <be.muennich at gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "options.h"

static options_t _options;
const options_t *options = (const options_t*) &_options;

void print_usage() {
	printf("usage: physlock [-defhLlsv] [-c command] [-u user]\n");
}

void print_version() {
	printf("physlock %s - lock all consoles\n", VERSION);
}

void parse_options(int argc, char **argv) {
	int opt;
	
	_options.detach = 0;
	_options.disable_sysrq = 0;
	_options.only_lock = 0;
	_options.only_unlock = 0;
	_options.crypt = 0;
	_options.fnek = 0;
	_options.cmd = NULL;
	_options.user = NULL;

	while ((opt = getopt(argc, argv, "defhLlsc:u:v")) != -1) {
		switch (opt) {
			case '?':
				print_usage();
				exit(1);
			case 'd':
				_options.detach = 1;
				break;
			case 'e':
				_options.crypt = 1;
				break;
			case 'f':
				_options.fnek = 1;
				break;
			case 'h':
				print_usage();
				exit(0);
			case 'L':
				_options.only_unlock = 1;
				break;
			case 'l':
				_options.only_lock = 1;
				break;
			case 's':
				_options.disable_sysrq = 1;
				break;
			case 'c':
				_options.cmd = optarg;
				break;
			case 'u':
				_options.user = optarg;
				break;
			case 'v':
				print_version();
				exit(0);
		}
	}
}
