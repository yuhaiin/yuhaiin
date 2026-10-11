#!/bin/sh
set -eu

ocserv --foreground --config=/etc/ocserv/ocserv.conf --debug=2
