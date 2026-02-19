#!/bin/sh
set -eu

exec cargo watch -x "run --locked -p less-sync-server"
