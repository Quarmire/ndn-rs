#!/usr/bin/env bash
# Low-memory bring-up for the G.06 AutoConfig live witness.
#
# This intentionally builds one heavy image at a time. The default compose
# `up -d --build interop ndn-fwd nfd yanfd` can ask Docker Desktop to compile
# Rust, ndn-cxx, NFD tools, and PSync at once, which is prone to OOM on small
# Docker VM memory limits.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

export COMPOSE_PARALLEL_LIMIT="${COMPOSE_PARALLEL_LIMIT:-1}"
export NDN_TESTBED_BUILD_JOBS="${NDN_TESTBED_BUILD_JOBS:-2}"

COMPOSE=(docker compose -f testbed/docker-compose.yml)

echo "==> Pulling reference runtime images"
"${COMPOSE[@]}" pull nfd yanfd

echo "==> Building ndn-fwd with NDN_TESTBED_BUILD_JOBS=${NDN_TESTBED_BUILD_JOBS}"
"${COMPOSE[@]}" build ndn-fwd

echo "==> Building interop with NDN_TESTBED_BUILD_JOBS=${NDN_TESTBED_BUILD_JOBS}"
"${COMPOSE[@]}" build interop

echo "==> Starting G.06 services without rebuilding"
"${COMPOSE[@]}" up -d --no-build nfd yanfd ndn-fwd
"${COMPOSE[@]}" up -d --no-build interop

"${COMPOSE[@]}" ps
