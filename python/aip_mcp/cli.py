# python/aip_mcp/cli.py
"""CLI entry point for the AIP MCP auth proxy."""

from __future__ import annotations

import argparse
import logging
import sys

from aip_mcp.config import ProxyConfig
from aip_mcp.proxy import AipProxy


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="aip-proxy",
        description="AIP MCP Auth Proxy -- drop-in authentication for any MCP server",
    )
    parser.add_argument(
        "--upstream", default="http://localhost:3000",
        help="Upstream MCP server URL (default: http://localhost:3000)",
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Port to listen on (default: 8080)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--trust-key", action="append", dest="trust_keys", default=[],
        help="Trusted public key (multibase, repeatable)",
    )
    parser.add_argument(
        "--config", dest="config_file",
        help="Path to TOML config file",
    )
    parser.add_argument(
        "--log-file",
        help="Path to audit log file (default: stderr)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose logging",
    )

    args = parser.parse_args(argv)

    # Set up logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    # Load config: file first, then CLI overrides
    if args.config_file:
        config = ProxyConfig.from_toml(args.config_file)
    else:
        config = ProxyConfig()

    # CLI args override config file
    if args.upstream != "http://localhost:3000":
        config.upstream = args.upstream
    if args.port != 8080:
        config.port = args.port
    if args.host != "127.0.0.1":
        config.host = args.host
    if args.trust_keys:
        config.trust_keys = args.trust_keys
    if args.log_file:
        config.log_file = args.log_file

    if not config.trust_keys:
        print("Error: at least one --trust-key is required", file=sys.stderr)
        sys.exit(1)

    proxy = AipProxy(config)
    proxy.serve_forever()


if __name__ == "__main__":
    main()
