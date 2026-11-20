"""Create the two hub identities for docker-compose.federation.yml and write deploy/.env.

    python deploy/init_federation.py [--force]

Keys are created on this machine, in deploy/keys/<hub>/identities/hub.key (mode 0600),
and mounted into the containers. They are never part of the image. deploy/keys and
deploy/.env must stay out of version control (see deploy/.gitignore).
"""

import argparse
import os
import sys
from pathlib import Path

from franscor.identity import Identity

HERE = Path(__file__).resolve().parent
HUBS = ("eu", "us")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="rewrite .env even if it exists")
    args = parser.parse_args()
    env_path = HERE / ".env"
    if env_path.exists() and not args.force:
        print(f"{env_path} exists; use --force to rewrite it", file=sys.stderr)
        return 1
    lines = []
    for hub in HUBS:
        home = HERE / "keys" / hub
        ident = Identity.load_or_create("hub", home)
        # The container runs as uid 10001; let it read its own key directory.
        if hasattr(os, "chown"):
            try:
                os.chown(home, 10001, 10001)
                for p in home.rglob("*"):
                    os.chown(p, 10001, 10001)
            except PermissionError:
                print(f"note: run `sudo chown -R 10001:10001 {home}` before starting the containers",
                      file=sys.stderr)
        lines.append(f"HUB_{hub.upper()}_ID={ident.agent_id}")
        print(f"hub-{hub}: {ident.agent_id}")
    env_path.write_bytes(("\n".join(lines) + "\n").encode("ascii"))
    print(f"wrote {env_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
