"""Run the web GUI:  python -m hipaa_analyzer.web  [--host H] [--port P]"""

import argparse

from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="hipaa-analyzer-web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app = create_app()
    print(f"HIPAA Policy Compliance Analyzer GUI: http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
