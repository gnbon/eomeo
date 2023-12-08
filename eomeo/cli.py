import argparse
import logging
from pathlib import Path

from . import analyzer

logging.basicConfig(level=logging.DEBUG)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("path", default=".")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.path:
        analyzer.analyze(args.path)


if __name__ == "__main__":
    main()
