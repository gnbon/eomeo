import argparse
import logging
from pathlib import Path

from . import analyzer

logging.basicConfig(level=logging.DEBUG)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filename")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.filename:
        target_file = Path(args.filename)
        analyzer.analyze_file(target_file)
    else:
        target_dir = Path(".")
        analyzer.analyze_dir(target_dir)


if __name__ == "__main__":
    main()
