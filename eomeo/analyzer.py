import logging
from pathlib import Path
from binaryninja import load

from .pattern import cmdi

#
# Internals
#

_ELF_MAGIC_NUMBER = b"\x7fELF"


def is_regular_file(path: Path):
    return path.is_file() and not path.is_symlink()


def is_elf_file(path: Path):
    with open(path, "rb") as f:
        magic_nuber = f.read(4)
    if magic_nuber == _ELF_MAGIC_NUMBER:
        return True
    return False


#
# Public API
#


def analyze_file(target_file: Path):
    try:
        logging.info(f"[*] Trying analyzing {target_file}")
        # check existing bndb
        # -> if exist, -f option will force file analyze
        bv = load(target_file)
        cmdi.system_on_variable(bv)
        bv.create_database(f"{bv.file.filename}.bndb")  # TODO: multithread scan
        logging.info(f"[*] Done analyzing {target_file}")

    except Exception as e:
        logging.info(f"[-] Error analyzing {target_file}: {e}")


def analyze_dir(target_dir: Path):
    for target_file in target_dir.rglob("*"):
        if is_regular_file(target_file) and is_elf_file(target_file):
            analyze_file(target_file)
