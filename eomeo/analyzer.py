import logging
from pathlib import Path
from binaryninja import *

from .pattern import cmdi

#
# Internals
#

_ELF_MAGIC_NUMBER = b"\x7fELF"


def _is_regular_file(path: Path):
    return path.is_file() and not path.is_symlink()


def _is_regular_dir(path: Path):
    return path.is_dir() and not path.is_symlink()


def _is_elf_file(path: Path):
    with open(path, "rb") as f:
        magic_nuber = f.read(4)
    if magic_nuber == _ELF_MAGIC_NUMBER:
        return True
    return False


def _is_regular_elf_file(path: Path):
    return _is_regular_file(path) and _is_elf_file(path)


def _bndb_path(path: Path):
    if path.suffix == ".bndb":
        return path
    return Path(str(path) + ".bndb")


def _analyze_bv_impl(bv: BinaryView):
    analyzer = cmdi.CommandInjectionAnalyzer(bv)
    analyzer.analyze()


#
# Public API
#


def analyze_file(target_file: Path):
    if _is_regular_file(target_file) and _is_elf_file(target_file):
        logging.info(f"[*] Trying analyzing {target_file}")
        bndb_file = _bndb_path(target_file)
        if bndb_file.exists():
            logging.info(
                f"[*] Found existing bndb file, analyzing this ... {bndb_file}"
            )
            with load(bndb_file) as bv:
                _analyze_bv_impl(bv)
                bv.save_auto_snapshot()
        else:
            with load(target_file) as bv:
                _analyze_bv_impl(bv)
                bv.create_database(bndb_file)

        logging.info(f"[*] Done analyzing {target_file}")


def analyze_dir(target_dir: Path):
    for target_file in target_dir.rglob("*"):
        if _is_regular_elf_file(target_file):
            analyze_file(target_file)
        else:
            logging.warn(f"[*] {target_file} seems not regular elf file")


def analyze(target_path_str: str):
    target_path = Path(target_path_str)

    if _is_regular_dir(target_path):
        analyze_dir(target_path)
    elif _is_regular_elf_file(target_path):
        analyze_file(target_path)
    else:
        logging.warn(f"[*] {target_path} seems not valid path")


def analyze_file_force(target_file: Path):
    if _is_regular_file(target_file) and _is_elf_file(target_file):
        logging.info(f"[*] Trying analyzing {target_file}")
        bndb_file = _bndb_path(target_file)
    if bndb_file.exists():
        logging.info(f"[*] Found existing bndb file, removing this ... {bndb_file}")
        bndb_file.unlink()

    with load(target_file) as bv:
        _analyze_bv_impl(bv)
        bv.create_database(bndb_file)

    logging.info(f"[*] Done analyzing {target_file}")


def analyze_force(target_path_str: str):
    target_path = Path(target_path_str)

    if _is_regular_dir(target_path):
        analyze_dir(target_path)
    elif _is_regular_elf_file(target_path):
        analyze_file_force(target_path)
    else:
        logging.warn(f"[*] {target_path} seems not valid path")
