import logging
from binaryninja import *
from binaryninja import BinaryView
from binaryninja.log import log_warn

from . import utils


def system_on_variable(bv: BinaryView):
    utils.make_tag(bv, utils.TAG_NAME, utils.TAG_EMOJI)
    func = bv.get_functions_by_name("system")[0]

    for xref in bv.get_code_refs(func.start):
        logging.info(xref.mlilfasdfasdf)
        mlil = xref.mlil

        if not isinstance(mlil, mediumlevelil.MediumLevelILCall):
            logging.info(f"{hex(xref.address)} is not function call")
            continue

        logging.info(f"{hex(xref.address)}: {mlil}")
        target_param = mlil.params[0]

        if isinstance(target_param, mediumlevelil.MediumLevelILVar):
            current_function.add_tag(
                TAG_NAME, "Command Injection(Possible)", xref.address
            )
            logging.info(f"{hex(xref.address)}->{target_param}")
