import logging
from binaryninja import *
from binaryninja import BinaryView
from binaryninja.log import log_warn


class CommandInjectionAnalyzer:
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.target_func = []
        self.count = 0
        self.tag_name = "Suspicious(Command Injection)"
        self.tag_icon = "🧐"
        self._make_tag()

    def _add_funcion(self, func_name: str):
        system_symbol = self.bv.get_symbol_by_raw_name(func_name)
        if system_symbol:
            self.target_func.append(system_symbol.address)
        else:
            logging.info(
                f"Could not find '{func_name}' symbol in the {self.bv.file.filename}."
            )

    def _make_tag(self):
        suspicious_tag = self.bv.get_tag_type(self.tag_name)
        if not suspicious_tag:
            logging.info(f"Make a new Tag Type {self.tag_icon} {self.tag_name}")
            self.bv.create_tag_type(self.tag_name, self.tag_icon)

    def _add_tag(self, func, address: int):
        # check if tag exists
        tags = self.bv.get_tags()
        for tag in tags:
            if address == tag[0]:
                logging.info("Current address already analyzed")
                return

        self.bv.add_tag(
            address, self.tag_name, f"Suspicious(Command Injection) #{self.count:05d}"
        )
        self.count += 1

    def analyze(self):
        self._make_tag()

        self._add_funcion("system")
        self._add_funcion("popen")

        for func in self.target_func:
            for xref in self.bv.get_code_refs(func):
                func = xref.function
                llil_index = func.llil.get_instruction_start(xref.address)
                if not llil_index:
                    continue
                mlil_index = func.llil.get_medium_level_il_instruction_index(llil_index)
                if not mlil_index:
                    continue
                mlil_insn = func.mlil[mlil_index]
                if not mlil_insn:
                    continue

                if mlil_insn.operation != MediumLevelILOperation.MLIL_CALL:
                    logging.info(f"{hex(xref.address)} is not function call")
                    continue

                call_param = mlil_insn.params[0]

                if call_param.operation == MediumLevelILOperation.MLIL_VAR:
                    current_function = mlil_insn.function.source_function
                    self._add_tag(current_function, mlil_insn.address)
                    logging.info(f"{hex(xref.address)}->system({call_param})")
