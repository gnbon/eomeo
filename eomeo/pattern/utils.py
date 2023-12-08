from binaryninja import *
import logging

TAG_NAME = "Suspicious"
TAG_EMOJI = "🧐"

def make_tag(bv: BinaryView, tag_name, tag_emoji):
    suspicious_tag = bv.get_tag_type(tag_name)
    if not suspicious_tag:
        logging.info(f"Make a new Tag Type {tag_emoji} {tag_name}")
        bv.create_tag_type(tag_name, tag_emoji)
