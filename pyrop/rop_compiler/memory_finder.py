import logging, collections
import classifier as cl, gadget as ga, finder, factories, utils

class MemoryFinder(finder.Finder):
    """This class parses a file to obtain any gadgets inside their executable sections"""

    def __init__(self, name, arch, base_address = 0, level = logging.WARNING, parser_type = None):
        super(MemoryFinder, self).__init__(name, arch, base_address, level)
        self.parser = factories.get_parser_from_name(parser_type)(name, base_address, level)

    def find_gadgets(self, validate = False, bad_bytes = None):
        """Finds gadgets in the specified file"""
        gadget_list = ga.GadgetList(log_level = self.level, bad_bytes = bad_bytes)
        for segment in self.parser.iter_executable_segments():
            self.get_gadgets_for_segment(segment, gadget_list, validate, bad_bytes)
        self.logger.debug("Found %d gadgets in %s", len([x for x in gadget_list.foreach()]), self.name)
        return gadget_list

    def get_gadgets_for_segment(self, segment, gadget_list, validate, bad_bytes):
        """Iteratively step through an executable section looking for gadgets at each address"""
        data, seg_address = self.parser.get_segment_bytes_address(segment)
        if self.base_address == 0 and seg_address == 0:
            self.logger.warning("No base address given for library or PIE executable.    Addresses may be wrong")

        startVA = self.base_address + seg_address
        classifier = cl.GadgetClassifier(self.arch,  data, startVA, validate, log_level = self.level)
        classic_gadgets = []
        for i in range(0, len(data), self.arch.instruction_alignment):#{
            #fix-me: applying ROPGadget here to black-list all bad code points.
            address = startVA + i
            if bad_bytes != None and utils.address_contains_bad_byte(address, bad_bytes, self.arch):
                continue
            gadgets = classifier.create_gadgets_from_instructions(address)
            if finder.FILTER_FUNC != None:
                gadgets = finder.FILTER_FUNC(gadgets)
            classic_gadgets += gadgets
        #}end for
        gadget_list.add_gadgets(classic_gadgets)

        #harvest the JCC gadgets if there are
        jcc_gadgets = classifier.harvest_jcc_gadgets(classic_gadgets)
        gadget_list.add_gadgets(jcc_gadgets)
