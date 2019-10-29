import addresses
import assemble
import string


GENERAL_REGISTERS = [
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'
]


ALL_REGISTERS = GENERAL_REGISTERS + [
    'esp', 'eip', 'ebp'
]


class GadgetSearch(object):
    def __init__(self, dump_path, start_addr=None):
        """
        Construct the GadgetSearch object.

        Input:
            dump_path: The path to the memory dump file created with GDB.
            start_addr: The starting memory address of this dump. Use
                        `addresses.LIBC_TEXT_START` by default.
        """
        self.start_addr = (start_addr if start_addr is not None
                           else addresses.LIBC_TEXT_START)
        with open(dump_path, 'rb') as f:
            self.dump = f.read()

    def get_format_count(self, gadget_format):
        """
        Get how many different register placeholders are in the pattern.
        
        Examples:
            self.get_format_count('POP ebx')
            => 0
            self.get_format_count('POP {0}')
            => 1
            self.get_format_count('XOR {0}, {0}; ADD {0}, {1}')
            => 2
        """
        # Hint: Use the string.Formatter().parse method:
        #
        import string
        format_iterator = string.Formatter().parse(gadget_format)

        # The format_iterator holds in index 1 the field name (if it has {0} it will hold 0).
        # So creating an histogram saying how many different field names there are will give us the answer
        histogram = {}
        for formatt in format_iterator:
            if formatt[1] is None:
                continue
            histogram[formatt[1]] = histogram.get(formatt[1], 0) + 1

        return len(histogram)

    def get_register_combos(self, nregs, registers):
        """
        Return all the combinations of `registers` with `nregs` registers in
        each combination. Duplicates ARE allowed!

        Example:
            self.get_register_combos(2, ('eax', 'ebx'))
            => [['eax', 'eax'],
                ['eax', 'ebx'],
                ['ebx', 'eax'],
                ['ebx', 'ebx']]
        """
        import itertools
        combos_itertools = itertools.product(registers, repeat=nregs)
        return [list(combo) for combo in list(combos_itertools)]

        

    def format_all_gadgets(self, gadget_format, registers):
        """
        Format all the possible gadgets for this format with the given
        registers.

        Example:
            self.format_all_gadgets("POP {0}; ADD {0}, {1}", ('eax', 'ecx'))
            => ['POP eax; ADD eax, eax',
                'POP eax; ADD eax, ecx',
                'POP ecx; ADD ecx, eax',
                'POP ecx; ADD ecx, ecx']
        """
        # Hints:
        #
        # 0. Use the previous functions to count the number of placeholders,
        #    and get all combinations of registers.
        #
        # 1. Use the `format` function to build the string:
        #
        #    'Hi {0}! I am {1}, you are {0}'.format('Luke', 'Vader')
        #    => 'Hi Luke! I am Vader, you are Luke'
        #
        # 2. You can use pass a list of arguments instead of specifying each
        #    argument individually. Use the internet, the force is strong with
        #    StackOverflow.
        num_placeholders = self.get_format_count(gadget_format)
        combos = self.get_register_combos(num_placeholders, registers)
        return [gadget_format.format(*combo) for combo in combos]

    def find_all(self, gadget):
        """
        Return all the addresses of the gadget inside the memory dump.

        Example:
            self.find_all('POP eax')
            => < all ABSOLUTE addresses in memory of 'POP eax; RET' >
        """
        # Notes:
        #
        # 1. Addresses are ABSOLUTE (for example, 0x08403214), NOT RELATIVE to
        #    the beginning of the file (for example, 12).
        #
        # 2. Don't forget to add the 'RET'.
        opcode = assemble.assemble_data(gadget + '; RET')
        indices = [i for i in self.find_all_helper(opcode, self.dump)]
        return [self.start_addr + index for index in indices]

    def find_all_helper(self, pattern, data):
        # Thanks to https://stackoverflow.com/questions/4664850/find-all-occurrences-of-a-substring-in-python
        i = data.find(pattern)
        while i != -1:
            yield i
            i = data.find(pattern, i+1)

    def find(self, gadget, condition=None):
        """
        Return the first result of find_all. If condition is specified, onlyider addresses that mee
        consider addresses that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(addr for addr in self.find_all(gadget)
                        if condition(addr))
        except StopIteration:
            raise ValueError("Couldn't find matching address for " + gadget)

    def find_all_formats(self, gadget_format, registers=GENERAL_REGISTERS):
        """
        Similar to find_all - but return all the addresses of all
        possible gadgets that can be created with this format and registers.
        Every elemnt in the result will be a tuple of the gadget string and
        the address in which it appears.

        Example:
            self.find_all_formats('POP {0}; POP {1}')
            => [('POP eax; POP ebx', address1),
                ('POP ecx; POP esi', address2),
                ...]
        """
        # all possible combinations of gadgets with this format
        gadgets = self.format_all_gadgets(gadget_format, registers)
        result = []
        for gadget in gadgets:  # iterate through all gadgets
            addresses_of_gadget = self.find_all(gadget)  # there might be more than one possible address for each gadget
            for address in addresses_of_gadget:  # iterate through all possible gadgets
                result.append((gadget, address))  # append to result

        return result


    def find_format(self, gadget_format, registers=GENERAL_REGISTERS,
                    condition=None):
        """
        Return the first result of find_all_formats. If condition is specified,
        only consider addresses that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(
                addr for addr in self.find_all_formats(gadget_format, registers)
                if condition(addr)
            )
        except StopIteration:
            raise ValueError(
                "Couldn't find matching address for " + gadget_format)

