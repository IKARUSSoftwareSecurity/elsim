"""
the sign module contains methods to enhance an Analysis object
by using a bytecode signature format developed by Cesare and Xiang
"""
# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import OrderedDict
from operator import itemgetter
import binascii
import enum

from androguard.core.bytecodes import dvm

TAINTED_PACKAGE_CREATE = 0
TAINTED_PACKAGE_CALL = 1
TAINTED_PACKAGE_INTERNAL_CALL = 2

class PredefinedSignature(enum.Enum):
    """
    Defines possible signature types
    """
    L0_0 = "L0_0"
    L0_1 = "L0_1"
    L0_2 = "L0_2"
    L0_3 = "L0_3"
    L0_4 = "L0_4"
    L0_5 = "L0_5"
    L0_6 = "L0_6"
    L0_0_L1 = "L0_0:L1"
    L0_1_L1 = "L0_1:L1"
    L0_2_L1 = "L0_2:L1"
    L0_3_L1 = "L0_3:L1"
    L0_4_L1 = "L0_4:L1"
    L0_5_L1 = "L0_5:L1"
    L0_0_L2 = "L0_0:L2"
    L0_0_L3 = "L0_0:L3"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    HEX = "hex"
    SEQUENCE_BB = "sequencebb"

SIGNATURES = {
    PredefinedSignature.L0_0: {"type": 0},
    PredefinedSignature.L0_1: {"type": 1},
    PredefinedSignature.L0_2: {"type": 2, "arguments": ["Landroid"]},
    PredefinedSignature.L0_3: {"type": 2, "arguments": ["Ljava"]},
    PredefinedSignature.L0_4: {"type": 2, "arguments": ["Landroid", "Ljava"]},
    PredefinedSignature.L0_5: {"type": 3, "arguments": ["Landroid"]},
    PredefinedSignature.L0_6: {"type": 3, "arguments": ["Ljava"]},
    PredefinedSignature.SEQUENCE_BB: {},
    PredefinedSignature.HEX: {},
}


class Sign:
    """
    The Sign object contains the signature for a single Method.
    """
    def __init__(self):
        # It looks like the ordering of the levels matters
        self.levels = OrderedDict()

    def add(self, level, value):
        """
        Adds given value to level

        :param str level:
        :param value:
        """
        self.levels[level] = value

    def get_string(self):
        """
        This returns actually bytes, as we require all functions in the similarity module
        to use bytes.
        All Strings are encoded as UTF-8.

        :rtype: bytes
        """
        return (''.join(self.levels.values())).encode('utf-8')

    def get_list(self):
        """
        Only used if the Signature type is SEQUENCE_BB
        """
        return self.levels["sequencebb"]


class Signature:
    """
    The Signature is a variant of the grammar described in:

    Cesare & Xiang (2010): Classification of Malware Using Structured Control Flow

    It wraps around an :class:`~androguard.core.analysis.analysis.Analysis` object.
    """
    def __init__(self, dx):
        """
        :param androguard.core.analysis.analysis.Analysis dx:
        """
        self.dx = dx

        # Contains Sign objects for faster lookup
        self._cached_signatures = {}

        # Contains the lower level signatures for faster lookup
        self._global_cached = {}

        # Defines which functions shall be called for what kind of signature
        self.levels = {
            # Classical method signature with basic blocks, strings, fields, packages
            "L0": {
                0: (self._get_strings_a, self._get_fields_a, self._get_packages_a, ),
                1: (self._get_strings_pa, self._get_fields_a, self._get_packages_a, ),
                2: (self._get_strings_a, self._get_fields_a, self._get_packages_pa_1, ),
                3: (self._get_strings_a, self._get_fields_a, self._get_packages_pa_2, ),
            },
            # strings
            "L1": (self._get_strings_a1, ),
            # exceptions
            "L2": (self._get_exceptions, ),
            # fill array data
            "L3": (self._get_fill_array_data, ),
            "L4": (self._get_packages, ),
            # Get opcodes as names
            "hex": (self._get_hex, ),
        }

    def get_method_signature(self, method, grammar_type=None, options=None, predef_sign=None):
        """
        Return a specific signature for a specific method

        predef_sign is a shortcut to defining grammar_type and options.
        But either predef_sign or grammar_type and options must be set.
        options is optional in any case.

        :param androguard.core.bytecodes.dvm.EncodedMethod method: The method to create the sign
        :param str grammar_type: the type of the signature (optional)
        :param dict options: the options of the signature (optional)
        :param PredefinedSignature predef_sign: used a predefined signature (optional)

        :rtype: Sign
        """
        if predef_sign is None and grammar_type is None and options is None:
            raise ValueError("you must either specify predef_sign or grammar_type and options!")

        if options is None:
            options = dict()

        # FIXME: this whole system is super complicated to work with...
        if predef_sign:
            if not isinstance(predef_sign, PredefinedSignature):
                # Legacy
                predef_sign = PredefinedSignature(predef_sign)

            grammar_type = []

            for i in predef_sign.value.split(":"):
                if "_" in i:
                    grammar_type.append("L0")
                    options["L0"] = SIGNATURES[PredefinedSignature(i)]
                else:
                    grammar_type.append(i)
            grammar_type = ':'.join(grammar_type)
        elif not isinstance(grammar_type, str) or not isinstance(options, dict):
            raise ValueError("grammar_type must be a str and options must be a dict")

        return self.get_method(self.dx.get_method(method), grammar_type, options)

    @staticmethod
    def _get_method_info(analysis_method):
        """
        Returns a string which describes the method in a unique fashion

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        """
        encmeth = analysis_method.get_method()
        return "%s-%s-%s" % (encmeth.get_class_name(), encmeth.get_name(), encmeth.get_descriptor())

    @staticmethod
    def _get_sequence_bb(analysis_method, min_instructions=6):
        """
        Returns the names of the opcodes for each non empty basic block
        which has more than n opcodes.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :param int min_instructions: give the minimal number of instr. the function must have
        :rtype: List[str]
        """
        res = []

        for i in analysis_method.basic_blocks.get():
            instructions = [j for j in i.get_instructions()]
            if len(instructions) >= min_instructions:
                res.append(''.join(map(lambda x: x.get_name(), instructions)))

        return res

    @staticmethod
    def _get_hex(analysis_method, *args):
        """
        Returns the decoded bytecode as text without any newlines

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        """
        buff = ""
        for i in analysis_method.get_method().get_instructions():
            buff += dvm.clean_name_instruction(i)
            buff += dvm.static_operand_instruction(i)
        return buff

    def _get_bb(self, analysis_method, functions, options):
        """
        Returns a list of basicblock signatures.
        For each basicblock, several functions are applied and additional
        branch opcodes are parsed and added to the output.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :param List[str] functions: the functions to call
        :param options: the options which might get passed to the functions
        :rtype: List[str]
        """
        bbs = []
        for b in analysis_method.basic_blocks.get():
            internal = []

            op_value = b.get_last().get_op_value()

            if 0x0e <= op_value <= 0x11:
                # return
                internal.append((b.end - 1, "R"))
            elif 0x32 <= op_value <= 0x3d:
                # if
                internal.append((b.end - 1, "I"))
            elif 0x28 <= op_value <= 0x2a:
                # goto
                internal.append((b.end - 1, "G"))
            elif 0x2b <= op_value <= 0x2c:
                # sparse or packed switch
                internal.append((b.end - 1, "G"))

            for func in functions:
                internal.extend(func(analysis_method, options))

            res = "B["
            # Sort by the offset and add the according string
            for i, k in sorted(internal, key=itemgetter(0)):
                if b.start <= i < b.end:
                    res += k
            res += "]"

            bbs.append(res)
        return bbs

    @staticmethod
    def _get_fill_array_data(analysis_method, *args):
        """
        Returns the content of fill-array-data-payloads commands

        .. warning::
            we actually have no idea what was meant here, but we assume that
            he wanted the content of the array as a hex string.
            How it was implemented did not even worked in the old androguard version...

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: str
        """
        buff = ""
        for basic_block in analysis_method.basic_blocks.get():
            for i in basic_block.get_instructions():
                if i.get_name() == "fill-array-data-payload":
                    buff += binascii.hexlify(i.get_data()).decode('ascii')
        return buff

    @staticmethod
    def _get_exceptions(analysis_method, *args):
        """
        Returns the class types of the handlers as one monolithic string

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: str
        """
        buff = ""

        method = analysis_method.get_method()
        code = method.get_code()
        if code is None or code.get_tries_size() <= 0:
            # No exception handlers in the method, or no code at all
            return buff

        for handler_catch in code.get_handlers().get_list():
            for handler in handler_catch.get_handlers():
                buff += str(analysis_method.get_vm().get_cm_type(handler.get_type_idx()))
        return buff

    def _get_all_strings_by_method(self, analysis_method):
        """
        TODO: This method belongs to androguard

        :rtype: Generator[(int, str), None, None]
        """
        # FIXME: this is super slow, as we always check all strings...
        for real_string, string_analysis in self.dx.get_strings_analysis().items():
            for _, src_meth, off in string_analysis.get_xref_from(withoffset=True):
                if analysis_method == src_meth:
                    yield off, real_string

    def _get_all_fields_by_method(self, analysis_method):
        """
        Wrapper to androguard get_xref_read/write that returns
        only the offsets and whether it's a read or write

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: Generator[(int, int), None, None]
        """
        # FIXME the return type is crap... should use an enum
        for _, _, off in analysis_method.get_xref_write():
            yield off, 1
        for _, _, off in analysis_method.get_xref_read():
           yield off, 0

    def _get_packages_by_method(self, analysis_method):
        """
        Wrapper to android get_xref_to and get_xref_new_instance that
        returns only the offset and the type of call

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: Generator[(int, int), None, None]
        """

        # If something is here, this is clearly a PACKAGE_CALL.
        for _, _, off in analysis_method.get_xref_to():
            yield off, TAINTED_PACKAGE_CALL

        # list1 = []
        for _, off in analysis_method.get_xref_new_instance():
            yield off, TAINTED_PACKAGE_CREATE
        #     list1.append((off, TAINTED_PACKAGE_CREATE))
        #
        # list2 = []
        # # In order to get the PACKAGE_CREATE, we need to check the ClassAnalysis objects...
        # # It stores the source, if and only if the xrefs is a create.
        # for ca in self.dx.get_classes():
        #     for called_class, values in ca.get_xref_to().items():
        #         for ref, meth, off in values:
        #             if ref == 0x22:
        #                 if meth == analysis_method:
        #                     #yield off, TAINTED_PACKAGE_CREATE
        #                     list2.append((off, TAINTED_PACKAGE_CREATE))
        #
        # if list1 == None and list2 == None:
        #     return
        # if sorted(list1) != sorted(list2):
        #     a = 1
        #
        # for off, t in list1:
        #     yield off, t

    def _get_strings_a1(self, analysis_method, *args):
        """
        Returns one long string with all used strings in the method,
        where all newlines are replaced by whitespaces.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: str
        """
        return ''.join([str(k).replace('\n', ' ') for _, k in self._get_all_strings_by_method(analysis_method)])

    def _get_strings_pa(self, analysis_method, *args):
        """
        Returns a list of tuples with the offset of the string usage and S plus the length of the string as second entry.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: List[(int, str)]
        """
        return [(k, 'S{}'.format(len(v))) for k, v in self._get_all_strings_by_method(analysis_method)]

    def _get_strings_a(self, analysis_method, *args):
        """
        Returns a list of tuples with the offsets of the string usage and 'S' as the second entry.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: List[(int, str)]
        """
        key = "SA-%s" % self._get_method_info(analysis_method)
        if key not in self._global_cached:
            self._global_cached[key] = [(k, 'S') for k, _ in self._get_all_strings_by_method(analysis_method)]

        return self._global_cached[key]

    def _get_fields_a(self, analysis_method, *args):
        """
        Returns a list of tuples with field accesses inside the method.
        The first item is the offset in the method, the second the accesstype.
        0 is for read and 1 for write access to the fields.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: List[(int, str)]
        """
        key = "FA-%s" % self._get_method_info(analysis_method)
        if key not in self._global_cached:
            self._global_cached[key] = [(k, 'F{}'.format(v)) for k, v in self._get_all_fields_by_method(analysis_method)]

        return self._global_cached[key]

    def _get_packages_a(self, analysis_method, *args):
        """
        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :rtype: List[(int, str)]
        """
        return [(offset, 'P{}'.format(access)) for offset, access in self._get_packages_by_method(analysis_method)]

    def _get_packages(self, analysis_method, include_packages):
        """
        returns just the package access flags, otherwise same as :meth:`_get_packages_pa_1`.

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :param List[str] include_packages:
        :rtype: str
        """
        return ''.join(map(itemgetter(1), self._get_packages_pa_1(analysis_method, include_packages)))

    def _get_packages_pa_1(self, analysis_method, include_packages):
        """
        Returns a list of tuples in the form (offset, str).
        The offset gives the bytecode offset where the method is used and the str
        has the form Px{name}.
        Px is the package access.
        
        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :param List[str] include_packages:
        :rtype: List[int, str]
        """
        key = "PA1-%s-%s" % (self._get_method_info(analysis_method), include_packages)
        if key not in self._global_cached:
            l = []

            for offset, access in self._get_packages_by_method(analysis_method):
                cls_name = analysis_method.class_name
                # Check if parts if the classname are in the list of to include packages
                present = any(map(lambda x, c=cls_name: x in str(c), include_packages))

                # Here we check what kind of call it is...
                # 1 => call
                # 0 => create
                # the special call 2 is used to define that this
                # is not an API but an internal package
                # but the access flag itself is always 0 or 1
                if access == TAINTED_PACKAGE_CALL:
                    # This is used of the package is called
                    if not analysis_method.is_external():
                        # If not external, then the call is 2.
                        # In that sense, we are only monitoring calls to APIs here!
                        # If the call is internal, we never print the name.
                        l.append((offset, "P{}".format(TAINTED_PACKAGE_INTERNAL_CALL)))
                    else:
                        if present:
                            l.append((offset, "P{}{{{}{}{}}}".format(access, cls_name, analysis_method.name, analysis_method.descriptor)))
                        else:
                            l.append((offset, "P{}".format(access)))
                else:
                    # This is called if the package is created
                    if present:
                        l.append((offset, "P{}{{{}}}".format(access, cls_name)))
                    else:
                        l.append((offset, "P{}".format(access)))

            self._global_cached[key] = l
        return self._global_cached[key]

    def _get_packages_pa_2(self, analysis_method, include_packages):
        """
        Returns a list of tuples in the form (offset, str).
        The offset gives the bytecode offset where the method is used and the str
        has the form Px{name}.
        Px is the package access.
 
        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :param List[str] include_packages:
        :rtype: List[int, str]
        """
        l = []
        for offset, access in self._get_packages_by_method(analysis_method):
            cls_name = analysis_method.class_name
            # Check if parts if the classname are in the list of to include packages
            present = any(map(lambda x, c=cls_name: x in str(c), include_packages))

            if present:
                l.append((offset, "P{}".format(access)))
                continue

            if access == 1:
                l.append((offset, "P{}{{{}{}{}}}".format(access, cls_name, analysis_method.name, analysis_method.descriptor)))
            else:
                l.append((offset, "P{}{{{}}}".format(access, cls_name)))

        return l

    def get_method(self, analysis_method, signature_type, signature_arguments=None) -> Sign:
        """
        Returns the Sign object for the given Method.

        The signature type is a string of the different signature methods which shall be used.
        Multiple signature methods can be used by separating them with a colon (:).

        signature_arguments must be a dictionary.
        The dictionary might have entries with the given signature_type which are dictionaries
        again.
        If a signature_type L0 is used, it expects to have a key L0 which is again a dict
        which has the key type, which resolves to an integer.
        Other functions require the key "arguments".

        :param androguard.core.analysis.analysis.MethodAnalysis analysis_method:
        :param str signature_type:
        :param dict signature_arguments: optional arguments
        :rtype: Sign
        """
        if not signature_arguments:
            signature_arguments = dict()

        key = "%s-%s-%s" % (self._get_method_info(analysis_method), signature_type, signature_arguments)

        if key not in self._cached_signatures:
            module_signature = Sign()
            for i in signature_type.split(":"):
                try:
                    # Check if we have arguments
                    _arguments = signature_arguments[i]["arguments"]
                except KeyError:
                    _arguments = []

                # For each signature type, we call the function and
                # add the signature type to the Sign object
                if i == "L0":
                    # L0 is special, because we use this special _get_bb wrapper
                    # Get all the functions which shall be applied
                    _type = self.levels[i][signature_arguments[i]["type"]]
                    module_signature.add(i, ''.join(self._get_bb(analysis_method, _type, _arguments)))
                elif i == "sequencebb":
                    # SequenceBB is special, as it returns a list and not string
                    value = self._get_sequence_bb(analysis_method)
                    module_signature.add(i, value)
                else:
                    value = ''
                    for func_name in self.levels[i]:
                        value += func_name(analysis_method, _arguments)
                    module_signature.add(i, value)

            self._cached_signatures[key] = module_signature

        return self._cached_signatures[key]
