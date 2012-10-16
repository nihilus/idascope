#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################
# Credits:
# - Thanks to Branko Spasojevic for contributing a function for
#   finding and renaming potential wrapper functions.
########################################################################

import json
import re

from helpers import JsonHelper

from IdaProxy import IdaProxy
from idascope.core.structures.FunctionContext import FunctionContext
from idascope.core.structures.CallContext import CallContext
from idascope.core.structures.ParameterContext import ParameterContext


class SemanticIdentifier():
    """
    A module to analyze and explore an IDB for semantics. For a set of API names, references to these
    are identified and used for creating context and allowing tagging of them.
    """

    def __init__(self, idascope_config):
        print ("[|] loading SemanticIdentifier")
        self.re = re
        self.ida_proxy = IdaProxy()
        self.FunctionContext = FunctionContext
        self.CallContext = CallContext
        self.ParameterContext = ParameterContext
        self.renaming_seperator = "_"
        self.semantic_definitions = []
        self.last_result = {}
        self.idascope_config = idascope_config
        self._load_config(self.idascope_config.semantics_file)
        return

    def _load_config(self, config_filename):
        """
        Loads a semantic configuration file and collects all definitions from it.
        @param config_filename: filename of a semantic configuration file
        @type config_filename: str
        """
        config_file = open(config_filename, "r")
        config = config_file.read()
        parsed_config = json.loads(config, object_hook=JsonHelper.decode_dict)
        self.renaming_seperator = parsed_config["renaming_seperator"]
        self.semantic_definitions = parsed_config["semantic_definitions"]
        return

    def calculate_number_of_basic_blocks_for_function_address(self, function_address):
        """
        Calculates the number of basic blocks for a given function by walking its FlowChart.
        @param function_address: function address to calculate the block count for
        @type function_address: int
        """
        number_of_blocks = 0
        try:
            func_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_address))
            for block in func_chart:
                number_of_blocks += 1
        except:
            pass
        return number_of_blocks

    def get_number_of_basic_blocks_for_function_address(self, address):
        """
        returns the number of basic blocks for the function containing the queried address,
        based on the value stored in the last scan result.

        If the number of basic blocks for this function has never been calculated, zero is returned.
        @param function_address: function address to get the block count for
        @type function_address: int
        @return: (int) The number of blocks in th e function
        """
        number_of_blocks = 0
        function_address = self.get_function_address_for_address(address)
        if function_address in self.last_result.keys():
            number_of_blocks = self.last_result[function_address].number_of_basic_blocks
        return number_of_blocks

    def scan(self):
        """
        Scan the whole IDB with all available techniques.
        """
        self.scan_by_references()
        self.scan_all_code()

    def scan_by_references(self):
        """
        Scan by references to API names, based on the definitions loaded from the config file.
        This is highly efficient because we only touch places in the IDB that actually have references
        to our API names of interest.
        """
        scan_result = {}
        for semantic_group in self.semantic_definitions:
            semantic_group_tag = semantic_group["tag"]
            for api_name in semantic_group["api_names"]:
                api_address = self.ida_proxy.LocByName(api_name)
                code_ref_addrs = [ref for ref in self.ida_proxy.CodeRefsTo(api_address, 0)]
                data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsTo(api_address)]
                ref_addrs = iter(set(code_ref_addrs).union(set(data_ref_addrs)))
                for ref in ref_addrs:
                    function_ctx = self.FunctionContext()
                    function_ctx.function_address = self.ida_proxy.LocByName(self.ida_proxy.GetFunctionName(ref))
                    function_ctx.function_name = self.ida_proxy.GetFunctionName(ref)
                    function_ctx.has_dummy_name = (self.ida_proxy.GetFlags(function_ctx.function_address) & \
                        self.ida_proxy.FF_LABL) > 0
                    if function_ctx.function_address not in scan_result.keys():
                        scan_result[function_ctx.function_address] = function_ctx
                    else:
                        function_ctx = scan_result[function_ctx.function_address]
                    call_ctx = self.CallContext()
                    call_ctx.called_function_name = api_name
                    call_ctx.address_of_call = ref
                    call_ctx.called_address = api_address
                    call_ctx.tag = semantic_group_tag
                    call_ctx.parameter_contexts = self._resolve_api_call(call_ctx)
                    function_ctx.call_contexts.append(call_ctx)
        self.last_result = scan_result

    def scan_all_code(self):
        """
        Not implemented yet. In the long run, this function shall perform a full enumeration of all instructions,
        gathering information like number of instructions, number of basic blocks,
        references to and from functions etc.
        """
        # for all functions, accumulate data for the following fields:
        #   number_of_basic_blocks = 0
        #   number_of_instructions = 0
        #   number_of_xrefs_from = 0
        #   number_of_xrefs_to = 0
        pass

    def get_function_address_for_address(self, address):
        """
        Get a function address containing the queried address.
        @param address: address to check the function address for
        @type address: int
        @return: (int) The start address of the function containing this address
        """
        return self.ida_proxy.LocByName(self.ida_proxy.GetFunctionName(address))

    def calculate_number_of_functions(self):
        """
        Calculate the number of functions in all segments.
        @return: (int) the number of functions found.
        """
        number_of_functions = 0
        for seg_ea in self.ida_proxy.Segments():
            for function_ea in self.ida_proxy.Functions(self.ida_proxy.SegStart(seg_ea), self.ida_proxy.SegEnd(seg_ea)):
                number_of_functions += 1
        return number_of_functions

    def get_identified_function_addresses(self):
        """
        Get all function address that have been covered by the last scanning.
        @return: (list of int) The addresses of covered functions.
        """
        return self.last_result.keys()

    def get_identified_dummy_function_addresses(self):
        """
        Get all function address with a dummy name that have been covered by the last scanning.
        @return: (list of int) The addresses of covered functions.
        """
        return [addr for addr in self.last_result.keys() if self.last_result[addr].has_dummy_name]

    def get_tags(self):
        """
        Get all the tags that have been covered by the last scanning.
        @return (list of str) The tags found.
        """
        tags = []
        for function_address in self.last_result.keys():
            for call_ctx in self.last_result[function_address].call_contexts:
                if call_ctx.tag not in tags:
                    tags.append(call_ctx.tag)
        return tags

    def get_tags_for_function_address(self, address):
        """
        Get all tags found for the function containing the queried address.
        @param address: address in the target function
        @type address: int
        @return: (list of str) The tags for the function containing the queried address
        """
        tags = []
        function_address = self.get_function_address_for_address(address)
        if function_address in self.last_result.keys():
            for call_ctx in self.last_result[function_address].call_contexts:
                if call_ctx.tag not in tags:
                    tags.append(call_ctx.tag)
        return tags

    def get_tag_count_for_function_address(self, tag, address):
        """
        Get the number of occurrences for a certain tag for the function containing the queried address.
        @param tag: a tag as included in semantic definitions
        @type tag: str
        @param address: address in the target function
        @type address: int
        @return: (int) The number of occurrences for this tag in the function
        """
        function_address = self.get_function_address_for_address(address)
        tag_count = 0
        if tag in self.get_tags_for_function_address(function_address):
            for call_ctx in self.last_result[function_address].call_contexts:
                if call_ctx.tag == tag:
                    tag_count += 1
        return tag_count

    def get_tagged_apis_for_function_address(self, address):
        """
        Get all call contexts for the function containing the queried address.
        @param address: address in the target function
        @type address: int
        @return: (list of CallContext data objects) The call contexts identified by the scanning of this function
        """
        function_address = self.get_function_address_for_address(address)
        if function_address in self.last_result.keys():
            all_call_ctx = self.last_result[function_address].call_contexts
            return [call_ctx for call_ctx in all_call_ctx if call_ctx.tag != ""]

    def get_address_tag_pairs_ordered_by_function(self):
        """
        Get all call contexts for all functions
        @return: a dictionary with key/value entries of the following form: (function_address,
                 dict((call_address, tag)))
        """
        functions_and_tags = {}
        for function in self.get_identified_function_addresses():
            call_contexts = self.get_tagged_apis_for_function_address(function)
            if function not in functions_and_tags.keys():
                functions_and_tags[function] = {}
            for call_ctx in call_contexts:
                functions_and_tags[function][call_ctx.address_of_call] = call_ctx.tag
        return functions_and_tags

    def get_functions_to_rename(self):
        """
        Get all functions that can be renamed according to the last scan result. Only functions with the standard
        IDA name I{sub_[0-9A-F]+} will be considered for renaming.
        @return: a list of dictionaries, each consisting of three tuples: ("old_function_name", str), \
                 ("new_function_name", str), ("function_address", int)
        """
        functions_to_rename = []
        for function_address_to_tag in self.last_result.keys():
            new_function_name = self.last_result[function_address_to_tag].function_name
            # has the function still a dummy name?
            if self.ida_proxy.GetFlags(function_address_to_tag) & self.ida_proxy.FF_LABL > 0:
                tags_for_function = self.get_tags_for_function_address(function_address_to_tag)
                for tag in sorted(tags_for_function, reverse=True):
                    if tag not in new_function_name:
                        new_function_name = tag + self.renaming_seperator + new_function_name
                functions_to_rename.append({"old_function_name": \
                    self.last_result[function_address_to_tag].function_name, "new_function_name": \
                    new_function_name, "function_address": function_address_to_tag})
        return functions_to_rename

    def rename_functions(self):
        """
        Perform the renaming of functions according to the last scan result.
        """
        for function in self.get_functions_to_rename():
            if function["old_function_name"] == self.ida_proxy.GetFunctionName(function["function_address"]):
                self.ida_proxy.MakeNameEx(function["function_address"], function["new_function_name"], \
                    self.ida_proxy.SN_NOWARN)

    def rename_potential_wrapper_functions(self):
        for seg_ea in self.ida_proxy.Segments():
            for func_ea in self.ida_proxy.Functions(self.ida_proxy.SegStart(seg_ea), self.ida_proxy.SegEnd(seg_ea)):
                if (self.ida_proxy.GetFlags(func_ea) & 0x8000) != 0:
                    # dummy function check if wrapper material
                    func_end = self.ida_proxy.GetFunctionAttr(func_ea, self.ida_proxy.FUNCATTR_END)
                    # wrappers are likely short
                    if (func_end - func_ea) > 0 and (func_end - func_ea) < 0x100:
                        nr_calls = 0
                        for i_ea in self.ida_proxy.FuncItems(func_ea):
                            if self.ida_proxy.GetMnem(i_ea) == 'call':
                                nr_calls += 1
                                if nr_calls > 1:
                                    break
                                call_dst = list(self.ida_proxy.CodeRefsFrom(i_ea, 0))
                                if len(call_dst) == 0:
                                    continue

                                call_dst = call_dst[0]
                                w_name = ''
                                if (self.ida_proxy.GetFunctionFlags(call_dst) & self.ida_proxy.FUNC_LIB) != 0 or \
                                    (self.ida_proxy.GetFlags(func_ea) & self.ida_proxy.FF_LABL) == 0:
                                    w_name = self.ida_proxy.Name(call_dst)
                        if nr_calls == 1 and len(w_name) > 0:
                            rval = False
                            name_suffix = 0
                            while rval == False:
                                if name_suffix > 40:
                                    print("[!] Potentially more than 50 wrappers for function %s, " \
                                        "please report IDB" % w_name)
                                    break
                                if self.ida_proxy.Demangle(w_name, \
                                    self.ida_proxy.GetLongPrm(self.ida_proxy.INF_SHORT_DN)) != w_name:
                                    f_name = w_name + '_' + str(name_suffix)
                                elif name_suffix > 0:
                                    f_name = w_name + '__w' + str(name_suffix)
                                else:
                                    f_name = w_name + '__w'
                                name_suffix += 1
                                rval = self.ida_proxy.MakeNameEx(func_ea, f_name, \
                                    self.ida_proxy.SN_NOCHECK | self.ida_proxy.SN_NOWARN)
                            if rval == True:
                                print("[+] Identified and renamed potential wrapper @ [%08x] to [%s]" % (func_ea, f_name))

    def get_parameters_for_call_address(self, call_address):
        """
        Get the parameters for the given address of a function call.
        @param call_address: address of the target call to inspect
        @type call_address: int
        @return: a list of ParameterContext data objects.
        """
        target_function_address = self.ida_proxy.LocByName(self.ida_proxy.GetFunctionName(call_address))
        all_tagged_apis_in_function = self.get_tagged_apis_for_function_address(target_function_address)
        for api in all_tagged_apis_in_function:
            if api.address_of_call == call_address:
                return self._resolve_api_call(api)
        return []

    def _resolve_api_call(self, call_context):
        """
        Resolve the parameters for an API calls based on a call context for this API call.
        @param call_context: the call context to get the parameter information for
        @type call_context: a CallContext data object
        @return: a list of ParameterContext data objects.
        """
        resolved_api_parameters = []
        api_signature = self._get_api_signature(call_context.called_function_name)
        push_addresses = self._get_push_addresses_before_target_address(call_context.address_of_call)
        resolved_api_parameters = self._match_push_addresses_to_signature(push_addresses, api_signature)
        return resolved_api_parameters

    def _match_push_addresses_to_signature(self, push_addresses, api_signature):
        """
        Combine the results of I{_get_push_addresses_before_target_address} and I{_get_api_signature} in order to
        produce a list of ParameterContext data objects.
        @param push_addresses: the identified push addresses before a function call that shall be matched to a function
                               signature
        @type push_addresses: a list of int
        @param api_signature: information about a function definition with
                              parameter names, types, and so on.
        @type api_signature: a dictionary with the layout as returned by I{_get_api_signature}
        @return: a list of ParameterContext data objects.
        """
        matched_parameters = []
        # TODO:
        # upgrade this feature with data flow analysis to resolve parameters with higher precision
        api_num_params = len(api_signature["parameters"])
        push_addresses = push_addresses[-api_num_params:]
        # TODO:
        # There might be the case where we identify less pushed parameters than required by the function
        # signature. Thus we calculate a "parameter discrepancy" that we use to adjust our enumeration index
        # so that the last n parameters get matched correctly. This is a temporary fix and might be solved later on.
        parameter_discrepancy = len(push_addresses) - api_num_params
        for index, param in enumerate(api_signature["parameters"], start=parameter_discrepancy):
            param_ctx = self.ParameterContext()
            param_ctx.parameter_type = param["type"]
            param_ctx.parameter_name = param["name"]
            if (parameter_discrepancy != 0) and (index < 0):
                param_ctx.valid = False
            else:
                param_ctx.push_address = push_addresses[index]
                param_ctx.ida_operand_type = self.ida_proxy.GetOpType(push_addresses[index], 0)
                param_ctx.ida_operand_value = self.ida_proxy.GetOperandValue(push_addresses[index], 0)
                param_ctx.value = param_ctx.ida_operand_value
            matched_parameters.append(param_ctx)
        return matched_parameters

    def _get_api_signature(self, api_name):
        """
        Get the signature for a function by using IDA's I{GetType()}. The string is then parsed with a Regex and
        returned as a dictionary.
        @param api_name: name of the API / function to get type information for
        @type api_name: str
        @return: a dictionary with key/value entries of the following form: ("return_type", str),
                 ("parameters", [dict(("type", str), ("name", str))])
        """
        api_signature = {"api_name": api_name, "parameters": []}
        api_location = self.ida_proxy.LocByName(api_name)
        type_def = self.ida_proxy.GetType(api_location)
        function_signature_regex = r"(?P<return_type>[\w\s\*]+)\((?P<parameters>[,\.\*\w\s]*)\)"
        result = self.re.match(function_signature_regex, type_def)
        if result is not None:
            api_signature["return_type"] = result.group("return_type")
            if len(result.group("parameters")) > 0:
                for parameter in result.group("parameters").split(","):
                    type_and_name = {}
                    type_and_name["type"] = parameter[:parameter.rfind(" ")].strip()
                    type_and_name["name"] = parameter[parameter.rfind(" "):].strip()
                    api_signature["parameters"].append(type_and_name)
        else:
            print ("[-] SemanticIdentifier._get_api_signature: No API/function signature for \"%s\" @ 0x%x available.") \
                % (api_name, api_location)
        # TODO:
        # here should be a check for the calling convention
        # currently, list list is simply reversed to match the order parameters are pushed to the stack
        api_signature["parameters"].reverse()
        return api_signature

    def _get_push_addresses_before_target_address(self, address):
        """
        Get the addresses of all push instructions in the basic block preceding the given address.
        @param address: address to get the push addresses for.
        @type address: int
        @return: a list of int
        """
        push_addresses = []
        function_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(address))
        for block in function_chart:
            if block.startEA <= address < block.endEA:
                for instruction_addr in self.ida_proxy.Heads(block.startEA, block.endEA):
                    if self.ida_proxy.GetMnem(instruction_addr) == "push":
                        push_addresses.append(instruction_addr)
                    if instruction_addr >= address:
                        break
        return push_addresses

    def get_last_result(self):
        """
        Get the last scan result as retrieved by I{scan_by_references}.
        @return: a dictionary with key/value entries of the following form: (function_address, FunctionContext)
        """
        return self.last_result

    def print_last_result(self):
        """
        nicely print the last scan result (mostly used for debugging)
        """
        for function_address in self.last_result.keys():
            print ("0x%x - %s -> ") % (function_address, self.ida_proxy.GetFunctionName(function_address)) \
                + ", ".join(self.get_tags_for_function_address(function_address))
            for call_ctx in self.last_result[function_address].call_contexts:
                print ("    0x%x - %s (%s)") % (call_ctx.address_of_call, call_ctx.called_function_name, call_ctx.tag)
