import re
from collections import defaultdict
from typing import List
from utils.exploit_gates1 import NetlistParser


def does_have_trojan0(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)
    chain = []

    def can_be_in_the_chain(gate_name: str, parser: NetlistParser) -> bool:
        gate = parser.get_gate(gate_name)
        if gate is None:
            return False
        if gate.gate_type != "dff":
            return False
        for output in gate.outputs:
            # not and nor
            if output.name not in parser.gates:
                continue
            if output.gate_type == 'not':
                for output_2 in output.outputs:
                    if output_2.name not in parser.gates:
                        continue
                    if output_2.gate_type == 'nor':
                        for output_3 in output_2.outputs:
                            if output_3.name not in parser.gates:
                                continue
                            if output_3.gate_type == 'dff':
                                return True
            # or
            elif output.gate_type == 'or':
                for output_2 in output.outputs:
                    if output_2.name not in parser.gates:
                        continue
                    if output_2.gate_type == 'dff':
                        return True
        return False
    
    def is_start_of_chain(gate_name: str, parser: NetlistParser) -> bool:
        gate = parser.get_gate(gate_name)
        if gate is None:
            return False
        if gate.gate_type != "dff":
            return False
        if not can_be_in_the_chain(gate_name, parser):
            return False
        
        d_input_gate = parser.get_gate(gate.inputs[3])
        if d_input_gate.gate_type == 'nor':
            for input_nor in d_input_gate.inputs:
                if input_nor not in parser.gates:
                    continue
                input_nor_gate = parser.get_gate(input_nor)
                if input_nor_gate.gate_type == 'not':
                    for input_not in input_nor_gate.inputs:
                        if input_not not in parser.gates:
                            continue
                        input_not_gate = parser.get_gate(input_not)
                        if input_not_gate.gate_type == 'dff':
                            return False
        elif d_input_gate.gate_type == 'or':
            for input_or in d_input_gate.inputs:
                if input_or not in parser.gates:
                    continue
                input_or_gate = parser.get_gate(input_or)
                if input_or_gate.gate_type == 'dff':
                    return False
        
        return True
    
    def create_chain(start_gate_name: str) -> int:
        start_of_chain = parser.get_gate(start_gate_name)
        if start_of_chain is None:
            #print("No chain found")
            return -1
        chain.append(start_gate_name)
        while can_be_in_the_chain(chain[len(chain) - 1], parser):
            added = False
            for output in parser.get_gate(chain[len(chain) - 1]).outputs:
                if output.gate_type == 'not':
                    for output_2 in output.outputs:
                        if output_2.gate_type == 'nor':
                            for output_3 in output_2.outputs:
                                if output_3.gate_type == 'dff':
                                    if can_be_in_the_chain(output_3.name, parser):
                                        chain.append(output.name)
                                        chain.append(output_2.name)
                                        chain.append(output_3.name)
                                        added = True
                                        break
                elif output.gate_type == 'or':
                    for output_2 in output.outputs:
                        if output_2.gate_type == 'dff':
                            if can_be_in_the_chain(output_2.name, parser):
                                chain.append(output.name)
                                chain.append(output_2.name)
                                added = True
                                break
            if not added:
                #print("No more gates can be added to the chain")
                break
        return len(chain)
    
    chain = []
    start_of_chain = None
    max_length = 0
    main_chain = []
    main_start = None
    for gate_name in parser.gates:
        chain = []
        if is_start_of_chain(gate_name, parser):
            start_of_chain = gate_name
            length = create_chain(start_of_chain)
            #print (f"Found start of chain: {start_of_chain} with length {length}")
            if length > max_length:
                max_length = length
                main_chain = chain.copy()
                main_start = start_of_chain
    chain = main_chain
    #print(f"Longest chain starts at {main_start} with length {max_length}")
    #add the final dff gate to the chain
    aaa = 0
    if not chain:
        aaa = 1
        #print("No chain found")
    else:
        current_last_gate = parser.get_gate(chain[-1])
        for output in current_last_gate.outputs:
            if output.gate_type == 'or':
                for output_2 in output.outputs:
                    if output_2.gate_type == 'dff':
                        chain.append(output.name)
                        chain.append(output_2.name)
                        break
            elif output.gate_type == 'not':
                for output_2 in output.outputs:
                    if output_2.gate_type == 'nor':
                        for output_3 in output_2.outputs:
                            if output_3.gate_type == 'dff':
                                chain.append(output.name)
                                chain.append(output_2.name)
                                chain.append(output_3.name)
                                break
        #print("Chain found:")
        #for gate_name in chain:
            #print(gate_name, parser.get_gate(gate_name).gate_type)
        #print("Chain length:", len(chain))
    visited_gates = set()
    xors = set()

    def dfs(gate_name: str) -> bool:
        visited_gates.add(gate_name)
        final_ans = False
        gate = parser.get_gate(gate_name)
        for input_name in gate.inputs:
            if input_name not in parser.gates:
                continue
            input_gate = parser.get_gate(input_name)

            if input_name in visited_gates:
                if input_name in xors:
                    final_ans = True
                continue
                    #xors.add(gate_name)
                #continue

            elif input_gate.gate_type == 'dff':
                if input_name in chain:
                    final_ans = True
                    #xors.add(gate_name)
                continue

            current = dfs(input_name)
            final_ans = final_ans or current
            
        if final_ans:
            xors.add(gate_name)
        
        
        
        return final_ans
    
    def find_xors_gates_in_chain(chain: List[str], parser: NetlistParser):
        if not chain:
            #print("No chain found")
            return
        final_gate = parser.get_gate(chain[0]).inputs[3]
        #xors.add(final_gate)
        visited_gates.clear()
        xors.clear()
        #visited_gates.add(final_gate)
        dfs(final_gate)

    find_xors_gates_in_chain(chain, parser)
    #print("XOR gates found in the chain:")
    #for gate_name in xors:
        #print(gate_name, parser.get_gate(gate_name).gate_type)

    #print("Number of XOR gates found in the chain:", len(xors))

    outputs_of_chain = set()
    for gate_name in chain:
        does_have_xor_output = False
        gate = parser.get_gate(gate_name)
        if gate is None:
            continue
        if gate.gate_type == 'dff':
            outputs = gate.outputs
            for output in outputs:
                if does_have_xor_output:
                    break
                if output.name not in parser.gates:
                    continue
                if output.name in xors:
                    continue
                if output.gate_type == 'xor':
                    for output_2 in output.outputs:
                        if output_2.name not in parser.gates:
                            continue
                        if output_2.gate_type == 'dff':
                            if output_2.name not in chain:
                                outputs_of_chain.add(output_2.name)
                                outputs_of_chain.add(output.name)
                                does_have_xor_output = True
                                break

    #print("Outputs of the chain:")
    #for output_name in outputs_of_chain:
        #print(output_name, parser.get_gate(output_name).gate_type)
    #print("Number of outputs of the chain:", len(outputs_of_chain))

    trojan_gates = []
    for output_name in outputs_of_chain:
        trojan_gates.append(output_name)
    for gate_name in xors:
        trojan_gates.append(gate_name)
    for gate_name in chain:
        trojan_gates.append(gate_name)

    #print("Number of trojan gates:", len(trojan_gates))
    #print("Trojan gates:")
    #for gate_name in trojan_gates:
        #print(gate_name, parser.get_gate(gate_name).gate_type)

    if len(main_chain) < 30:
        does_exist = False
        trojan_gates = []
    else:
        does_exist = True
    return [trojan_gates, does_exist]