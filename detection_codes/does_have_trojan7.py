import re
from collections import defaultdict
from typing import List
from utils.exploit_gates2 import NetlistParser

def does_have_trojan7(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)
    calculated_dfs = {}

    final_gate = None
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        num_of_xor_xnor_outs = 0
        for output in gate.outputs:
            if output.gate_type in ['xor', 'xnor']:
            # if output.gate_type == 'xnor':
                num_of_xor_xnor_outs += 1
        if num_of_xor_xnor_outs == 4 and len(gate.outputs) == 4:
            final_gate = gate_name
            break
    
    #print (f"Final Gate: {final_gate}")

    def find_number_of_leaves(gate_name: str) -> int:
        """
        Find the number of leaves for a given gate.
        """
        gate = parser.get_gate(gate_name)
        answer = 0
        for input in gate.inputs:
            driver_gate = parser.get_gate(input)
            if driver_gate is None:
                answer += 1
                continue
            if driver_gate.gate_type == 'dff':
                answer += 1
                continue
            if driver_gate.name in calculated_dfs:
                answer += calculated_dfs[driver_gate.name]
                continue
            answer += find_number_of_leaves(driver_gate.name)
        
        calculated_dfs[gate_name] = answer
            
        return answer

    calculated_dfs = {}
    #print (find_number_of_leaves('g1369'))
    for gate_name in parser.gates:
        if gate_name in calculated_dfs:
            continue
        if parser.get_gate(gate_name).gate_type == 'dff':
            calculated_dfs[gate_name] = 1
            continue
        find_number_of_leaves(gate_name)

    def find_trojan_gates(gate_name: str):
        gate = parser.get_gate(gate_name)
        outputs = gate.outputs
        visited = set()
        trojan_gates.append(gate_name)
        for output in outputs:
            if output:
                if output.gate_type == 'xor' or output.gate_type == 'xnor':
                    trojan_gates.append(output.name)
        queue = [gate_name]
        visited.add(gate_name)
        while queue:
            current_gate_name = queue.pop(0)
            current_gate = parser.get_gate(current_gate_name)
            for input, input_net in zip(current_gate.inputs, current_gate.input_nets):
                if '[' in input_net:
                    continue
                input_gate = parser.get_gate(input)
                if input_gate is None:
                    continue
                if input_gate.name in visited:
                    continue
                visited.add(input)
                trojan_gates.append(input)
                if calculated_dfs[input] > 2:
                    queue.append(input)
                else:
                    for input_of_input in input_gate.inputs:
                        input_of_input_gate = parser.get_gate(input_of_input)
                        if input_of_input_gate is None:
                            continue
                        if input_of_input_gate.gate_type == 'not':
                            trojan_gates.append(input_of_input)
        
    trojan_gates = []
    if final_gate is not None:    
        #print(f"Final Gate: {final_gate}")
        find_trojan_gates(final_gate)
        # for trojan_gate_name in trojan_gates:
        #     trojan_gate = parser.get_gate(trojan_gate_name)
        #     for input in trojan_gate.input_nets:
        #         input_gate = parser.get_gate(input)
                
        # print(f"Number of Trojan Gates: {len(trojan_gates)}")
        # print(f"Trojan Gates: {trojan_gates}")
        gate = parser.get_gate(final_gate)
        outputs = []
        for output in gate.outputs:
            outputs.append(output.gate_type)
        # print(f"Outputs of Final Gate: {outputs}")

    for gate_name in trojan_gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type == 'dff':
            return [[], False]
    if len(trojan_gates) < 30:
        return [[], False]
    
    # added this to avoid unusually large trojans (remove if needed)
    if len(trojan_gates) > 1000:
        return [[], False]
    ##################################
    return [trojan_gates, True]
