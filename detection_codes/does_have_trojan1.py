import re
from collections import defaultdict
from typing import List
from utils.exploit_gates2 import NetlistParser
from collections import deque

def find_reset_signals(parser: NetlistParser) -> set[str]:
    reset_signals = set()
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type == "dff":
            reset_signal = gate.reset_signal
            if not reset_signal.startswith('1'):
                reset_signals.add(reset_signal)
    return reset_signals

def has_directed_path(s: str, t: str, mx: int, parser: NetlistParser) -> bool:
    visited = set()
    queue = [(s, 0)]  # (current_gate, current_length)
    
    while queue:
        current_gate, current_length = queue.pop(0)
        
        if current_gate == t:
            return True
        
        if current_length < mx:
            for output in parser.get_gate(current_gate).outputs:
                if output.name not in visited:
                    visited.add(output.name)
                    queue.append((output.name, current_length + 1))
    
    return False



def shortest_path_gates(parser: NetlistParser, s: str, t: str) -> List[str]:
    """
    Returns the list of gates in the shortest directed path from gate s to gate t.
    If no path exists, returns an empty list.
    """
    if s not in parser.gates or t not in parser.gates:
        return []  # Either start or target gate does not exist
    
    queue = deque([s])
    visited = {s}
    parent = {s: None}  # Keep track of the parent gate for path reconstruction
    
    while queue:
        current = queue.popleft()
        
        if current == t:
            # Reconstruct the path
            path = []
            while current is not None:
                path.append(current)
                current = parent[current]
            return path[::-1]  # Reverse to get path from s to t
        
        for neighbor in parser.fanout_of(current):
            if neighbor not in visited:
                visited.add(neighbor)
                parent[neighbor] = current
                queue.append(neighbor)
    
    return []  # No path found

class Pattern:
    def __init__(self, dff_name: str, nand_name: str, not_name: str, has_father_yet: bool):
        self.dff_name = dff_name
        self.nand_name = nand_name
        self.not_name = not_name

class Pattern1: 
    def __init__(self, dff_name: str, and_name: str, has_father_yet: bool):
        self.dff_name = dff_name
        self.and_name = and_name
        self.has_father_yet = has_father_yet

def does_have_trojan1(target_file: str) -> List:
    
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)

    reset_signal = list(find_reset_signals(parser))[0] if find_reset_signals(parser) else None

    def has_non_trojan_not_input(gate_name: str, parser: NetlistParser) -> None:
        gate = parser.get_gate(gate_name)
        for input_gate in gate.inputs:
            if input_gate not in parser.gates:
                continue
            if parser.get_gate(input_gate).gate_type == "not" and input_gate not in trojan_gates:
                trojan_gates.append(input_gate)
                has_non_trojan_not_input(input_gate, parser)
        return

    reset_signal = list(find_reset_signals(parser))[0] if find_reset_signals(parser) else None
    # mx = 4  # maximum length of the path to search
    # # mx = 10  # maximum length of the path to search (set to 10 to test)
    patterns = []
    
    visited = set()
    def returns_to_itself(gate, main_gate_name):
        # Check if any output of the gate feeds back into its input (dfs)
        if gate.name in visited:
            return gate.name == main_gate_name
        visited.add(gate.name)
        for output in gate.outputs:
            if returns_to_itself(output, main_gate_name):
                return True
        return False

    def find_if_last_dff(gate):
        if '[' in gate.output_net:
            return False
        if returns_to_itself(gate, gate.name):
            visited.clear()
            return True
        visited.clear()
        return False

    last_dff = None
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        is_pattern = False
        if gate.gate_type == "dff":
            is_pattern = find_if_last_dff(gate)
            last_dff = gate if is_pattern else last_dff
            if is_pattern:
                break

    if last_dff is None:
        return [[], False]
    
    def traverse_to_find_trojan_gates(gate_name):
        if gate_name in trojan_gates:
            return
        if parser.get_gate(gate_name).gate_type == 'not':
            if '[' in parser.get_gate(gate_name).input_nets[0] or parser.get_gate(gate_name).input_nets[0] == reset_signal:
                return
        trojan_gates.append(gate_name)
        gate = parser.get_gate(gate_name)
        for input_gate in gate.inputs:
            if input_gate in parser.gates:
                if '[' not in parser.get_gate(input_gate).output_net:
                    traverse_to_find_trojan_gates(input_gate)
                elif parser.get_gate(input_gate).gate_type == 'dff':
                    traverse_to_find_trojan_gates(input_gate)

    traverse_to_find_trojan_gates(last_dff.name)

    num_dff_in_trojan = 0
    for gate_name in trojan_gates:
        if parser.get_gate(gate_name).gate_type == 'dff':
            num_dff_in_trojan += 1
    if len(trojan_gates) > 15 and len(trojan_gates) < 50 and num_dff_in_trojan * 3 < len(trojan_gates):
        return [trojan_gates, True]
    return [[], False]

        
    all_our_not_gates = [p.not_name for p in patterns if p.not_name is not None]
    #all_our_nand_gates = [p.nand_name for p in patterns if p.nand_name is not None]
    all_our_dff_gates = [p.dff_name for p in patterns if p.dff_name is not None]

    for not_gate in all_our_not_gates:
        for dff_gate in all_our_dff_gates:
            if has_directed_path(not_gate, dff_gate, 10, parser):
                path = shortest_path_gates(parser, not_gate, dff_gate)
                for gate_in_path in path:
                    if gate_in_path not in trojan_gates:
                        trojan_gates.append(gate_in_path)

    for trojan_gate in trojan_gates:
        #inputs = parser.get_gate(trojan_gate).inputs
        has_non_trojan_not_input(trojan_gate, parser)
            #if q_output.gate_type == "nand":
    for trojan_gate in trojan_gates:
        if parser.get_gate(trojan_gate).gate_type == "not" and parser.get_gate(trojan_gate).input_net == reset_signal:
            #remove the not gate from trojan_gates
            trojan_gates.remove(trojan_gate)

    
    # print ("number of patterns found:", len(patterns))
    # for i, pattern in enumerate(patterns):
    #     print (f"Pattern {i+1}: DFF: {pattern.dff_name}, NAND: {pattern.nand_name}, NOT: {pattern.not_name}")
    
    if len(patterns) <= 3:
        return [[], False]
    
    flag = 0
    for i, pattern in enumerate(patterns):
        not_gate = parser.get_gate(pattern.not_name)
        outputs = not_gate.outputs
        if (len(outputs) < 2):
            flag += 1

    if flag > 1:
        return [[], False]
    
    return [trojan_gates, True]