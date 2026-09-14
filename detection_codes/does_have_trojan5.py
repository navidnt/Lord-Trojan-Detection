import re
from collections import defaultdict
from typing import List
from utils.exploit_gates1 import NetlistParser


class Signal:
    def __init__(self, name: str, size: int, sig_type: str):
        self.name = name
        self.size = size
        self.type = sig_type  # "None", "PI", or "PO"

    def __repr__(self):
        return f"Signal(name='{self.name}', size={self.size}, type='{self.type}')"


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*?$", "", text, flags=re.M)
    return text


def parse_range_to_size(range_str: str) -> int:
    m = re.match(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", range_str) if range_str else None
    if not m:
        return 1
    a, b = int(m.group(1)), int(m.group(2))
    return abs(a - b) + 1


def extract_decl_names(decl_body: str):
    parts = [p.strip() for p in decl_body.split(",")]
    names = []
    for p in parts:
        base = re.split(r"\s*\[", p)[0].strip()
        base = re.split(r"\s*=", base)[0].strip()
        if base:
            names.append(base)
    return names


def parse_verilog_signals(text: str):
    clean = strip_comments(text)
    clean = re.sub(r"\s+", " ", clean)

    port_dir_map = {}
    for dir_kw in ["input", "output"]:
        pattern = rf"\b{dir_kw}\b\s+(?:reg\s+|wire\s+)?(?P<range>\[[^\]]+\]\s+)?(?P<names>[^;]+?)\s*;"
        for m in re.finditer(pattern, clean):
            rng = m.group("range")
            size = parse_range_to_size(rng) if rng else 1
            names = extract_decl_names(m.group("names"))
            for nm in names:
                if nm not in port_dir_map:
                    port_dir_map[nm] = (dir_kw, size)

    wire_info = {}
    for m in re.finditer(r"\bwire\b\s+(?P<range>\[[^\]]+\]\s+)?(?P<names>[^;]+?)\s*;", clean):
        rng = m.group("range")
        size = parse_range_to_size(rng) if rng else 1
        names = extract_decl_names(m.group("names"))
        for nm in names:
            prev = wire_info.get(nm)
            if prev is None or size > prev:
                wire_info[nm] = size

    all_names = set(wire_info.keys()) | set(port_dir_map.keys())
    signals = []
    for nm in sorted(all_names):
        if nm in port_dir_map:
            dir_kw, port_size = port_dir_map[nm]
            sig_type = "PI" if dir_kw == "input" else "PO"
            size = max(port_size, wire_info.get(nm, port_size))
        else:
            sig_type = "None"
            size = wire_info.get(nm, 1)
        signals.append(Signal(nm, size, sig_type))

    return signals

def signals_to_dict(signals):
    """
    Convert a list of Signal objects into a dictionary mapping
    signal name -> Signal object.
    """
    return {sig.name: sig for sig in signals}









def does_have_trojan5(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)
    PIs_in_fanin = set()
    size_min = 6


    with open(target_file, "r") as f:
        text = f.read()
    signals = parse_verilog_signals(text)

    # for sig in signals:
    #     print(sig)
    signals_dict = signals_to_dict(signals)
    #print(signals_dict['n1'])

    def find_fanin_nets(gate_name: str) -> bool:
        """
        Find all fanin nets for a given gate name using bfs.
        """
        visited = set()
        queue = [gate_name]
        visited.add(gate_name)
        while queue:
            current_gate_name = queue.pop(0)
            current_gate = parser.get_gate(current_gate_name)
            if not current_gate:
                continue
            if current_gate.gate_type == 'dff': # Skip DFFs, you can add other types if needed
                return False
            inputs = current_gate.inputs
            for input_gate_name in inputs:
                if parser.get_gate(input_gate_name) is None:
                    if input_gate_name[0] != '1':
                        PIs_in_fanin.add(input_gate_name)
                    continue
                
                if input_gate_name not in visited:
                    visited.add(input_gate_name)
                    queue.append(input_gate_name)

        return True
    
    def extract_before_bracket(s: str) -> str:
        if '[' in s:
            return s.split('[', 1)[0]
        return s


    def are_PIs_valid() -> bool:
        """
        Check if all PIs in the fanin of a gate are valid.
        """
        nets_name_set = set()
        nets_set = set()
        for pi in PIs_in_fanin:
            group_of_pi = extract_before_bracket(pi)
            nets_name_set.add(group_of_pi)
            nets_set.add(signals_dict[group_of_pi])
        if len(nets_name_set) != 3:
            return False
        num_of_more_than_min = 0
        num_of_one = 0
        for net in nets_set:
            if net.size > size_min:
                num_of_more_than_min += 1
            if net.size == 1:
                num_of_one += 1
        return num_of_more_than_min == 2 and num_of_one == 1
    
    
    def find_fanin_gates(net_name: str) -> set:
        """
        Find all fanin gates for a given net name using bfs.
        """
        answer = set()
        for i in range(signals_dict[net_name].size):
            new_net_name = f"{net_name}[{i}]"
            if not parser.net_to_drivers[new_net_name]:
                continue
            driver_gate = parser.net_to_drivers[new_net_name]
            driver_gate_name = driver_gate.name
            visited = set()
            queue = [driver_gate_name]
            visited.add(driver_gate_name)
            answer.add(driver_gate_name)
            while queue:
                current_gate_name = queue.pop(0)
                current_gate = parser.get_gate(current_gate_name)
                inputs = current_gate.inputs
                for input_gate_name in inputs:
                    if parser.get_gate(input_gate_name) is None:
                        continue
                    
                    if input_gate_name not in visited:
                        visited.add(input_gate_name)
                        queue.append(input_gate_name)
                        answer.add(input_gate_name)
                        
        return answer
    
    answer_set = set()
    all_gates_in_fanin = set()
    min_num_of_gates_in_fanin = -1
    for signal in signals:
        net_name = signal.name
        if signals_dict[net_name].size < size_min:
            continue
        # Process the signal
        PIs_in_fanin = set()
        for i in range(signals_dict[net_name].size):
            new_net_name = f"{net_name}[{i}]"
            if not parser.net_to_drivers[new_net_name]:
                continue
            driver_gate = parser.net_to_drivers[new_net_name]
            driver_gate_name = driver_gate.name
            can_be = find_fanin_nets(driver_gate_name)
            if not can_be:
                break
        # if not can_be:
        #     continue
        if not are_PIs_valid():
            continue
        answer_set.add(net_name)
        all_gates_in_fanin_copy = find_fanin_gates(net_name)
        if min_num_of_gates_in_fanin == -1 or len(all_gates_in_fanin_copy) < min_num_of_gates_in_fanin:
            min_num_of_gates_in_fanin = len(all_gates_in_fanin_copy)
            all_gates_in_fanin = all_gates_in_fanin_copy
            # print(f'found a new min: {net_name}')
        # print (len(all_gates_in_fanin_copy), net_name)
        


    # for net_name in sorted(answer_set):
        # print(f"Valid net: {net_name} with size {signals_dict[net_name].size}")

    for gate_name in all_gates_in_fanin:
        trojan_gates.append(gate_name)

    if len(trojan_gates) > 0:
        return [trojan_gates, True]
    else:
        return [[], False]