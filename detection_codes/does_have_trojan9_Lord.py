import re
from collections import defaultdict
from typing import List
from utils.exploit_gates2 import NetlistParser
from utils.exploit_gates2 import transform_and_parse_with_originals


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


def does_have_trojan9(target_file: str) -> List:
    trojan_gates = []
    trojan_gates_set = set()

    new_parser = NetlistParser()
    new_parser.parse_netlist(target_file)

    with open(target_file, "r") as f:
        text = f.read()
    signals = parse_verilog_signals(text)
    signal_dict = signals_to_dict(signals)

    def find_fanin_cone(gate_name: str) -> set:
        """
        Find the fanin cone of a gate until primary inputs or a dff using bfs.
        """
        gate = new_parser.get_gate(gate_name)
        fanin_inputs = set()
        queue = [gate]
        visited = set()
        visited.add(gate.name)
        while queue:
            current_gate = queue.pop(0)
            inputs = current_gate.inputs
            if current_gate.gate_type == 'dff':
                fanin_inputs.add(current_gate.output_net.split('[')[0])
                continue
            for input_name in inputs:
                driver_gate = new_parser.get_gate(input_name)
                if driver_gate is None:
                    # print (input_name)
                    if input_name[0] != '1':
                        if signal_dict[input_name.split('[')[0]].size > 1 and signal_dict[input_name.split('[')[0]].size <= 3:
                            fanin_inputs.add(input_name)
                        else:
                            fanin_inputs.add(input_name.split('[')[0])

                else:
                    if driver_gate.name not in visited:
                        queue.append(driver_gate)
                        visited.add(driver_gate.name)
        return fanin_inputs

    def find_whole_fanin_cone(gate_name: str) -> set:
        """
        Find the fanin cone of a gate until primary inputs or a dff using bfs.
        """
        gate = new_parser.get_gate(gate_name)
        fanin_inputs = set()
        queue = [gate]
        visited = set()
        visited.add(gate.name)
        while queue:
            current_gate = queue.pop(0)
            inputs = current_gate.inputs
            if current_gate.gate_type == 'dff':
                fanin_inputs.add(current_gate.output_net.split('[')[0])
                continue
            for input_name in inputs:
                driver_gate = new_parser.get_gate(input_name)
                if driver_gate is None:
                    # print (input_name)
                    if input_name[0] != '1':
                        if signal_dict[input_name.split('[')[0]].size > 1 and signal_dict[input_name.split('[')[0]].size <= 3:
                            fanin_inputs.add(input_name)
                        else:
                            fanin_inputs.add(input_name.split('[')[0])

                else:
                    if driver_gate.name not in visited:
                        queue.append(driver_gate)
                        visited.add(driver_gate.name)
        return visited

    ans = 0
    eligible_outputs = []
    for gate_name in new_parser.gates:
        gate = new_parser.get_gate(gate_name)
        gate_outputs = gate.outputs
        if gate.gate_type != 'dff':
            brackets = set()
            num_of_big = 0
            fanin_inputs = find_fanin_cone(gate_name)
            if len(fanin_inputs) >= 5 and len(fanin_inputs) <= 25:
                for net in fanin_inputs:
                    if '[' in net:
                        brackets.add(net.split('[')[0])
                if len(brackets) > 2:
                    continue
                if '[' not in gate.output_net:
                    continue
                if signal_dict[gate.output_net.split('[')[0]].size > 64:
                    continue
                eligible_outputs.append(gate_name)
                ans += 1

    if ans < 4:
        return [[], False]
   
    eligible_gates = set()
    for gate_name in eligible_outputs:
        add_set = find_whole_fanin_cone(gate_name)
        eligible_gates.update(add_set)

    real_eligible_gates = set()
    for gate_name in eligible_gates:
        if '[' in gate_name:
            real_eligible_gates.add(gate_name.split('[')[0])
        else:
            real_eligible_gates.add(gate_name)

    does_exist = True
    if len(real_eligible_gates) == 0:
        does_exist = False
    trojan_gates = list(real_eligible_gates)
    return [trojan_gates, does_exist]