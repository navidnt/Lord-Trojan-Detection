import re
from collections import defaultdict
from typing import List
from utils.exploit_gates3 import NetlistParser

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


def does_have_trojan3(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)
    signals = parse_verilog_signals(open(target_file).read())
    signals_dict = signals_to_dict(signals)

    # print(signals_dict['n13'])
    possible_output_signals = set()
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type != "dff":
            continue
        sn_gate_name = gate.inputs[1]
        rn_gate_name = gate.inputs[0]
        sn_gate = parser.get_gate(sn_gate_name)
        rn_gate = parser.get_gate(rn_gate_name)
        if sn_gate == None or rn_gate == None:
            continue
        sn_gate_inputs = set(sn_gate.input_nets)
        rn_gate_inputs = set(rn_gate.input_nets)
        intersection = sn_gate_inputs.intersection(rn_gate_inputs)
        # if gate_name == 'g89':
        #     print(sn_gate_inputs)
        #     print(rn_gate_inputs)
        #     print(intersection)
        #     print("Found gate g89")
        inside = None
        for inter in intersection:
            match = re.search(r"\[(.*?)\]", inter)
            if match:
                inside = match.group(1)
            else:
                continue
        if inside == None:
            continue
        q_net = gate.q_net.split('[', 1)[0]
        inside_q = None
        match_q = re.search(r"\[(.*?)\]", gate.q_net)
        if match_q:
            inside_q = match_q.group(1)

        if len(sn_gate_inputs) == 2 and len(rn_gate_inputs) == 2 and inside == inside_q:
            #print(q_net)
            possible_output_signals.add(q_net)
    
    if len(possible_output_signals) == 0:
        return [[], False]
    main_output_signal = list(possible_output_signals)[0]
    # print(main_output_signal)
    final_dffs = []
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type == "dff":
            if gate.q_net.split('[')[0] == main_output_signal:
                final_dffs.append(gate_name)
    # print(final_dffs)
    reset_signal = None
    sample_final_dff = parser.get_gate(final_dffs[0])
    reset_gate_name = sample_final_dff.inputs[0]
    reset_gate = parser.get_gate(reset_gate_name)
    if reset_gate == None:
        reset_signal = reset_gate_name
    else:
        queue = [reset_gate]
        while queue:
            current_gate = queue.pop(0)
            for input_name, input_gate_name in zip(current_gate.input_nets, current_gate.inputs):
                if '[' in input_name:
                    continue
                if signals_dict[input_name].type == "PI":
                    reset_signal = input_name
                    queue = []
                    break
                input_gate = parser.get_gate(input_gate_name)
                if input_gate and input_gate not in queue:
                    queue.append(input_gate)
    if reset_signal == None:
        return [[], False]
    input_signal = None
    queue = [reset_gate]
    while queue:
        current_gate = queue.pop(0)
        for input_name, input_gate_name in zip(current_gate.input_nets, current_gate.inputs):
            if '[' in input_name:
                input_signal = input_name.split('[')[0]
                queue = []
                break
            input_gate = parser.get_gate(input_gate_name)
            if input_gate and input_gate not in queue:
                queue.append(input_gate)
    if input_signal == None:
        return [[], False]
    
    trojan_gates = final_dffs.copy()
    for dff_name in final_dffs:
        dff_gate = parser.get_gate(dff_name)
        queue = [dff_gate.name]
        while queue:
            
            current_gate_name = queue.pop(0)
            current_gate = parser.get_gate(current_gate_name)
            for input_name, input_gate_name in zip(current_gate.input_nets, current_gate.inputs):
                # if dff_name == 'g26':
                #     print(input_name, input_gate_name)
                if input_name == reset_signal:
                    continue
                if '[' in input_name:
                    if input_name.split('[')[0] == input_signal:
                        continue
                    if signals_dict[input_name.split('[')[0]].type == "PI":
                        continue
                input_gate = parser.get_gate(input_gate_name)
                if not input_gate:
                    continue
                if input_gate.name not in trojan_gates:
                    if input_gate.name not in queue:
                        trojan_gates.append(input_gate.name)
                        queue.append(input_gate.name)

    # added this to avoid abnormally large trojans (remove if needed)
    if len(trojan_gates) > 1000:
        return [[], False]
    ##################################
    return [trojan_gates, True]