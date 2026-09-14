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


def find_next_dff_in_fanout(parser: NetlistParser, gate_name: str) -> str:
    gate = parser.get_gate(gate_name)
    if len(gate.outputs) != 1:
        return None
    for output in gate.outputs:
        if output.gate_type == "dff":
            return output.name
        dff = find_next_dff_in_fanout(parser, output.name)
        if dff is not None:
            return dff
    return None
    


def does_have_trojan2(target_file: str) -> List:

    signals = parse_verilog_signals(open(target_file).read())
    signals_dict = signals_to_dict(signals)

    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)

    visited_signals = set()

    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type != "dff":
            continue
        if '[' not in gate.output_net:
            continue
        signal_name = gate.output_net.split('[')[0]
        if signal_name in visited_signals:
            continue
        visited_signals.add(signal_name)
        if signals_dict[signal_name].size != 8:
            continue
        number_of_dffs_with_this_signal = 0
        dffs_with_this_signal = []
        for gate_name2 in parser.gates:
            gate2 = parser.get_gate(gate_name2)
            if gate2.gate_type != "dff":
                continue
            if gate2.output_net.startswith(signal_name + '['):
                number_of_dffs_with_this_signal += 1
                dffs_with_this_signal.append(gate_name2)
        if number_of_dffs_with_this_signal != 8:
            continue

        main_dff = find_next_dff_in_fanout(parser, gate_name)
        if main_dff == None:
            continue
        if '[' in parser.get_gate(main_dff).output_net:
            continue
        flag = True
        for dff_name in dffs_with_this_signal:
            dff = find_next_dff_in_fanout(parser, dff_name)
            if dff == None or dff != main_dff:
                flag = False
                break
        if not flag:
            continue
        # if we reach here, we found a trojan
        # print (signal_name)
        signals_to_begin = []
        for dff_name in dffs_with_this_signal:
            dff = parser.get_gate(dff_name)
            signals_to_begin.append(dff.input_nets[3])
        
        # Mark all gates that are in a path betwween these signals and the main_dff
        gates_with_signal = []
        for sig in signals_to_begin:
            for gate_name3 in parser.gates:
                gate3 = parser.get_gate(gate_name3)
                if sig in gate3.input_nets:
                    gates_with_signal.append(gate_name3)
        # backward bfs from main_dff to these gates
        queue = [main_dff]
        while queue:
            current_gate_name = queue.pop(0)
            if current_gate_name in trojan_gates:
                continue
            trojan_gates.append(current_gate_name)
            # if current_gate_name in gates_with_signal:
            #     continue
            current_gate = parser.get_gate(current_gate_name)
            if current_gate.gate_type == "dff":
                input_gate_name = current_gate.inputs[3]
                if parser.get_gate(input_gate_name) is not None:
                    if parser.get_gate(input_gate_name).output_net in signals_to_begin:
                        continue
                    queue.append(input_gate_name)
            else:
                for input_gate_name in current_gate.inputs:
                    if parser.get_gate(input_gate_name) is not None:
                        if parser.get_gate(input_gate_name).output_net in signals_to_begin:
                            continue
                        queue.append(input_gate_name)
        # print (f"Main_dff: {main_dff}")
        # print (f"signal_name: {signal_name}")
        # print (f"signals_to_begin: {signals_to_begin}")

    # print (signals_dict['n47'])
    # print (f"visited_signals: {visited_signals}")
    if len(trojan_gates) > 0:
        return (trojan_gates, True)
    return ([], False)



