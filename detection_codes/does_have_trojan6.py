import re
from collections import defaultdict
from typing import List
from utils.exploit_gates2 import NetlistParser


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

def does_have_trojan6(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)
    calculated_dfs = {}
    signals = parse_verilog_signals(open(target_file).read())
    signals_dict = signals_to_dict(signals)

    # Find a nor gate with 2 or gates in its outputs
    main_nor = None
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        it_is_not = False
        
        if gate.gate_type != "nor" or len(gate.outputs) != 2:
            continue
        for out in gate.outputs:
            if out.gate_type != "or":
                it_is_not = True
                break
        if not it_is_not:
            main_nor = gate
            break
    
    if main_nor is None:
        return [[], False]
    
    #trojan_gates.append(main_nor.name)
    for out in main_nor.outputs:
        trojan_gates.append(out.name)
    
    # Explore fanin cone of the main_nor until reaching '[' in the input net names or reaching not gate
    visited = set()

    def mark_trojan_fanin(gate_name: str):
        gate = parser.get_gate(gate_name)
        visited.add(gate_name)
        trojan_gates.append(gate_name)
        for input in gate.inputs:
            input_gate = parser.get_gate(input)
            if input_gate is None:
                continue
            if '[' in input_gate.output_net:
                continue
            if input_gate.gate_type == 'not':
                visited.add(input_gate.name)
                trojan_gates.append(input_gate.name)
                continue
            if input_gate.name not in visited:
                mark_trojan_fanin(input_gate.name)
    
    mark_trojan_fanin(main_nor.name)
    if len(trojan_gates) < 25:
        return [trojan_gates, False]
    return [trojan_gates, True]