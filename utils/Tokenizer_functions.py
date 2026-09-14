

def extract_trojan_gates(filename):
    trojan_gates = []
    inside_block = False

    with open(filename, 'r') as file:
        for line in file:
            stripped = line.strip()
            if stripped == "TROJAN_GATES":
                inside_block = True
                continue
            if stripped == "END_TROJAN_GATES":
                break
            if inside_block:
                trojan_gates.append(stripped)

    return trojan_gates