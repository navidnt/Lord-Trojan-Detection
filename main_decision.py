#!/usr/bin/env python3
import argparse
import random
from collections import defaultdict
from typing import List
import sys
import os


from utils.exploit_gates1 import NetlistParser
from detection_codes.does_have_trojan0 import does_have_trojan0
from detection_codes.does_have_trojan4 import does_have_trojan4
from detection_codes.does_have_trojan5 import does_have_trojan5
from detection_codes.does_have_trojan2 import does_have_trojan2
from detection_codes.does_have_trojan1 import does_have_trojan1
from detection_codes.does_have_trojan7 import does_have_trojan7
from detection_codes.does_have_trojan6 import does_have_trojan6
from detection_codes.does_have_trojan3 import does_have_trojan3
from detection_codes.does_have_trojan9 import does_have_trojan9



def does_have_any_trojan(target_file) -> List:
    Trojan_number_found = -1
    [trojan_gates, does_exist] = does_have_trojan0(target_file)
    if does_exist:
        Trojan_number_found = 0
    if not does_exist:
        [trojan_gates, does_exist] = does_have_trojan1(target_file)
        if does_exist:
            Trojan_number_found = 1
        if not does_exist:
            [trojan_gates, does_exist] = does_have_trojan2(target_file)
            if does_exist:
                Trojan_number_found = 2
            if not does_exist:
                [trojan_gates, does_exist] = does_have_trojan4(target_file)
                if does_exist:
                    Trojan_number_found = 4
                if not does_exist:
                    [trojan_gates, does_exist] = does_have_trojan5(target_file)
                    if does_exist:
                        Trojan_number_found = 5
                    if not does_exist:
                        [trojan_gates, does_exist] = does_have_trojan7(target_file)
                        if does_exist:
                            Trojan_number_found = 7
                        if not does_exist:
                            [trojan_gates, does_exist] = does_have_trojan3(target_file)
                            if does_exist:
                                Trojan_number_found = 3
                            if not does_exist:
                                [trojan_gates, does_exist] = does_have_trojan6(target_file)
                                if does_exist:
                                    Trojan_number_found = 6
                                if not does_exist:
                                    [trojan_gates, does_exist] = does_have_trojan9(target_file)
                                    if does_exist:
                                        Trojan_number_found = 9                            
                                
    return [trojan_gates, does_exist, Trojan_number_found]


def main():
    parser = argparse.ArgumentParser(description="Hardware Trojan Detection Inference Script")
    parser.add_argument("-netlist", required=True, help="Path to the input flattened Verilog netlist")
    parser.add_argument("-output", required=True, help="Path to the output result file")
    
    args = parser.parse_args()


    if not os.path.isfile(args.netlist):
        print(f"Error: Input netlist '{args.netlist}' does not exist.")
        sys.exit(1)

    trojan_gates, does_exist, trojan_number = does_have_any_trojan(args.netlist)

    with open(args.output, "w") as f:
        if does_exist:
            f.write("TROJANED\n")
            f.write("TROJAN_GATES\n")
            for gate in trojan_gates:
                f.write(f"{gate}\n")
            f.write("END_TROJAN_GATES\n")
        else:
            f.write("NO_TROJAN\n")


if __name__ == "__main__":
    main()



