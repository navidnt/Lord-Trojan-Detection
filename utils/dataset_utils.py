import re
from collections import defaultdict
from typing import List
from transformers import BertTokenizerFast
from utils.exploit_gates import NetlistParser
from torch.utils.data import Dataset
from dataclasses import dataclass
import torch

MAX_LEN = 512
PAD_TOKEN = "[PAD]"

@dataclass
class GateEntry:
    gate_name: str
    tokens: List[str]
    label: int  # 1 if Trojan, 0 if normal

tokenizer = BertTokenizerFast.from_pretrained("bert-base-uncased")
custom_tokens = ['DFF', 'X', 'AND', 'OR', 'NOT', '[PAD]', '[SEP]']
tokenizer.add_tokens(custom_tokens)

def build_dataset(parser, trojan_gate_names: set = None) -> List[GateEntry]:
    dataset = []
    for gate_name in parser.gates:
        tokens = tokenize_gate_fanin_cone_parser(parser, gate_name)
        # Pad or truncate to MAX_LEN
        if len(tokens) > MAX_LEN:
            tokens = tokens[:MAX_LEN]
        else:
            tokens += [PAD_TOKEN] * (MAX_LEN - len(tokens))
        label = 1 if trojan_gate_names and gate_name in trojan_gate_names else 0
        dataset.append(GateEntry(gate_name=gate_name, tokens=tokens, label=label))
    return dataset

def encode_dataset(dataset: List[GateEntry], tokenizer, max_length=20):
    token_texts = [" ".join(entry.tokens) for entry in dataset]
    labels = [entry.label for entry in dataset]

    encodings = tokenizer(
        token_texts,
        padding='max_length',
        truncation=True,
        max_length=max_length,
        return_tensors='pt'
    )
    label_tensor = torch.tensor(labels)
    return torch.utils.data.TensorDataset(
        encodings['input_ids'], encodings['attention_mask'], label_tensor
    )

def build_dataset_from_file(parser, is_trojan: bool) -> List[GateEntry]:
    dataset = []
    label = 1 if is_trojan else 0
    for gate_name in parser.gates:
        tokens = tokenize_gate_fanin_cone_parser(parser, gate_name)
        # Pad or truncate to MAX_LEN
        if len(tokens) > MAX_LEN:
            tokens = tokens[:MAX_LEN]
        else:
            tokens += [PAD_TOKEN] * (MAX_LEN - len(tokens))
        dataset.append(GateEntry(gate_name=gate_name, tokens=tokens, label=label))

    return dataset

def tokenize_gate_fanin_cone_parser(parser, gate_name: str, max_depth=6) -> List[str]:
    tokens = []

    def traverse(name, depth):
        if depth > max_depth:
            return
        gate = parser.get_gate(name)
        if not gate:
            tokens.append('X')
            return
        tokens.append(gate.gate_type.upper())
        for input_net in gate.inputs:
            if input_net in parser.gates:
                traverse(input_net, depth + 1)
            else:
                tokens.append('X')
    traverse(gate_name, 0)
    return tokens

# Create Dataset Class for Hugging Face Trainer
class GateDataset(Dataset):
    def __init__(self, dataset):
        self.input_ids = dataset.tensors[0]
        self.attention_mask = dataset.tensors[1]
        self.labels = dataset.tensors[2]

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            'input_ids': self.input_ids[idx],
            'attention_mask': self.attention_mask[idx],
            'labels': self.labels[idx]
        }

import csv

def export_to_csv(dataset: List[GateEntry], filename: str):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['gate_name', 'label', 'tokens'])
        for entry in dataset:
            writer.writerow([entry.gate_name, entry.label, " ".join(entry.tokens)])