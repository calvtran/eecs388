#!/usr/bin/python3
# coding: latin-1
blob = """                 i1QM}�u��.�׹��� ��;�������|���k �����)���of^5�^]�{� �1����P�3�	�Oa��^MP]":��`&`��ӕ�C�E�<6���{T��z��z��Gg1�����"""
from hashlib import sha256
print(sha256(blob.encode("latin-1")).hexdigest())