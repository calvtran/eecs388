#!/usr/bin/python3
# coding: latin-1
blob = """                 i1QM}�u��.�׹��Q ��;�������|���k ���U�)���of^5�^ݘ{� �1����P�3�	�Oa��^�P]":��`&`��ӕ�C�E�<6���{���z��z��Gg1�S���"""
from hashlib import sha256
print(sha256(blob.encode("latin-1")).hexdigest())