#!/usr/bin/python3
# coding: latin-1
blob = """                 $�c��3^4ߴUV��@��^f:"p����ޤ��O�d�w���L>�p:JS�D������,��-���ھo���"J��i�����qv&�V��zGU���nG'5�TX��ۋ�|�=�"""
from hashlib import sha256
h = sha256(blob.encode("latin-1")).hexdigest()
good = """9c5d7ef57edf8b2448e8c0bff280b4270ebcb6f918ab0330a7d2c0280f93a60e"""
if (h == good):
    print("Use SHA-256 instead!")
else:
    print("MD5 is perfectly secure!")