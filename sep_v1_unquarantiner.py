"""
SEP unquarantiner for VBN v1.
"""


__author__ = "Nino '@gibbersen' Pellegrino"


import os
import zipfile
import argparse
import sys
import pyminizip


def parse_arguments():
	# setting the command line parser
	parser = argparse.ArgumentParser(description="SEP Unquarantiner, a tool to unquarantine SEP samples in version 1. By Nino '@gibbersen' Pellegrino.")
	parser.add_argument("FILE", type=str, help="vbn file path")
	parser.add_argument("-o", type=str, help="path where to store the unquarantined file")	
	return parser.parse_args()


def compress(in_memory, path):
	# currently there is no way to zip-compress an in-memory file with Python.
	# I use a workaround that could not work in every case.
	# ------------------------------------------------------------------------
	# first we store the unquarantined file on disk, 
	# hoping the antivirus is not so fast in detecting and quarantining it
	plain = "unquarantined"
	with open(plain, "wb") as qrn:
		qrn.write(in_memory)
	# now we compress it with password "infected"
	pyminizip.compress(plain, ".", path, "infected", 0)
	# now we remove the temporary plain unquarantined file
	os.remove(plain)


def xor(data, key):
    for i in range(len(data)):
        data[i] ^= key
    return data


def decrypt(path):
	# get the unquarantined file size
	size = os.path.getsize(path) - 0xE68
	decrypted = None
	with open(path, "rb") as vbn:
		# go to the actual file start
		vbn.seek(0xE68)
		# read the encrypted original file
		encrypted = bytearray(vbn.read(size))
		# deencrypt the unquarantined file
		decrypted = xor(encrypted, 0x5A)
	return decrypted


def main():
	args = parse_arguments()
	if not os.path.exists(args.FILE) or not os.path.isfile(args.FILE):
		print("The provided vbn dile does not exist or it is invalid.")
		sys.exit(2)
	if args.o is None:
		fname = os.path.splitext(args.FILE)[0]
		args.o = fname + ".zip"
	unquarantined = decrypt(args.FILE)
	compress(unquarantined, args.o)
	print("The unquarantined file is ready (zip pass: 'infected').")


if __name__ == "__main__":
    main()	