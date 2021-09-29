import os, sys, pickle
import numpy as np
from mymodule.sboxes import *

from timeit import default_timer as timer
from datetime import timedelta

from itertools import permutations
perms = tuple([tuple([0] + list(x)) for x in permutations(range(1,8), 7)])

cipher_list = ["PIPO", "FLY"]
pipobp_make = lambda bp:[8*(x//8) + (x + bp[x//8])%8 for x in range(64)] # PIPO (i,j) = bp => (i, j+bp[i]), where (i,j) = x//8, x%8	x=8*i+j
flybp_make = lambda bp:[8*((x//8-bp[x%8])%8) + x%8 for x in range(64)] # FLY (i,j) = bp => (i, j-bp[i]), where (i,j) = x%8, x//8		x=8*j+i

cipher2bp_make = dict(zip(cipher_list, [pipobp_make, flybp_make]))

def finding_bal(monolist, sbox):
	ret = []
	for u in range(1, 1<<sbox.outbit):
		compononet_func = sbox.component(u)
		iscomponentbal = True
		for mono in compononet_func.get_monomials():
			if monolist[mono] == False:
				iscomponentbal = False
				break
		if iscomponentbal:
			ret.append(u)
	return ret

if __name__ == "__main__":
	# 1. Choose Cipher
	print("Write Cipher name : "); cipher_name = input().upper()
	if not cipher_name in cipher_list:
		print("%s is not in cipher_list :"%cipher_name, cipher_list)
		exit()
	else:
		sb = SBOX_DICTIONARY[cipher_name]

 	# 2. from n to m
	print("Write n m ( range(n,m) ). There must be 1 space between n and m.")
	n, m = map(int, input().split())
	
	if not os.path.isdir("result"):
		os.mkdir("result")

	if cipher_name == "PIPO":
		from dp_search.pipo import linear_search
	elif cipher_name == "FLY":
		from dp_search.fly import linear_search

	# 3. Search i-th perm
	for i in range(n,m):
		# 3-1. If already searched, then pass
		if os.path.isfile("result/" + cipher_name + "{0:0>4}".format(i)):
			continue
		# 3-2. If not, then search
		bp = cipher2bp_make[cipher_name](perms[i]) # bitpermutation making

		start = timer() # Start Timer
		if cipher_name == "PIPO":
			rets = linear_search(6, bp, pruning = lambda x: finding_bal(x, sb)) # threshold : 6
		elif cipher_name == "FLY":
			rets = linear_search(6, bp, pruning = lambda x: finding_bal(x, sb)) # threshold : 6
		end = timer() # End Timer
		with open("Running_time.txt", 'a') as f:
			f.write("{0:0>4}-th : ".format(i) + "WorkingTime: {} sec\n".format(timedelta(seconds=end-start)))

		# 4. Store result
		with open("result/" + cipher_name + "{0:0>4}".format(i), 'wb') as ff:
			pickle.dump(rets, ff)
		# with open("main_test", 'wb') as ff:
		# 	pickle.dump(rets,ff)
		if rets[0]: # rets[0] = True : i-th permutation cross the threshold. i.e. excluded case
			pass
		else:
			with open(cipher_name + "_perms.txt", 'a') as f: # write case in the txt-file
				f.write("{0:0>4} ".format(i) + str(perms[i]) + '\n') # line = i perm
