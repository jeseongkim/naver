# ========================================================================
from timeit import default_timer as timer
from datetime import timedelta
from dp_search.pipo import linear_search
from itertools import permutations
import pickle
perms = tuple([tuple([0] + list(x)) for x in permutations(range(1,8), 7)])
pipobp_make = lambda bp:[8*(x//8) + (x + bp[x//8])%8 for x in range(64)] # PIPO (i,j) = bp => (i, j+bp[i]), where (i,j) = x//8, x%8	x=8*i+j


# code 1
# for i in range(0,5):
# 	start = timer()
# 	ret = linear_search(6, pipobp_make(perms[i]))
# 	end = timer()
# 	print("WorkingTime: {} sec".format(timedelta(seconds=end-start)))
# 	with open("timetest.txt", 'a') as f:
# 		f.write("WorkingTime: {} sec\n".format(timedelta(seconds=end-start)))
# 	with open("result/result{0:0>4}".format(i), 'wb') as f:
# 		pickle.dump(ret, f)

start = timer()
BP=	[  	0,  1,  2,  3,  4,  5,  6,  7,
   15,  8,  9, 10, 11, 12, 13, 14,
   20, 21, 22, 23, 16, 17, 18, 19,
   27, 28, 29, 30, 31, 24, 25, 26,
   38, 39, 32, 33, 34, 35, 36, 37,
   45, 46, 47, 40, 41, 42, 43, 44,
   49, 50, 51, 52, 53, 54, 55, 48,
   58, 59, 60, 61, 62, 63, 56, 57]
from dp_search.pipo import linear_search_validtest
ret = linear_search_validtest(6,BP)
with open("result/validtest", 'wb') as f:
	pickle.dump(ret, f)
end = timer()
with open("timetest.txt", 'a') as f:
	f.write("valid : " + "WorkingTime: {} sec\n".format(timedelta(seconds=end-start)))
# ========================================================================