import  threading
from multiprocessing.dummy import Pool
from multiprocessing import Manager
import random
from Constant import BLACK_LIST as d
import json


d = dict()
class P():
    def __init__(self):
        self.d = {}
    def check(x):
        if x in self.d:
            self.d[x] = self.d[x] + 1
        else:
            self.d[x] = 1



def tt(asddsa):
#    lock.acquire()
    return 123
  #  lock.release()


def test2(x):
    if x in d:
        d[x] = d[x] + 1
    else:
        d[x] = 1
    with open('dict.json','w') as fp:
        json.dump(d,fp)
    



if __name__ == "__main__":
    # t = Test()
    # t.start()
    # print("End")
    m = Manager()
    a = m.dict()
    lock = m.Lock()
	
    pool = Pool(processes=10)
    p = P()
    while True: 
        r = pool.apply_async(tt,args=(666,),callback = test2)
        print(d)
#    pool.close
    print("END")
