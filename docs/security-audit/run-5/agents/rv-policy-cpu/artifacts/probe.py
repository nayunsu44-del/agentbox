import sys; sys.path.insert(0,"/target")
import asyncio, threading, time, statistics
from agentbox.policy import Policy
P=Policy.load('/target/agentbox/default_policy.yaml')
cmd='x;'*16384
async def probe():
    lat=[]
    for _ in range(30):
        s=time.perf_counter(); x=0
        for i in range(20000): x+=i
        await asyncio.sleep(0.001); lat.append((time.perf_counter()-s)*1000)
    return statistics.median(lat), max(lat)
async def run(nth):
    ths=[threading.Thread(target=lambda:P.decide('exec',{'command':cmd})) for _ in range(nth)]
    for t in ths: t.start()
    r=await probe()
    for t in ths: t.join()
    return r
for n in (0,1,4):
    print(n, "median/max ms %.1f %.1f"%asyncio.run(run(n)))
