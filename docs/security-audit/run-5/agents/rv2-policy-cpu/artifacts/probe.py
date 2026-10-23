import asyncio, time, threading, statistics
from agentbox.policy import Policy
p = Policy.load('/target/agentbox/default_policy.yaml')
cmd='x;'*16384
async def probe():
    lat=[]
    for _ in range(30):
        t=time.perf_counter()
        x=0
        for i in range(20000): x+=i
        await asyncio.sleep(0.001)
        lat.append((time.perf_counter()-t)*1000)
    return statistics.median(lat), max(lat)
async def run(n):
    ths=[threading.Thread(target=lambda: p.decide('exec',{'command':cmd})) for _ in range(n)]
    for t in ths: t.start()
    r=await probe()
    for t in ths: t.join()
    return r
for n in (0,1,4,0):
    print(n, [round(v,1) for v in asyncio.run(run(n))])
