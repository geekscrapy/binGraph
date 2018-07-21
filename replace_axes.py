import matplotlib.pyplot as plt
import matplotlib.ticker as ticker


fig, host = plt.subplots()


host.plot([1,2,1,4,5],[1,2,3,4,5], marker='o', label='value 1')
host.plot([3,1,3,1,2],[1,2,3,4,5], label='value 2')

host.set_xlim([2, 6])
host.set_ylim([0, 6])


plt.savefig(fname='test.png')
plt.show()
