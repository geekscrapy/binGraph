import matplotlib.pyplot as plt
import matplotlib.ticker as ticker


plt.plot([1,2,1,4,5],[1,2,3,4,5], marker='o', label='value 1')
plt.plot([3,1,3,1,2],[1,2,3,4,5], label='value 2')

plt.gca().get_xaxis().set_visible(False)

ax1 = plt.twiny()
ax2 = ax1.twiny()

ax1.set_xlabel('TOP')
ax2.set_xlabel('BOTTOM')

ax1.xaxis.set_label_position('top')
ax2.xaxis.set_label_position('bottom')


ax2.set_visible(False)

ax1.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x%x') % (int(x))))


plt.savefig(fname='test.png')
plt.show()
