# fortune cookies

import random

fck = ['2021 will **** less...',
       '"Youre not allowed to say this, but...", is usually the preamble for something pretty pretty stupid which is coming next.',
       '...',
       'the plot thickens',
       'just grabbing some b33rs'
	   'it just had to happen in 2023'
       ]


def rnd_fck():
    nxt_fck = random.choice(fck)
    return nxt_fck
