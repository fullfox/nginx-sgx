#!/usr/bin/env python

import sys
import json
import pandas as pd
import seaborn as sb
import numpy as np
import scipy as sp
import matplotlib.pyplot as plt


# HTTP status considered as a valid response
accepted_http_status = [200, 400, 401, 404]

max_delay = 1000 # ms

theory_req_per_sec = [] # theoric rps, as coded in k6 script
data = {}

# All points with the same rps tag value should have the same duration tag value

# Looping and parsing over the JSON file
with open(sys.argv[1],"r") as f:
    for line in f:
        item = json.loads(line)
        if item["type"] == "Point":
            if item["metric"] == "http_req_duration":
                rps = int(item["data"]["tags"]["rps"])
                if rps not in data:
                    theory_req_per_sec.append(rps)
                    data[rps] = {"delay":[], "duration":[], "loss": 0}
                    data[rps]["duration"] = int(item["data"]["tags"]["duration"])
                if int(item["data"]["tags"]["status"]) not in accepted_http_status: # loss
                    data[rps]["loss"] = data[rps]["loss"] + 1
                else:
                    data[rps]["delay"].append(item["data"]["value"])

# Rates
req_per_sec = [round((len(data[p]["delay"]) + data[p]["loss"])/data[p]["duration"],1) for p in data]
 # (nb_reponse_valide + nb_req_loss)/durée_totale_runtime, arrondis à 1decimale
 # actual injected rps rate

resp_per_sec = [round(len(data[p]["delay"])/data[p]["duration"],1) for p in data]
 # (nb_reponse_valide)/durée_totale_runtime, arrondis à 1decimale
 # actual received rps rate

error_rate = (100 - 100*np.array(resp_per_sec)/np.array(req_per_sec))


# Stats en CLI
for rps in data:
    if len(data[rps]["delay"]) == 0:
        print(rps, "loss 100%")
    else:
        d = data[rps]["delay"]
        print("rps="+str(rps), "  avg=", np.mean(d),"  med=", np.percentile(d, 50),"  min=",np.min(d),"  max=",np.max(d), "  p(95)=", np.percentile(d, 95),
        "  loss=", data[rps]["loss"], "(", 100*data[rps]["loss"]/(len(data[rps]["delay"]) + data[rps]["loss"]) , "%)\n")


# Let's build an array for delay plotting
# Explication: .boxplot requiert une matrice rectangulaire, hors pour chaques colonnes (rps) on a un nombre différents de requetes réalisé.
# Donc on construit une matrice rectangulaire et on bouche les trous avec des NaN.
max_len_sample = 0
for p in data:
    max_len_sample = max(max_len_sample, len(data[p]["delay"]))
delays = np.zeros((len(data), max_len_sample))*np.nan
i = 0
for p in data:
    for j in range(len(data[p]["delay"])):
        delays[i][j] = data[p]["delay"][j]
    i = i + 1



# Let's plot

# delays vs req_per_sec
plt.suptitle(sys.argv[1], fontsize=14)
plt.subplot(221)
plt.ylim(1, max_delay)
axes = pd.DataFrame(data=delays.T,columns=req_per_sec).boxplot(column=req_per_sec, whis=10, showfliers=False)
axes.set_yscale('log')
axes2 = axes.twiny()
a,b = axes.get_xlim()
xt = axes.get_xticks()
tick = np.linspace(min(xt)-a, max(xt)-a, len(theory_req_per_sec)).tolist() + [max(xt)]
axes2.set_xticks(tick, theory_req_per_sec + [""])
axes2.set_xlabel("requests per sec (goal)")
axes.set_xlabel("requests per sec (sent)")
axes.set_ylabel("log10( delay (ms) )")


# req_per_sec vs resp_per_sec
plt.subplot(222)
plt.plot(req_per_sec, resp_per_sec, 'r+')
plt.ylim(0, max(req_per_sec))
plt.xticks(req_per_sec)
plt.grid()
plt.xlabel("requests per sec")
plt.ylabel("response per sec")


# delays vs resp_per_sec
plt.subplot(223)
plt.plot(resp_per_sec, np.nanmedian(delays, axis=1), "r+")
plt.grid()
plt.xlabel("response per sec")
plt.ylabel("median delay")

# error_rate vs req_per_sec
plt.subplot(224)
plt.plot(req_per_sec, error_rate, 'rX')
plt.ylim(0, 100)
plt.grid()
#plt.xticks(req_per_sec)
plt.xlabel("requests per sec")
plt.ylabel("error rate %")


plt.show(block=True)
