# coding:utf-8

"""
file: client.py
date: 2023/1/25 11:01
author: JASON
email: yinqiu001@e.ntu.edu.sg
"""

from socket import *
import threading
import json
import time
import re
import random
import numpy as np
import torch
import torch.nn.functional as f
import ast

HOST = '127.0.0.1'
PORT = 8028
USERNAME = "c3"
PASSWORD = "c3"
BUFSIZ = 1024  # the buffer size
ADDR = (HOST, PORT)
FACTOR = 0.5
# in the current version, BETA_1 + BETA_3 should be 1
BETA_1 = 0.65
BETA_2 = 0
BETA_3 = 0.35

tcpCliSock = socket(AF_INET, SOCK_STREAM)
tcpCliSock.connect(ADDR)
userAccount = None

# the elements for calculating local opinions
# the format of interaction: {"timestamp": time.time, "vale", int, "server": int}
# the format of positive/negative_interaction: [interaction, interaction ...]
# the format of local opinion: {"timestamp": time.time, "p", float, "n": float, "u": float, "interaction_number": int,
# "value": int, "result": float}
positive_interaction = dict()
negative_interaction = dict()
positive_interaction["0"] = list()
positive_interaction["1"] = list()
positive_interaction["2"] = list()
negative_interaction["0"] = list()
negative_interaction["1"] = list()
negative_interaction["2"] = list()
# Three servers in this system
local_opinion = dict()
local_opinion["0"] = dict()
local_opinion["1"] = dict()
local_opinion["2"] = dict()

# the elements for calculating recommended opinions and overall opinions
# the format of recommended_opinion is {"server0": [local_opinion], "server1": [local_opinion], "server2" \
# : [local_opinion]}
# the format of overall_opinion is {"server0": {}, "server1": {}, "server2": {}}
recommended_opinion = dict()
recommended_opinion["0"] = dict()
recommended_opinion["1"] = dict()
recommended_opinion["2"] = dict()
for i in recommended_opinion.keys():
    recommended_opinion[i]["c1"] = dict()
    recommended_opinion[i]["c2"] = dict()
overall_opinion = dict()
overall_opinion["0"] = dict()
overall_opinion["1"] = dict()
overall_opinion["2"] = dict()

# the weight
# the format of weight: {"0": {}, "1": {}, "2":{}}
weight_dict = dict()
weight_dict["0"] = dict()
weight_dict["1"] = dict()
weight_dict["2"] = dict()

# the final opinion
# the format of final opinion: {"server0" float, "server1": float, "server2": float}
final_opinion = dict()
final_opinion["0"] = 0
final_opinion["1"] = 0
final_opinion["2"] = 0

# for experiment 2
server_workload = dict()
server_workload["0"] = 0
server_workload["1"] = 0
server_workload["2"] = 0


def weight_calculation():
    # calculate the weight
    for i_temp in recommended_opinion.keys():
        temp = recommended_opinion[i_temp]
        for j_temp in temp.keys():
            if temp[j_temp] != dict():
                interaction_number = temp[j_temp]["interaction_number"]
                freshness = time.time() - temp[j_temp]["timestamp"]
                value = temp[j_temp]["value"]/temp[j_temp]["interaction_number"]
                weight = BETA_1 * interaction_number + BETA_2 * freshness + BETA_3 * value
                weight_dict[i_temp][j_temp] = weight


def overall_opinion_calculation():
    p_o = 0
    n_o = 0
    u_o = 0
    weight_sum = 1
    # the temporary variables
    for i_temp in recommended_opinion.keys():
        temp = recommended_opinion[i_temp]
        for z_temp, j_temp in temp.items():
            if j_temp != dict():
                # print(weight_dict[i_temp], j_temp)
                p_o += weight_dict[i_temp][z_temp] * j_temp["p"]
                n_o += weight_dict[i_temp][z_temp] * j_temp["n"]
                u_o += weight_dict[i_temp][z_temp] * j_temp["u"]
            else:
                pass
        for k_temp in weight_dict[i_temp].values():
            weight_sum += k_temp
        p_o = p_o/weight_sum
        n_o = n_o/weight_sum
        u_o = u_o/weight_sum
        overall_opinion[i_temp]["p"] = p_o
        overall_opinion[i_temp]["n"] = n_o
        overall_opinion[i_temp]["u"] = u_o
        p_o = 0
        n_o = 0
        u_o = 0
        weight_sum = 1


def final_opinion_calculation():
    for i_temp in overall_opinion.keys():  # the server index
        if local_opinion[i_temp] != dict():
            p_f = (local_opinion[i_temp]["p"] * overall_opinion[i_temp]["u"] + overall_opinion[i_temp]["p"] *
                   local_opinion[i_temp]["u"])/(overall_opinion[i_temp]["u"] + local_opinion[i_temp]["u"] -
                                                overall_opinion[i_temp]["u"] * local_opinion[i_temp]["u"])
            n_f = (local_opinion[i_temp]["n"] * overall_opinion[i_temp]["u"] + overall_opinion[i_temp]["n"] *
                   local_opinion[i_temp]["u"])/(overall_opinion[i_temp]["u"] + local_opinion[i_temp]["u"] -
                                                overall_opinion[i_temp]["u"] * local_opinion[i_temp]["u"])
            u_f = (overall_opinion[i_temp]["u"] * local_opinion[i_temp]["u"])/(overall_opinion[i_temp]["u"] +
                                                                               local_opinion[i_temp]["u"] -
                                                                               overall_opinion[i_temp]["u"] *
                                                                               local_opinion[i_temp]["u"])
            final_reputation_score = 10 * p_f + u_f * n_f
            final_opinion[i_temp] = final_reputation_score

    print(final_opinion)


def local_opinion_update(interaction):
    index = interaction["server"]
    local_opinion[index]["timestamp"] = time.time()
    local_opinion[index]["p"] = 0.5 * len(positive_interaction[index])/(len(positive_interaction[index]) +
                                                                        len(negative_interaction[index]))
    local_opinion[index]["n"] = 0.5 * len(negative_interaction[index])/(len(positive_interaction[index]) +
                                                                        len(negative_interaction[index]))
    local_opinion[index]["u"] = 0.5
    if "interaction_number" in local_opinion[index].keys():
        local_opinion[index]["interaction_number"] += 1
    else:
        local_opinion[index]["interaction_number"] = 1
    if "value" in local_opinion[index].keys():
        local_opinion[index]["value"] += interaction["value"]
    else:
        local_opinion[index]["value"] = interaction["value"]
    return local_opinion


def interaction_generation():
    interaction = dict()
    interaction["timestamp"] = time.time()
    interaction["value"] = random.gauss(40, 5)
    interaction["server"] = str(random.randint(0, 2))
    return interaction


def interaction_generation_with_bias():
    interaction = dict()
    interaction["timestamp"] = time.time()
    interaction["value"] = random.gauss(40, 5)
    # detect which is the most familiar server
    interaction_0 = len(positive_interaction["0"])
    interaction_1 = len(positive_interaction["1"])
    interaction_2 = len(positive_interaction["2"])
    temp_list = [interaction_0, interaction_1, interaction_2]
    interaction["server"] = str(temp_list.index(max(temp_list)))
    return interaction


def interaction_generation_with_reputation():
    interaction = dict()
    interaction["timestamp"] = time.time()
    interaction["value"] = random.gauss(40, 5)
    # detect which is the most familiar server
    reputation = list(final_opinion.values())
    src = torch.Tensor(reputation)
    prob = f.softmax(src)
    np.random.seed(0)
    prob = prob.numpy().tolist()
    prob[2] = 1 - prob[0] - prob[1]
    p = np.array(prob)
    index = np.random.choice([0, 1, 2], p=p.ravel())
    print(prob)

    interaction["server"] = str(index)
    return interaction


def random_run():
    randomness = list()
    for i in range(80):
        randomness.append(1)
    for x in range(20):
        randomness.append(0)
    a = random.choice(randomness)
    if a == 0:
        return False
    if a == 1:
        return True


def register():
    myre = r"^[_a-zA-Z]\w{0,}"
    account = USERNAME
    if not re.findall(myre, account):
        print('Account illegal!')
        return None
    password1 = PASSWORD
    password2 = PASSWORD
    if not (password1 and password1 == password2):
        print('Password not illegal!')
        return None
    global userAccount
    userAccount = account
    return account, password1


class inputdata(threading.Thread):
    def run(self):
        period = 0
        while True:
            # wait a certain time
            interval = random.randint(10, 15)
            time.sleep(interval)  # sleep a random time
            # generate and pack the message
            # interaction = interaction_generation() # the normal one
            # below is for experiment 2
            if period < 30:
                interaction = interaction_generation()
            else:
                interaction = interaction_generation_with_reputation()
            # below is for experiment 1
            """
            if period < 10:
                if random_run() is True:
                    positive_interaction[interaction["server"]].append(interaction)
                else:
                    negative_interaction[interaction["server"]].append(interaction)
            else:
                if interaction["server"] == "0":
                    negative_interaction[interaction["server"]].append(interaction)
                else:
                    positive_interaction[interaction["server"]].append(interaction)
            """
            # the normal one
            if random_run() is True:
                positive_interaction[interaction["server"]].append(interaction)
            else:
                negative_interaction[interaction["server"]].append(interaction)
            server_workload[interaction["server"]] += 1
            local_opinion_update(interaction)
            period += 1
            print("major result", period, server_workload)
            # send the message
            sendto = ["c1", "c2"]
            msg = str(local_opinion)
            dataObj = {'to': sendto, 'msg': msg, 'froms': userAccount}
            datastr = json.dumps(dataObj)
            tcpCliSock.send(datastr.encode('utf-8'))


class getdata(threading.Thread):
    def run(self):
        while True:
            # receive the data
            data = tcpCliSock.recv(BUFSIZ)
            dataObj = json.loads(data.decode('utf-8'))
            # print('{} -> {}'.format(dataObj['froms'], dataObj['msg']))

            # extract useful information
            # 1. update recommended_opinion
            temp = eval(dataObj["msg"])
            for ele in temp.keys():
                recommended_opinion[ele][dataObj['froms']] = temp[ele]
            # print(recommended_opinion)

            # 2. calculate the weight
            weight_calculation()

            # 3. calculate the overall reputation
            overall_opinion_calculation()

            # 4. calculate the final opinion
            final_opinion_calculation()


def main():
    while True:
        regInfo = register()
        if regInfo:
            datastr = json.dumps(regInfo)
            tcpCliSock.send(datastr.encode('utf-8'))
            break
    myinputd = inputdata()
    mygetdata = getdata()
    myinputd.start()
    mygetdata.start()
    myinputd.join()
    mygetdata.join()


if __name__ == '__main__':
    main()
