#!/bin/python3
import random
import string
import json
def getRand():
 return ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))
roster=None
with open('members.json','r') as f:
 roster=json.loads(f.read())
with open('teams.json','r') as f:
 teams=json.loads(f.read())
rand=getRand()
roster[rand]={"Name":"","Phone":"","Email":"","EID":"","Parent":""}
for f in ["Name","Phone","Email","EID","Parent"]:
 roster[rand][f]=input(f+': ')
print("\nTeams:")
teamks=list(teams.keys())
for i,v in enumerate(teamks):
    print("%s: %s"%(i+1,roster[v]['Name']))
tn=input("Team Number: ")
# import code
# code.interact(local=dict(globals(), **locals()))
print(teamks,tn)
teams[teamks[int(tn)-1]].append(rand)
# print(json.dumps(roster,indent=4))
# print(json.dumps(teams,indent=4))
with open('members.json','w') as f:
    f.write(json.dumps(roster,indent=4))
with open('teams.json','w') as f:
    f.write(json.dumps(teams,indent=4))
