import tornado.ioloop
import tornado.web
import json
import hashlib
from datetime import datetime
import os
import tornado.autoreload
import sys
import random
from random_words import RandomWords
import tornado.httputil
import atexit
import re
import base64
import time
import socket
import string
import traceback
haslock={}

def releaseLock():
    for s in list(haslock.copy().keys()):
        if not haslock[s].closed:
            haslock[s].close()
            haslock.pop(s)
        if os.path.exists(s+'.lock'):
            os.remove(s+'.lock')

atexit.register(releaseLock)

rw = RandomWords()

def getInvite():
    inv=[]
    for i in range(0,2):
        inv.append(''.join(e for e in rw.random_word().capitalize() if e.isalnum()))
    inv.append(str(random.randint(1000,9999)))
    return ''.join(inv)

def log_except_hook(*exc_info):
    text = "".join(traceback.format_exception(*exc_info))
    with open('error.log','w+') as f:
        f.write(text)

sys.excepthook = log_except_hook

data={'Auth':{},'Data':{}}

def dbLock(n):
    while os.path.exists(n+'.lock'):
        time.sleep(1)
    lf=open(n+'.lock', 'w')
    haslock[n]=lf

def dbRead(n):
    try:
        with open(n+'.json','r') as f:
            data[n]=json.loads(f.read())
    except:
            data[n]={}

def dbWrite(n):
    with open(n+'.json','w') as f:
        f.write(json.dumps(data[n],indent=4))

def dbUnlock(n):
    haslock[n].close()
    haslock.pop(n)
    os.remove(n+'.lock')

def hashits(s):
    uk=base64.b64decode(ret['Auth'])
    m=hashlib.sha256()
    m.update(uk)
    k=m.digest()
    b64k=base64.b64encode(k).decode()

def hashit(b):
    m=hashlib.sha256()
    m.update(b)
    k=m.digest()
    return base64.b64encode(k).decode()

def getRand():
 return ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))

settings = {
    "cookie_secret": "GgvJJqBWcZ0UUKhYP2f6I12jAKqh27c5uwRczie8rNzXIvt1P5ihJLg3qfVGsnivctXySoJQ0kBywbIbe4bobhC0JLi26St9MWbQVDDI1ONubmylxf4GzwLyt18zNt8JYoG1DLUUoewlnYujyAkNGu66GMZfTEiB768e8YBl1aYlS6gGcYYXVBoFJ0LrOrvWYPcs36jWxOXaF6RZqmlI3jA6sUPe99rFeuSaUThfCJABnflx0L92o4ZJRgxkRPjx",
}

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("token")

class MainHandler(BaseHandler):
    def get(self,r=None):
        cip=self.request.headers.get('X-Forwarded-For', self.request.headers.get('X-Real-Ip', self.request.remote_ip))
        client={'ip':cip,'method':'get'}
        print(client)
        if not self.request.path=='/':
            if os.path.exists(self.request.path[1:]):
                with open(self.request.path[1:],'rb') as f:
                    self.write(f.read())
            return
        with open('index.html','r') as f:
            self.write(f.read())
    def post(self,r=None):
        cip=self.request.headers.get('X-Forwarded-For', self.request.headers.get('X-Real-Ip', self.request.remote_ip))
        client={'ip':cip,'method':'post'}
        print(client)
        if not self.request.path=='/':
            return
        file_dic = {}
        arg_dic = {}
        ret={}
        tornado.httputil.parse_body_arguments('application/x-www-form-urlencoded', self.request.body, arg_dic, file_dic)
        for k,v in arg_dic.items():
            ret[k]=v[0].decode()
        print(ret)  # or other code`
        if not 'Func' in ret:
            self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
            return
        if ret['Func'] not in ['Reg','ValidateInvite','Auth','CheckSess','GetTeams','GetTeam','TeamRoster','AddMbr']:
            self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
            print(ret)
            return
        if ret['Func']=='CheckSess':
            if self.current_user is None:
                self.write(json.dumps({'Result':'False'}))
            else:
                self.write(json.dumps({'Result':'True'}))
            return
        elif ret['Func']=='Auth':
            if not 'Auth' in ret or 'Auth'=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Login (Err0)'}))
                return
            if not 'User' in ret or 'User'=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Login (Err1)'}))
                return
            dbLock('auth')
            dbRead('auth')
            if not ret['User'] in data['auth']:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Login (Err2)'}))
                dbUnlock('auth')
                return
            b64k=hashit(base64.b64decode(ret['Auth']))
            print(b64k)
            if data['auth'][ret['User']]['Key']==b64k:
                self.write(json.dumps({'Result':'Success'}))
                dbUnlock('auth')
                b64tok=hashit((ret['User']+data['auth'][ret['User']]['Invite']).encode())
                self.set_secure_cookie("token", b64tok)
                self.set_secure_cookie("user", ret['User'])
                self.set_secure_cookie("uid", data['auth'][ret['User']]['UserID'])
                return
            self.write(json.dumps({'Result':'Fail','Reason':'Invalid Login (Err3)'}))
            dbUnlock('auth')
            return
        elif ret['Func']=='ValidateInvite':
            if not 'Code' in ret:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
                return
            dbLock('Invites')
            dbRead('Invites')
            if not ret['Code'] in data['Invites']:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Invitation'}))
                dbUnlock('Invites')
                return
            dbUnlock('Invites')
            self.write(json.dumps({'Result':'Success'}))
            return
        elif ret['Func']=='TeamRoster':
            if self.current_user is None:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
                return
            print(ret['Roster'])
            for s in ['log','roster','members']:
                dbLock(s)
            for s in ['log','roster','members']:
                dbRead(s)
            # for s in ['teams','members','roster']:
            #     dbUnlock(s)
            print(data['roster'])
            ret['Roster']=json.loads(ret['Roster'])
            uid=self.get_secure_cookie("uid").decode()
            dt=datetime.now()
            dtd=dt.strftime("%Y.%m.%d")
            dtt=dt.strftime("%H:%M:%S")
            for m in data['roster'][uid].copy():
                if not m in ret['Roster']:
                    print("%s (%s) check-out@%s,%s"%(m,data['members'][m]['Name'],dtd,dtt))
                    data['roster'][uid].remove(m)
                    if not dtd in data['log'][uid]:
                        data['log'][uid][dtd]={}
                    if not dtt in data['log'][uid][dtd]:
                        data['log'][uid][dtd][dtt]={}
                    if not 'check-out' in data['log'][uid][dtd][dtt]:
                        data['log'][uid][dtd][dtt]['check-out']=[]
                    data['log'][uid][dtd][dtt]['check-out'].append(m)
            for m in ret['Roster'].copy():
                if not m in data['roster'][uid]:
                    print("%s (%s) check-in@%s,%s"%(m,data['members'][m]['Name'],dtd,dtt))
                    data['roster'][uid].append(m)
                    if not dtd in data['log'][uid]:
                        data['log'][uid][dtd]={}
                    if not dtt in data['log'][uid][dtd]:
                        data['log'][uid][dtd][dtt]={}
                    if not 'check-in' in data['log'][uid][dtd][dtt]:
                        data['log'][uid][dtd][dtt]['check-in']=[]
                    data['log'][uid][dtd][dtt]['check-in'].append(m)
            print(data['roster'])
            for s in ['roster','log','members']:
                dbWrite(s)
            for s in ['roster','log','members']:
                dbUnlock(s)
            self.write(json.dumps({'Result':'Success'}))
            return
        elif ret['Func']=='GetTeam':
            if self.current_user is None:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
                return
            DBs=['teams','members','roster']
            for s in DBs:
                dbLock(s)
            for s in DBs:
                dbRead(s)
            for s in DBs:
                dbUnlock(s)
            uid=self.get_secure_cookie("uid").decode()
            print(uid,data['teams'].keys())
            if not uid in data['teams'].keys():
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
                return
            team={uid:data['members'][uid]}
            for m in data['teams'][uid]:
                if not m in data['members']:
                    continue
                team[m]=data['members'][m]
            for m in team:
                if m in data['roster'][uid]:
                    team[m]['InRoster']="True"
                else:
                    team[m]['InRoster']="False"
            p=json.dumps({'Result':'Success','Payload':team})
            print(p)
            self.write(p)
            return
        elif ret['Func']=='AddMbr':
            if self.current_user is None:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
                return
            if not 'Name' in ret or ret['Name']=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Name'}))
                return
            if not 'Phone' in ret or ret['Phone']=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Phone'}))
                return
            if not 'Email' in ret or not bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$",ret['Email'])):
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Email'}))
                return
            if not 'Parent' in ret or ret['Parent']=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Company'}))
                return
            if not 'Team' in ret or ret['Parent']=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Team'}))
                return
            DBs=['teams','members']
            for s in DBs:
                dbLock(s)
            for s in DBs:
                dbRead(s)
            for k,v in data['members'].items():
                if ret['Name']==v['Name']:
                    self.write(json.dumps({'Result':'Fail','Reason':'Name Exists'}))
                    return
            rand=getRand()
            data['members'][rand]={
                'Name':ret['Name'],
                'Phone':ret['Phone'],
                'Email':ret['Email'],
                'Parent':ret['Parent']
            }
            data['teams'][ret['Team']].append(rand)
            for s in DBs:
                dbWrite(s)
            for s in DBs:
                dbUnlock(s)
            self.write(json.dumps({'Result':'Success'}))
        elif ret['Func']=='GetTeams':
            if self.current_user is None:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Response'}))
                return
            DBs=['teams','members']
            for s in DBs:
                dbLock(s)
            for s in DBs:
                dbRead(s)
            for s in DBs:
                dbUnlock(s)
            teams={}
            for v in list(data['teams'].keys()):
                teams[v]=data['members'][v]['Name']
            self.write(json.dumps({'Result':'Success','Payload':teams}))
        elif ret['Func']=='Reg':
            if not 'User' in ret or not bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$",ret['User'])):
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Email'}))
                return
            if not 'Auth' in ret or ret['Auth']=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Password'}))
                return
            if not 'Invite' in ret or ret['Invite']=='':
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Invitation'}))
                return
            # Implement ThreadIDs in the lockfiles
            dbLock('Invites')
            dbRead('Invites')
            if not ret['Invite'] in data['Invites']:
                self.write(json.dumps({'Result':'Fail','Reason':'Invalid Invitation'}))
                dbUnlock('Invites')
                return
            dbLock('auth')
            dbRead('auth')
            if ret['User'] in data['auth']:
                self.write(json.dumps({'Result':'Fail','Reason':'Email already Registered'}))
                dbUnlock('auth')
                dbUnlock('Invites')
                return
            b64k=hashit(base64.b64decode(ret['Auth']))
            data['auth'][ret['User']]={'Key':b64k,'Invite':ret['Invite'],'UserID':getRand()}
            # if ret['Invite']!='UltimateUninvite2020':
            data['Invites'].remove(ret['Invite'])
            dbWrite('auth')
            dbUnlock('auth')
            dbWrite('Invites')
            dbUnlock('Invites')
            self.write(json.dumps({'Result':'Success'}))
            return

def make_app():
    return tornado.web.Application([
        (r"/(.*)", MainHandler),
    ], **settings)
        # (r"/", MainHandler),
        # (r"/login", LoginHandler),

if __name__ == "__main__":
    app = make_app()
    app.listen(8819)
    # tornado.autoreload.start()
    # tornado.autoreload.watch('app.py')
    tornado.ioloop.IOLoop.current().start()
