import base64,json,socket,time,http.client
def check(value, message):
    if not value: raise RuntimeError(message)

def wait(fn, seconds=60):
    end=time.monotonic()+seconds; last=None
    while time.monotonic()<end:
        try:
            value=fn()
            if value:return value
        except (OSError,ValueError,KeyError,http.client.HTTPException) as e:last=str(e)
        time.sleep(.3)
    raise TimeoutError('readiness deadline: '+str(last))

class Marionette:
    def __init__(self, port):
        self.s=socket.create_connection(('127.0.0.1',port),timeout=5);self.s.settimeout(35);self.n=0
        try:
            check(self.recv().get('marionetteProtocol')==3,'unexpected Marionette protocol')
            session=self.cmd('WebDriver:NewSession',{'acceptInsecureCerts':False,'pageLoadStrategy':'normal'})
            check(session['capabilities']['acceptInsecureCerts'] is False,'certificate verification bypassed')
            self.cmd('WebDriver:SetTimeouts',{'pageLoad':20000,'script':20000,'implicit':0})
        except Exception:
            self.s.close()
            raise
    def recv(self):
        prefix=b''
        while not prefix.endswith(b':'):
            chunk=self.s.recv(1);check(chunk,'Marionette closed');prefix+=chunk
            check(len(prefix)<20,'invalid Marionette header')
        size=int(prefix[:-1]);check(size<8*1024*1024,'response too large');body=b''
        while len(body)<size:
            chunk=self.s.recv(size-len(body));check(chunk,'Marionette closed');body+=chunk
        return json.loads(body)
    def cmd(self,name,args):
        self.n+=1;body=json.dumps([0,self.n,name,args]).encode()
        self.s.sendall(str(len(body)).encode()+b':'+body);r=self.recv()
        check(r[:2]==[1,self.n],'unexpected Marionette sequence')
        if r[2] is not None:raise RuntimeError(name+': '+json.dumps(r[2])[:700])
        return r[3]
    def page(self,url):
        error=None
        try:self.cmd('WebDriver:Navigate',{'url':url})
        except Exception as e:error=str(e)
        try:
            state=self.cmd('WebDriver:ExecuteScript',{'script':"return {url:location.href,uri:document.documentURI,title:document.title,secure:isSecureContext,text:document.body?.innerText?.slice(0,500),frame:document.querySelector('iframe')?.src};",'args':[],'newSandbox':True,'sandbox':'default'})['value']
        except Exception as e:state={'inspection_error':str(e)}
        if error:state['navigation_error']=error
        return state
    def screenshot(self,path):
        try:
            result=self.cmd('WebDriver:TakeScreenshot',{'id':None,'full':False,'highlights':[]})
            if isinstance(result,dict):result=result['value']
            path.write_bytes(base64.b64decode(result))
        except Exception as e:return str(e)
    def close(self):
        try:self.cmd('WebDriver:DeleteSession',{})
        except Exception:pass
        self.s.close()
