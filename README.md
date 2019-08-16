# Zoomeye-API（一款基于Scapy及WxPython的简易网络嗅探器）
>desktop.py为嗅探器运行文件,senrecv.py为修改过的scapy模块中的文件运行前需要使用senrecv.py替换掉scapy中的senrecn.py文件
1. Scapy模块提供的sniff函数不能在本程序续中直接使用，其内部存在一个永真循环。
在Python中无法终止一个正常运行的线程除非其正常运行结束，为了解决此问题为
sniff函数添加thread_event参数并在调用时赋值为一个thread.Even对象，每次循环时
判断此事件对象是否被设置倘若设置则跳出循环从而结束线程。其次为了使线程内
数据与主程序共享数据包列表信息设置share_data参数，调用时将其赋值为一个自
定义的Data对象，此对象利用类实例共享类变量的特征实现数据共享。关键代码如下：
```python
def sniff(count=0, store=True, offline=None, prn=None, lfilter=None,
          L2socket=None, timeout=None, opened_socket=None,
          stop_filter=None, iface=None, started_callback=None,thread_event=None,share_data=None, *arg, **karg):
    
#-------------------------------------------  
    lst = []
    if share_data: #将函数内部数据包列表赋值给share_data.list用于共享
        if hasattr(share_data,'list'):
            share_data.list = plist.PacketList(lst, "Sniffed")
    if timeout is not None:
        stoptime = time.time() + timeout
    remain = None
    read_allowed_exceptions = ()
    is_python_can_socket = getattr(opened_socket, "is_python_can_socket", lambda: False)

#------------------------------------------------
    
    else:
        def _select(sockets):
            try:
                return select(sockets, [], [], remain)[0]
            except select_error as exc:
                # Catch 'Interrupted system call' errors
                if exc[0] == errno.EINTR:
                    return []
                raise

#------------------------------------------------
                
    try:
        if started_callback:
            started_callback()
        while sniff_sockets:
#查看是否存在此参数且是为thread.Event对象，倘若是则判断事件是否设置，设置后则跳出循环从而实现主程序对线程的控制。
            if 'threading._Event' in str(type(thread_event)):
                if thread_event.is_set():
                    break
#-------------------------------------------------         
    except KeyboardInterrupt:
        pass
    if opened_socket is None:
        for s in sniff_sockets:
            s.close()
    return plist.PacketList(lst, "Sniffed")

```
2. 捕获功能：此功能为嗅探器最核心功能，desktop.py文件中OnCapture函数实现
了此功能。关键代码如下：
```python
def OnCapture(self, event):
        global Flag_capture
        global Filter
        global Iface
      global tmp_data_list      
        flag.clear()
        
        def prn(a): #此函数实现将数据包信息（ID，捕获时间等）显示在GUI窗口中
            global Index
            Index += 1
#下面代码用于获取一个数据包的信息（ID，捕获时间等）
            tmp = ['None','None','None','None','None','None']
            tmp[0] = time.strftime("%H:%M:%S.%%06i", time.localtime(a.time)) % int((a.time - int(a.time)) * 1000000) #捕获时间
            if a.haslayer('Ether'):
                tmp[1] = a[Ether].src #没有除Ether层之外的上层协议时，将源/目标地址置为MAC地址
                tmp[2] = a[Ether].dst
                tmp[3] = 'ARP'
                tmp[4] = str(len(a.original))
            if a.haslayer('IP'): #存在IP层时将地址置为IP层源/目的地址
                tmp[1] = a[IP].src
                tmp[2] = a[IP].dst
                if a[IP].proto in proto_map.keys():
                    tmp[3] = proto_map[a[IP].proto]
                else:
                    tmp[3] = str(a[IP].proto)
            if a.haslayer('IPv6'): #存在IPv6层时将地址置为IPv6层源/目的地址
                tmp[1] = a[IPv6].src
                tmp[2] = a[IPv6].dst
                if a[IPv6].nh in proto_map.keys():
                    tmp[3] = proto_map[a[IPv6].nh]
                else:
                    tmp[3] = str(a[IPv6].nh)
                    
            tmp[5] = a.summary() #设置数据包摘要信息
            tmp = [str(Index)] + tmp
            try:
                wx.CallAfter(self.dvlc.AppendItem,tmp) #wxpython模块是线程不安全的，此函数解决了这个问题，使其能够在线程中调用窗口函数。
            except:
                pass           
            return None 
        
        if not Flag_capture:
#初始化数据包ID及窗口
            Index = 0
            if not self.text.IsEmpty():
                Filter = self.text.GetLineText(0)            
            self.dvlc.DeleteAllItems() 
            self.statusbar.SetStatusText("Total:", 0)
            self.statusbar.SetStatusText("TCP:", 1)
            self.statusbar.SetStatusText("UDP:", 2)
            self.statusbar.SetStatusText("ICMP:", 3)
            self.statusbar.SetStatusText("Other:", 4)
            self.button1.SetBackgroundColour(wx.Colour(255,0,0))
            self.button1.SetLabel('STOP')
#开启线程用于捕获数据包
            thread = threading.Thread(target=sniff,kwargs={'thread_event':flag,'share_data':data,'prn':prn,'iface':Iface,'filter':Filter})#filter参数可以用于捕获时过滤
            thread.setDaemon(True) #setDaemon可以使线程随着主线程关闭而关闭
            thread.start()      
        else:
            Filter = None
            Iface = None
#第二次点击时修改界面捕获按钮样式及显示捕获数据包统计信息
            self.button1.SetBackgroundColour(wx.Colour(255,255,255))
            self.button1.SetLabel('Capture')            
            stats = dict((x._name, 0) for x in data.list.stats)
            other = 0
            for r in data.list.res:
                f = 0
                for p in stats:
                    if data.list._elt2pkt(r).haslayer(p):
                        stats[p] += 1
                        f = 1
                        break
                if not f:
                    other += 1
            total = 0
            for i in stats.values():
                total += i
            total += other
            self.statusbar.SetStatusText("Total:%d"%total, 0)
            self.statusbar.SetStatusText("TCP:%d"%stats['TCP'], 1)
            self.statusbar.SetStatusText("UDP:%d"%stats['UDP'], 2)
            self.statusbar.SetStatusText("ICMP:%d"%stats['ICMP'], 3)
            self.statusbar.SetStatusText("Other:%d"%other, 4)                     
            flag.set()
            tmp_data_list = data.list
        if Flag_capture:
            Flag_capture = False
        else:
            Flag_capture = True


```
3. 过滤功能用于在嗅探结束后或者打开一个新的数据包后，对数据包列
表进行过滤，其关键代码如下
```python
def OnFilter(self,event):
        global Filter
        global Index
        Index = 0
        
        def prn(a):
           ------------实现与OnCapture中的相同------------
        
        if not self.text.IsEmpty():
            Filter = self.text.GetLineText(0) 
        else:
            Filter = None 
#清空窗口中列表
        self.dvlc.DeleteAllItems()
#利用sniff函数重新读入tmp_data_list并设置filter参数来实现过滤
        sniff(offline=tmp_data_list, prn=prn,filter=Filter,share_data=data)
iv.	打开文件功能，
def OnOpen(self,event):
        global tmp_data_list
#弹出对话框用于选择需要打开的文件
        dlg = wx.FileDialog(
            self, message="Choose a file",
            defaultDir=os.getcwd(), 
            defaultFile="",
            wildcard=wildcard,
            style=wx.OPEN | wx.MULTIPLE | wx.CHANGE_DIR
            )
        if dlg.ShowModal() == wx.ID_OK:
            paths = dlg.GetPaths()
            path = paths[0]
            global Index
            Index = 0
            def prn(a):
          ------------实现与OnCapture中的相同------------             
            self.dvlc.DeleteAllItems()
#获得路径并使用sniff的offline参数打开并显示在窗口中
            sniff(offline=path, prn=prn, share_data=data)
            tmp_data_list = data.list
#用于统计数据包列表信息
            stats = dict((x._name, 0) for x in data.list.stats)
            other = 0
            for r in data.list.res:
                f = 0
                for p in stats:
                    if data.list._elt2pkt(r).haslayer(p):
                        stats[p] += 1
                        f = 1
                        break
                if not f:
                    other += 1
            total = 0
            for i in stats.values():
                total += i
            total += other
            self.statusbar.SetStatusText("Total:%d"%total, 0)
            self.statusbar.SetStatusText("TCP:%d"%stats['TCP'], 1)
            self.statusbar.SetStatusText("UDP:%d"%stats['UDP'], 2)
            self.statusbar.SetStatusText("ICMP:%d"%stats['ICMP'], 3)
            self.statusbar.SetStatusText("Other:%d"%other, 4)
#销毁对话框
        dlg.Destroy()
v.	保存功能用于将捕获到的数据包列表保存为Pcap文件，关键代码如下。
def OnSave(self,event):
        dlg = wx.FileDialog(
            self, message="Save file as ...", defaultDir=os.getcwd(), 
            defaultFile="", wildcard=wildcard, style=wx.SAVE
            )
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
#利用wrpcap文件将数据包列表写入指定文件
            wrpcap(path,data.list)
#销毁对话框
        dlg.Destroy() 

```

#界面介绍：
+ 主界面
![主页面](/pic/1.PNG)

+ 捕获界面

![捕获界面](/pic/2.png)

+ 打开pcap文件

![打开pcap](/pic/3.png)

+ 保存pcap文件

![保存pcap文件](/pic/4.png)

+ 数据显示

![数据显示1](/pic/5.png)
![数据显示2](/pic/6.png)