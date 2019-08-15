import wx
import wx.html
import wx.aui
import cStringIO
import wx.dataview as dv
from scapy.all import *
import threading
import time
from wx.lib.wordwrap import wordwrap


class Data():
    def __init__(self):
        self.list = []
ID_About = wx.NewId()
Flag_capture = False
flag = threading.Event()
data = Data()
tmp_data_list = data.list
Filter = None
Iface = None
Index = 0
proto_map ={0:'IP',1:'ICMP',2:'IGMP',3:'GGP',6:'TCP',12:'PUP',17:'UDP',22:'IDP',77:'ND'}
wildcard = "PCAP (*.pcap)|*.pcap"
def GetIntroText():
    return overview

def GetMondrianData():
    return \
'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00 \x00\x00\x00 \x08\x06\x00\
\x00\x00szz\xf4\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\x00\x00qID\
ATX\x85\xed\xd6;\n\x800\x10E\xd1{\xc5\x8d\xb9r\x97\x16\x0b\xad$\x8a\x82:\x16\
o\xda\x84pB2\x1f\x81Fa\x8c\x9c\x08\x04Z{\xcf\xa72\xbcv\xfa\xc5\x08 \x80r\x80\
\xfc\xa2\x0e\x1c\xe4\xba\xfaX\x1d\xd0\xde]S\x07\x02\xd8>\xe1wa-`\x9fQ\xe9\
\x86\x01\x04\x10\x00\\(Dk\x1b-\x04\xdc\x1d\x07\x14\x98;\x0bS\x7f\x7f\xf9\x13\
\x04\x10@\xf9X\xbe\x00\xc9 \x14K\xc1<={\x00\x00\x00\x00IEND\xaeB`\x82' 

def GetMondrianIcon():
    icon = wx.EmptyIcon()
    stream = cStringIO.StringIO(GetMondrianData())
    img_data = wx.ImageFromStream(stream)
    bit_img = wx.BitmapFromImage(img_data)
    icon.CopyFromBitmap(bit_img)
    return icon
    

#-----------------------------------main class-----------------------------------------

class PyAUIFrame(wx.Frame):
    
    def __init__(self, parent, id=-1, title="", pos=wx.DefaultPosition,
                 size=wx.DefaultSize, style=wx.DEFAULT_FRAME_STYLE |
                                            wx.SUNKEN_BORDER |
                                            wx.CLIP_CHILDREN):

        wx.Frame.__init__(self, parent, id, title, pos, size, style)
        
        # tell FrameManager to manage this frame        
        self._mgr = wx.aui.AuiManager()
        self._mgr.SetManagedWindow(self)
        
        self._perspectives = []
        self.n = 0
        self.x = 0
        
        self.SetIcon(GetMondrianIcon())

        # create menu
        mb = wx.MenuBar()

        file_menu = wx.Menu()
        file_menu.Append(wx.ID_EXIT, "Exit")
        file_menu.Append(wx.ID_OPEN,"Open")
        file_menu.Append(wx.ID_SAVE,"Save")
        mb.Append(file_menu, "File")
        
        help_menu = wx.Menu()
        help_menu.Append(ID_About, "About...")
        mb.Append(help_menu, "Help")
    
        self.SetMenuBar(mb)
        
        #create statusbar
        self.statusbar = self.CreateStatusBar(5, wx.ST_SIZEGRIP)
        self.statusbar.SetStatusWidths([-1, -1, -1, -1, -1])
        self.statusbar.SetStatusText("Total:", 0)
        self.statusbar.SetStatusText("TCP:", 1)
        self.statusbar.SetStatusText("UDP:", 2)
        self.statusbar.SetStatusText("ICMP:", 3)
        self.statusbar.SetStatusText("Other:", 4)        
        
        #create toolbar
        tb = self.CreateToolBar(style = wx.TB_HORIZONTAL| wx.NO_BORDER| wx.TB_FLAT) 
        
        self.combo = wx.ComboBox(tb, size = wx.Size(200,10), choices = networks)
        tb.AddControl(self.combo)    
        
        ID_Capture = wx.NewId()
        self.button1 = wx.Button(tb, id=ID_Capture, label='Capture')
        tb.AddControl(self.button1)
        
        tb.AddStretchableSpace()
        tb.AddSeparator()
        tb.AddStretchableSpace()
        
        self.text = wx.TextCtrl(tb, size = (325,10))
        tb.AddControl(self.text)
        
        ID_Filter = wx.NewId()
        self.button2 = wx.Button(tb, id=ID_Filter, label='Filter')
        tb.AddControl(self.button2)
        
        tb.Realize()        
        
        # add panel
        self._mgr.AddPane(self.CreateListCtrl(), wx.aui.AuiPaneInfo().
                          Name("test10").Caption("List Pane").
                          CenterPane())          
    
        self._mgr.AddPane(self.CreateTreeCtrl(), wx.aui.AuiPaneInfo().
                          Name("test8").Caption("Tree Pane").
                          Bottom().Layer(0).Position(-1).Row(0).CloseButton(False))
        
        
        self._mgr.AddPane(self.CreateHTMLCtrl(), wx.aui.AuiPaneInfo().Name("html_content").
                          Bottom().Layer(0).Position(0).Row(0).CloseButton(False))
        self._mgr.Update()
        
        #bind event        
        self.Bind(wx.EVT_MENU, self.OnExit, id=wx.ID_EXIT)
        self.Bind(wx.EVT_MENU, self.OnAbout, id=ID_About)
        self.dvlc.Bind(wx.dataview.EVT_DATAVIEW_SELECTION_CHANGED, self.OnItemSelected)
        self.Bind(wx.EVT_COMBOBOX,self.OnCombo)
        self.Bind(wx.EVT_BUTTON,self.OnCapture,id=ID_Capture)
        self.Bind(wx.EVT_BUTTON,self.OnFilter,id=ID_Filter)
        self.Bind(wx.EVT_MENU, self.OnOpen, id=wx.ID_OPEN)
        self.Bind(wx.EVT_MENU, self.OnSave, id=wx.ID_SAVE)

#------------------------------------------Creaters--------------------------------------------
        
    def CreateListCtrl(self):
        # create the listctrl
        self.dvlc = dvlc = dv.DataViewListCtrl(self)
    
        # Give it some columns.
        # The ID col we'll customize a bit:
        dvlc.AppendTextColumn('id', width=40, align=wx.ALIGN_CENTER_HORIZONTAL)
        dvlc.AppendTextColumn('time', width=150, align=wx.ALIGN_CENTER_HORIZONTAL)
        dvlc.AppendTextColumn('source', width=150, align=wx.ALIGN_CENTER_HORIZONTAL)
        dvlc.AppendTextColumn('destination', width=150, align=wx.ALIGN_CENTER_HORIZONTAL)
        dvlc.AppendTextColumn('protocol', width=80, align=wx.ALIGN_CENTER_HORIZONTAL)
        dvlc.AppendTextColumn('length', width=80, align=wx.ALIGN_CENTER_HORIZONTAL)
        dvlc.AppendTextColumn('info', width=200, align=wx.ALIGN_CENTER_HORIZONTAL)
        return dvlc       
    
        
    def CreateHTMLCtrl(self):
        ctrl = wx.html.HtmlWindow(self, -1, wx.DefaultPosition, wx.Size(400, 300))
        if "gtk2" in wx.PlatformInfo or "gtk3" in wx.PlatformInfo:
            ctrl.SetStandardFonts()
        ctrl.SetPage(GetIntroText())        
        return ctrl
    
    
    
    def CreateTextCtrl(self):

        text = ("This is text box %d")%(self.n + 1)

        return wx.TextCtrl(self,-1, text, wx.Point(0, 0), wx.Size(150, 90),
                           wx.NO_BORDER | wx.TE_MULTILINE)    
    
    def CreateTreeCtrl(self):
        tree = wx.TreeCtrl(self, -1, wx.Point(0, 0), wx.Size(160, 250),
                           wx.TR_DEFAULT_STYLE | wx.NO_BORDER)
        
        root = tree.AddRoot("###[ Ethernet ]### ")
        tree.Expand(root)

        return tree

#------------------------------------------Event_handler--------------------------------------------

    def OnExit(self, event):
        self.Close()

    def OnAbout(self, event):
        # First we create and fill the info object
        info = wx.AboutDialogInfo()
        licenseText = "Just for fun"
        info.Name = "Hello World"
        info.Version = "1.2.3"
        info.Copyright = "(C) 2018 Programmers and Coders Everywhere"
        info.Description = wordwrap(
            "A Simple sniffer created by ZW",
            250, wx.ClientDC(self))
        info.WebSite = ("http://en.wikipedia.org/wiki/Hello_world", "Hello World home page")
        info.Developers = [ "ZW"]

        info.License = wordwrap(licenseText, 150, wx.ClientDC(self))
        wx.AboutBox(info,self)        


    def OnItemSelected(self, event):
        id_fun = self.dvlc.GetSelectedRow()
        try:
            pkt = data.list[id_fun]
            overview1 = """\
            <html><body>
            <pre>"""+str(hexdump(pkt,True))+"""</pre>
            </body></html>
            """       
            self._mgr.GetPane('html_content').window.SetPage(overview1)
            
            tree = self._mgr.GetPane('test8').window
            tree_root = tree.GetRootItem()
            tree.DeleteChildren(tree_root)
            tree_data = pkt.show(True)
            for line in tree_data.split('\n')[1:]:
                if '#' in line:
                    tree_root = tree.AppendItem(tree_root,line[line.find('#'):].strip(' ').strip('|'),0)
                else:
                    tree.AppendItem(tree_root,line.strip(' ').strip('|'))
            #test = tree.AppendItem(root, "Item 1", 0)
            #tree.AppendItem(test, "Subitem 1", 1)            
        except Exception:
            pass
        
    def OnCombo(self,event): 
        global Iface
        Iface = self.combo.GetValue()
    
    def OnCapture(self, event):
        global Flag_capture
        global Filter
        global Iface
        global tmp_data_list
        flag.clear()
        
        def prn(a):
            global Index
            Index += 1
            tmp = ['None','None','None','None','None','None']
            tmp[0] = time.strftime("%H:%M:%S.%%06i", time.localtime(a.time)) % int((a.time - int(a.time)) * 1000000)
            if a.haslayer('Ether'):
                tmp[1] = a[Ether].src
                tmp[2] = a[Ether].dst
                tmp[3] = 'ARP'
                tmp[4] = str(len(a.original))
            if a.haslayer('IP'):
                tmp[1] = a[IP].src
                tmp[2] = a[IP].dst
                if a[IP].proto in proto_map.keys():
                    tmp[3] = proto_map[a[IP].proto]
                else:
                    tmp[3] = str(a[IP].proto)
            if a.haslayer('IPv6'):
                tmp[1] = a[IPv6].src
                tmp[2] = a[IPv6].dst
                if a[IPv6].nh in proto_map.keys():
                    tmp[3] = proto_map[a[IPv6].nh]
                else:
                    tmp[3] = str(a[IPv6].nh)
                    
            tmp[5] = a.summary() 
            tmp = [str(Index)] + tmp
            try:
                wx.CallAfter(self.dvlc.AppendItem,tmp)
            except:
                pass           
            return None 
        
        if not Flag_capture:
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
            thread = threading.Thread(target=sniff,kwargs={'thread_event':flag,'share_data':data,'prn':prn,'iface':Iface,'filter':Filter})
            thread.setDaemon(True)
            thread.start()      
        else:
            Filter = None
            Iface = None
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
        

    
    def OnFilter(self,event):
        global Filter
        global Index
        Index = 0
        
        def prn(a):
            global Index
            Index += 1
            tmp = ['None','None','None','None','None','None']
            tmp[0] = time.strftime("%H:%M:%S.%%06i", time.localtime(a.time)) % int((a.time - int(a.time)) * 1000000)
            if a.haslayer('Ether'):
                tmp[1] = a[Ether].src
                tmp[2] = a[Ether].dst
                tmp[3] = 'ARP'
                tmp[4] = str(len(a.original))
            if a.haslayer('IP'):
                tmp[1] = a[IP].src
                tmp[2] = a[IP].dst
                if a[IP].proto in proto_map.keys():
                    tmp[3] = proto_map[a[IP].proto]
                else:
                    tmp[3] = str(a[IP].proto)
            if a.haslayer('IPv6'):
                tmp[1] = a[IPv6].src
                tmp[2] = a[IPv6].dst
                if a[IPv6].nh in proto_map.keys():
                    tmp[3] = proto_map[a[IPv6].nh]
                else:
                    tmp[3] = str(a[IPv6].nh)
                    
            tmp[5] = a.summary() 
            tmp = [str(Index)] + tmp
            try:
                self.dvlc.AppendItem(tmp)
            except:
                pass
            return None 
        
        if not self.text.IsEmpty():
            Filter = self.text.GetLineText(0) 
        else:
            Filter = ''
        self.dvlc.DeleteAllItems()
        sniff(offline=tmp_data_list, prn=prn,filter=Filter,share_data=data)
    
    def OnSave(self,event):
        dlg = wx.FileDialog(
            self, message="Save file as ...", defaultDir=os.getcwd(), 
            defaultFile="", wildcard=wildcard, style=wx.SAVE
            )
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
            wrpcap(path,data.list)
        dlg.Destroy()        
    
    def OnOpen(self,event):
        global tmp_data_list
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
                global Index
                Index += 1
                tmp = ['None','None','None','None','None','None']
                tmp[0] = time.strftime("%H:%M:%S.%%06i", time.localtime(a.time)) % int((a.time - int(a.time)) * 1000000)
                if a.haslayer('Ether'):
                    tmp[1] = a[Ether].src
                    tmp[2] = a[Ether].dst
                    tmp[3] = 'ARP'
                    tmp[4] = str(len(a.original))
                if a.haslayer('IP'):
                    tmp[1] = a[IP].src
                    tmp[2] = a[IP].dst
                    if a[IP].proto in proto_map.keys():
                        tmp[3] = proto_map[a[IP].proto]
                    else:
                        tmp[3] = str(a[IP].proto)
                if a.haslayer('IPv6'):
                    tmp[1] = a[IPv6].src
                    tmp[2] = a[IPv6].dst
                    if a[IPv6].nh in proto_map.keys():
                        tmp[3] = proto_map[a[IPv6].nh]
                    else:
                        tmp[3] = str(a[IPv6].nh)
                        
                tmp[5] = a.summary() 
                tmp = [str(Index)] + tmp
                try:
                    self.dvlc.AppendItem(tmp)
                except:
                    pass
                return None 
             
            self.dvlc.DeleteAllItems()
            sniff(offline=path, prn=prn, share_data=data)
            tmp_data_list = data.list
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
        dlg.Destroy()
                       
        

        
       

overview = """\
<html><body>
<h3>HEX Window</h3>
</body></html>
"""

        
if __name__ == '__main__':
    networks = get_if_list() 
    app = wx.App(False) 
    frame = PyAUIFrame(None,wx.ID_ANY, "Sniffer", size=(750, 590))
    frame.Show() 
    app.MainLoop()