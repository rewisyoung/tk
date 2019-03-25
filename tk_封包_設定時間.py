import tkinter  as tk
from tkinter import ttk,Button
import datetime
import sqlite3
try:
    from scapy.all import IP,sniff,Ether
    import wmi
except :
    import os
    os.system('pip install scapy==2.4.0')#沒有scapy就自動下載
    os.system('pip install wmi')
    from scapy.all import IP,sniff,Ether
    import wmi
#https://blog.csdn.net/sinat_21302587/article/details/74279209
iface_name=[]
w=wmi.WMI()
lans=w.Win32_NetworkAdapterConfiguration(IPEnabled=1)

for i in range (0,len(lans)):
   iface_name.append(lans[i].Description)
"""抓網卡名稱"""

def button_check():
    
    window3=tk.Tk()
    window3.title('時間確認')
    window3.geometry('200x200')
    
    global time_total
    time_total=int(entry1.get())*360+int(entry2.get())*60+int(entry3.get())
    label_time=tk.Label(window3,text="時間設定為"+str(time_total)+"秒")
    label_time.grid()
    window3.mainloop()

def button_push():
    
    #button_check()
    global time_total
    time_total=int(entry1.get())*360+int(entry2.get())*60+int(entry3.get())
    window2=tk.Tk()
    window2.title('window2')
    window2.geometry('400x300')
    mtime=datetime.datetime.now()
    label = tk.Label(window2, text="現在為"+str(mtime.month)+"月"+str(mtime.day)+"日"+str(mtime.hour)+"時"+str(mtime.minute)+"分"+str(mtime.second)+"秒")
    label.grid()
    
    
    
    count=0
    while 1:
        count=packet_sniff(count)
        if count==1:
            conn.close
            break

    window2.mainloop()
    
    
listforlen=[]
listforhour=[]
listforminute=[]
listforsecond=[]
arp=[]
vlanIEEE=[]
IPv6=[]
LLDP=[]
udp=[]
tcp=[]
icmp=[]
other=[]
"""TCP與UDP內port種類"""
HTTP=[]
HTTPS=[]
SMTP=[]
SSH=[]
FTP=[]
"""TCP與UDP內port種類"""

timecount=0#用來算時間陣列listforhour,listforminute....的印出
id_count=1
tcp_count=0
FTP_count=0
SSH_count=0
SMTP_count=0
HTTPS_count=0
HTTP_count=0

def packet_sniff(count):
    """抓現在測的時間"""
    time=datetime.datetime.now()
    hour=str(time.hour)
    minute=str(time.minute)
    second=str(time.second)
    time_save(hour,minute,second)#傳進去存
    """抓現在測的時間"""
    packets=sniff(iface = comboExample.get(), timeout=float(time_total))
    print("抓到了"+str(len(packets))+"個封包")
    print(packets)
    """測試時可以看有沒有分類對"""
   # print("================================")
   # print(packets)
   # print("================================")
   # packets.show()
   # print("================================")
    """測試時可以看有沒有分類對"""
    """開始分類"""
    for i in range(len(packets)):
        try:
            if packets[i][Ether].type==0x806:#ARP，IP位址轉換成Mac位址
                arp.append(str(packets[i].summary()))
            
            if packets[i][Ether].type==0x8100:#VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq[4]
                vlanIEEE.append(str(packets[i].summery()))
            
            if packets[i][Ether].type==0x86DD:#Internet Protocol Version 6 (IPv6)
                IPv6.append(str(packets[i].summery()))
            
            if packets[i][Ether].type==0x88CC:#鏈路層發現協定 (LLDP)
                LLDP.append(str(packets[i].summery()))
                
            if packets[i][Ether].type==0x800:#Internet Protocol version 4 (IPv4)
                if str(packets[i][IP].proto)=="17" and packets[i].sport!=137 and packets[i].dport!=137:#UDP
                    udp.append(str(packets[i].summary()))
                    if packets[i].sport==20 or packets[i].dport==20 or packets[i].sport==21 or packets[i].dport==21:#FTP，檔案傳輸協定
                        FTP.append(str(packets[i].summary()))
                    if packets[i].sport==22 or packets[i].dport==22:#SSH，遠端登入協定
                        SSH.append(str(packets[i].summary())) 
                    if packets[i].sport==25 or packets[i].dport==25:#SMTP，簡單郵件傳輸協定
                        SMTP.append(str(packets[i].summary())) 
                        
                if str(packets[i][IP].proto)=="6" and packets[i].sport!=137 and packets[i].dport!=137:#TCP
                    tcp.append(str(packets[i].summary()))
                    if packets[i].sport==443 or packets[i].dport==443:#https，超文字傳輸安全協定
                        HTTPS.append(str(packets[i].summary()))
                    if packets[i].sport==80 or packets[i].dport==80:#http，超文字傳輸協定
                        HTTP.append(str(packets[i].summary()))
                    if packets[i].sport==20 or packets[i].dport==20 or packets[i].sport==21 or packets[i].dport==21:#FTP，檔案傳輸協定
                        FTP.append(str(packets[i].summary()))
                    if packets[i].sport==22 or packets[i].dport==22:#SSH，遠端登入協定
                        SSH.append(str(packets[i].summary()))
                    if packets[i].sport==25 or packets[i].dport==25:#SMTP，簡單郵件傳輸協定
                        SMTP.append(str(packets[i].summary()))
                        
                if str(packets[i][IP].proto)=="1":#ICMP，一般視為是 IP 的輔助協定, 常用來『報告錯誤，EX:ping -t www.google.com
                    icmp.append(str(packets[i].summary()))
        except Exception:
            other.append(str(packets[i].summary()))
    
    """開始分類"""
    """建立資料庫"""
    global id_count
    global tcp_count
    global FTP_count
    global SSH_count
    global SMTP_count
    global HTTPS_count
    global HTTP_count
    tcp_count=tcp_count+len(tcp)
    FTP_count=FTP_count+len(FTP)
    SSH_count=SSH_count+len(SSH)
    SMTP_count=SMTP_count+len(SMTP)
    HTTPS_count=HTTPS_count+len(HTTPS)
    HTTP_count=HTTP_count+len(HTTP)
    conn = sqlite3.connect('test.db')
    conn.execute("INSERT INTO packet_port (ID,PORT_NAME,COUNT_this_time,COUNT_all) VALUES (?,?,?,?)",(id_count,'TCP',len(tcp),tcp_count))
    conn.execute("INSERT INTO packet_port (ID,PORT_NAME,COUNT_this_time,COUNT_all) VALUES (?,?,?,?)",(id_count,'FTP',len(FTP),FTP_count))
    conn.execute("INSERT INTO packet_port (ID,PORT_NAME,COUNT_this_time,COUNT_all) VALUES (?,?,?,?)",(id_count,'SSH',len(SSH),SSH_count))
    conn.execute("INSERT INTO packet_port (ID,PORT_NAME,COUNT_this_time,COUNT_all) VALUES (?,?,?,?)",(id_count,'SMTP',len(SMTP),SMTP_count))
    conn.execute("INSERT INTO packet_port (ID,PORT_NAME,COUNT_this_time,COUNT_all) VALUES (?,?,?,?)",(id_count,'HTTPS',len(HTTPS),HTTPS_count))
    conn.execute("INSERT INTO packet_port (ID,PORT_NAME,COUNT_this_time,COUNT_all) VALUES (?,?,?,?)",(id_count,'HTTP',len(HTTP),HTTP_count))

    id_count=id_count+1
    conn.commit()
    conn.close
    """建立資料庫"""
    num=str(len(packets))
    len_save(num)
    count=count+1#這在下面算迴圈用，以後可能會移掉
    
    '''
    cursor = conn.cursor()
    cursor = cursor.execute("SELECT * FROM packet_port")
    for row in cursor:
        label = tk.Label(mainWin,text=row)
        label.grid()
    conn.commit()
    conn.close  
    '''
     
    
    return count
# lambda 是種將運算式 (expression) 重複運用的方式，類似函數 (function) ，卻又不像函數需要額外命名函數的識別字 (identifier) ，因此又被稱為無名函數，基本上 lambda 運算式就是函數的簡化
def len_save(num):#記錄下時間和抓到的相對應封包量
    
    listforlen.append(num) 
       
def time_save(hour,minute,second):
   
    listforhour.append(hour)
    listforminute.append(minute)
    listforsecond.append(second)
    
def pri():    
    global timecount#一定要在這邊設global
    
    print("在"+listforhour[timecount]+"時"+listforminute[timecount]+"分"+listforsecond[timecount]+"秒有"+listforlen[timecount]+"個封包")

    timecount = timecount+1
    if arp: #要是我裡面有東西，就是true就會印           
        print("=====ARP包=====")
        for i in range(len(arp)):
            print(arp[i])
        print("===============")
    if vlanIEEE:          
        print("=====VLAN-tagged frame (IEEE 802.1Q)包=====")
        for i in range(len(vlanIEEE)):
            print(vlanIEEE[i])
        print("===============")
    if IPv6:           
        print("=====IPv6包=====")
        for i in range(len(IPv6)):
            print(IPv6[i])
        print("===============")
    if LLDP:           
        print("=====LLDP包=====")
        for i in range(len(LLDP)):
            print(LLDP[i])
        print("===============")
    if udp:
        print("=====UDP包=====")
        for i in range(len(udp)):
            print(udp[i])
        print("===============")
    if tcp:
        print("=====TCP包=====")
        for i in range(len(tcp)):
            print(tcp[i])
        print("===============")
    if icmp:
        print("=====ICMP包=====")
        for i in range(len(icmp)):
            print(icmp[i])
        print("===============")
    if other:
        print("=====未分類封包=====")
        for i in range(len(other)):
            print(other[i])
        print("===============")
    """下面是在分TCP跟UDP部分更細部內容"""
    print("接下來是TCP跟UDP細分")
    if HTTPS:
        print("=====與網頁有關封包(HTTPS)=====")
        for i in range(len(HTTPS)):
            print(HTTPS[i])
        print("===============")
    if HTTP:
        print("=====與網頁有關封包(HTTP)=====")
        for i in range(len(HTTP)):
            print(HTTP[i])
        print("===============")
    if FTP:
        print("=====可能在和FTP server做檔案傳輸(FTP)=====")
        for i in range(len(FTP)):
            print(FTP[i])
        print("===============")
    if SSH:
        print("=====遠端登入(SSH)=====")
        for i in range(len(SSH)):
            print(SSH[i])
        print("===============")
    if SMTP:
        print("=====郵件伺服器間的電子郵件傳遞(SSH)=====")
        for i in range(len(SMTP)):
            print(SMTP[i])
        print("===============")
    """上面是在分TCP跟UDP部分更細部內容"""    
    """因我迴圈讓他跑了三次，他list會依值往後加，這邊記得要清除list，這樣才不會把三組的數值通通放在一起計算了"""    
    arp.clear()
    vlanIEEE.clear()
    IPv6.clear()
    LLDP.clear()
    udp.clear()
    tcp.clear()
    icmp.clear()
    other.clear()
    HTTPS.clear()
    HTTP.clear()
    FTP.clear()
    SSH.clear()
    SMTP.clear()
    """因我迴圈讓他跑了三次，他list會依值往後加，這邊記得要清除list，這樣才不會把三組的數值通通放在一起計算了"""
    
    
"""sqlite資料庫部分"""
conn = sqlite3.connect('test.db')
 
conn.execute("create table if not exists packet_port (ID INTEGER,PORT_NAME TEXT,COUNT_this_time INTEGER,COUNT_all INTEGER)")

conn.commit()
conn.close    
"""sqlite資料庫部分"""      

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''   
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''   
mainWin = tk.Tk()
mainWin.title("Sniff程式")





label = tk.Label(mainWin, text="請選擇網路介面卡")
label.grid(row=0)

comboExample = ttk.Combobox(mainWin,width=40,value=iface_name,state='readonly')
comboExample.grid(row=1)
comboExample.current(0)
#print(comboExample.current(), comboExample.get())

labe2 = tk.Label(mainWin, text="請設定時間，執行")
labe2.grid(row=2, pady=5, sticky=tk.W)


#entryvar1=tk.Variable()
entry1=tk.Entry(mainWin,width=3)
entry1.grid(row=2,padx=100,pady=5,sticky=tk.W)

labe2 = tk.Label(mainWin, text="小時")
labe2.grid(row=2,padx=125, pady=5,sticky=tk.W)

#entryvar2=tk.Variable()
entry2=tk.Entry(mainWin,width=3)
entry2.grid(row=2,padx=155, pady=5,sticky=tk.W)

labe3 = tk.Label(mainWin, text="分鐘")
labe3.grid(row=2,padx=180, pady=5,sticky=tk.W)

#entryvar3=tk.Variable()
entry3=tk.Entry(mainWin,width=3)
entry3.grid(row=2,padx=210, pady=5,sticky=tk.W)

labe4 = tk.Label(mainWin, text="秒")
labe4.grid(row=2,padx=235, pady=5,sticky=tk.W)


#建立一個按鈕實體
sniffButton = Button(mainWin, text = 'sniff',command=button_push);
#將按鈕放到視窗裡，座標為(400，600)
sniffButton.grid();
'''
conn = sqlite3.connect('test.db')

cursor = conn.cursor()
cursor = cursor.execute("SELECT * FROM packet_port")
for row in cursor:
    label = tk.Label(mainWin,text=row)
    label.grid()
conn.commit()
conn.close    
    
'''

mainWin.mainloop()