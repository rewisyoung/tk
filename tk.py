import tkinter as tk
from tkinter import ttk,Button
import wmi
import time
import win32com

'''
掃描硬體程式功能程式碼
'''
class PCHardwork(object):
 global s
 s = wmi.WMI()
 def get_CPU_info(self):
  cpu = []
  cp = s.Win32_Processor()
  for u in cp:
   cpu.append(
    {
     "Name": u.Name,
     "Serial Number": u.ProcessorId,
     "CoreNum": u.NumberOfCores,
     "numOfLogicalProcessors": u.NumberOfLogicalProcessors,
     "timestamp": time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime()),
     "cpuPercent": u.loadPercentage
    }
   )

  return cpu
 def get_disk_info(self):
  disk = []
  for pd in s.Win32_DiskDrive():
      try:
       disk.append(
        {
         "Serial": s.Win32_PhysicalMedia()[0].SerialNumber.lstrip().rstrip(), # 獲取硬碟序列號，呼叫另外一個win32 API
         "Caption": pd.Caption,
         "size": str(int(float(pd.Size)/1024/1024/1024))+"G"
    }
   )
      except:
           print("x")

  return disk

 def get_memory_info(self):
  memory = []
  for me in s.Win32_PhysicalMemory():
   memory.append(
    {
        "Manufacturer": me.Manufacturer,
        "Speed": me.Speed,
        "Capacity":str(int(float(me.Capacity)/1024/1024/1024))+"G"
    }
   )

  return memory

 def get_network_info(self):
  network = []
  for nw in s.Win32_NetworkAdapterConfiguration (IPEnabled=1):
   network.append(
    {
     "Description": nw.Description,
     "DefaultIPGateway": nw.DefaultIPGateway,
     "MAC": nw.MACAddress,
     "ip": nw.IPAddress
    }
   )

  return network


#執行測試：
PCinfo = PCHardwork()
PCinfo.get_CPU_info()
PCinfo.get_disk_info()
PCinfo.get_memory_info()
PCinfo.get_network_info()




mainWin = tk.Tk()
mainWin.title("掃瞄硬體程式")

label=tk.Label(mainWin, text="請按下掃瞄") 


label.pack()       #顯示元件
Button = Button(mainWin, text = '掃瞄',command=PCHardwork);



mainWin.mainloop()