
import wmi
import time
import json
import win32com
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
  print (":::CPU info:" ,json.dumps(cpu, indent=4))
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
  print(":::Disk info:", json.dumps(disk, indent=4))
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
  print(":::memory info:", json.dumps(memory, indent=4))
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
  print(":::Network info:", json.dumps(network, indent=4))
  return network
 def get_running_process(self):
  process = []
  for p in s.Win32_Process():
   process.append(
    {
     p.Name: p.ProcessId
    }
   )
  print(":::Running process:", json.dumps(process, indent=4))
  return process
#執行測試：
PCinfo = PCHardwork()
PCinfo.get_CPU_info()
PCinfo.get_disk_info()
PCinfo.get_memory_info()
PCinfo.get_network_info()
PCinfo.get_running_process()