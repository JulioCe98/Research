#Optimizado

import pyshark
import traceback
import pandas as pd
from pandas import ExcelWriter
from datetime import datetime

#check
def tcp_urg_pck(pkt):
    retorno =0
    try:
            if pkt.transport_layer == 'TCP':
                sumo = False
                for lyr in pkt.layers:
                    flagUrg = str(lyr.get_field_value('tcp.flags.urg'))
                    if flagUrg not in 'None' and flagUrg not in '0':
                        if sumo == False:
                            retorno += 1
                            sumo = True
    except AttributeError:
            pass
    except Exception:
            print ('Error en tcp_urg_packet')
    return retorno




#not supported
def source_pck(capture):
    print ("-------Mining Source_PCK-------")
    pkts = []
    for pkt in capture:
        try:
            if pkt.ip.src == 'falta la IP a la que se dirigen los pck':
                pkts.append(pkt)
        except AttributeError:
            pass
        except Exception:
            print ('Error en source_app_packets')
    return pkts

#not supported
def remote_pck(capture):
    print ("-------Mining Remote_PCK-------")
    pkts = []
    for pkt in capture:
        try:
            if pkt.ip.dst == 'falta la ip desde donde llegan los pck':
                pkts.append(pkt)
        except AttributeError:
            pass
        except Exception:
            print ('Error en remote_app_packets')
    return pkts

#check
def duration(pkt, firstPkt):
    return float(pkt.frame_info.time_epoch)  -  float(firstPkt.frame_info.time_epoch)

#not supported
def avg_local_pck_rate(capture):
    time = duration(capture)
    if time not in 'NA':
        resultado = len(source_pck(capture)) / float(time)
    else:
        resultado = 'NA'
    return resultado

#not supported
def avg_remote_pck_rate(capture):
    time = duration(capture)
    if time not in 'NA':
        resultado = len(remote_pck(capture)) / float(time)
    else:
        resultado = 'NA'
    return resultado



#check
def dns(pkt):
    sumo = False
    retorno = 0
    for lyr in pkt.layers:
        if lyr.layer_name in 'dns':
            if(sumo == False):
                retorno += 1
                sumo = True
    return retorno


#check
def tcp(pkt):
    retorno = 0
    if pkt.transport_layer == 'TCP':
        retorno += 1

    return retorno

#check
def udp(pkt):
    retorno = 0
    if pkt.transport_layer == 'UDP':
        retorno += 1
    return retorno

#check
def http(pkt):
    sumo = False
    retorno = 0
    for lyr in pkt.layers:
        if lyr.layer_name in 'http':
            if (sumo == False):
                retorno += 1
                sumo = True
    return retorno


def irc(capture):
    return

#check
def bytes(pkt):
    return (float)(pkt.length)


def create_Matriz(generalRoute, matrizRoute):

    "@param generalRoute es la ruta donde esta el txt con la sruta de las carpetas de benignos y malignos"
    "@param matrizRoute es la ruta se guardara la matriz creada"
    namePcap=[]
    tcpUrg = []
    mduration = []
    mdns = []
    mtcp = []
    mudp = []
    mbytes = []
    mnumberPck = []
    mtype =[]
    mhttp =[]
    file = open(generalRoute,"r")
    i = 0 #Inicio
    try:
     for g in file.readlines():
            namePcap.append("Name")
            tcpUrg.append("TCP_URG_pck")
            mduration.append("Duration (Time)")
            mdns.append("# DNS")
            mtcp.append("# TCP")
            mudp.append("# UDP")
            mhttp.append("# HTTP")
            mbytes.append("Bytes")
            mnumberPck.append("# of pck")
            mtype.append("Type")
            while i < 2: #Final
                try:
                    print('VA EN :' + str(i))
                    cap = pyshark.FileCapture('Resource/Beningnos/'+str(i)+'.pcap')#Mover si es Malignos o Beningnos
                    isFirstPkt = False
                    tempTcpUrg = 0
                    tempDuration = 0
                    tempDns =0
                    tempTcp = 0
                    tempUdp=0
                    tempHttp = 0
                    tempBytes =0
                    tempNumberPkt = 0
                    firstPkt = None

                    namePcap.append("Capture" + str(i))
                    for pkt in cap:

                        if(isFirstPkt == False):
                            firstPkt = pkt
                            isFirstPkt = True

                        tempTcpUrg += tcp_urg_pck(pkt);
                        tempDuration = duration(pkt,firstPkt)
                        tempDns +=  dns(pkt)
                        tempTcp += tcp(pkt)
                        tempUdp += udp(pkt)
                        tempHttp += http(pkt)
                        tempBytes += bytes(pkt)
                        tempNumberPkt += 1

                    tcpUrg.append(str(tempTcpUrg)+"")
                    mduration.append(str(tempDuration))
                    mdns.append(str(tempDns))
                    mtcp.append(str(tempTcp))
                    mudp.append(str(tempUdp))
                    mhttp.append(str(tempHttp))
                    mbytes.append(str(tempBytes))
                    mnumberPck.append(str(tempNumberPkt))
                    mtype.append("1") # 0 Benignos, 1 Malignos
                    i+=1

                    df = pd.DataFrame(
                    data={"c1": namePcap, "c2": tcpUrg, "c3": mduration, "c4": mdns, "c5": mtcp, "c6": mudp,"c7": mhttp, "c8": mbytes, "c9": mnumberPck, "c10": mtype})
                    writer = ExcelWriter(rutaMatriz + '(' +str(i) +')' +'.xlsx')
                    df.to_excel(writer, 'Hoja de datos', index=False)
                    writer.save()
                    cap.close()
                except Exception as e:
                     i+=1
                     print ("exception during the pcap lecture process")
                     print (e)


    except Exception as e:
        traceback.print_exc()

    return 0


#cap = pyshark.FileCapture('Resource/0.pcap', "w")
#print(duration(cap))

rutaGeneral = 'Resource/Routes.txt'
rutaMatriz = 'Resource/Malign_Dataset'

create_Matriz(rutaGeneral,rutaMatriz)
print('finalize')
