#!/usr/bin/python
import ast
import time
import logging
import os
import sys
import traceback
import boto.vpc
from optparse import OptionParser
from optparse import Option

listVPC=[]
pwd=os.getcwd()
if "/" in sys.argv[0]:
    fname=sys.argv[0].split("/")[1].split(".")[0]
else:
    fname=sys.argv[0].split(".")[0]
dtime=time.strftime("%Y%m%d-%H%M%S", time.gmtime())
user=os.getenv("USER")
logformat = logging.Formatter("%(asctime)s [%(threadName)-9.9s] [%(levelname)-7.7s]  %(message)s")
fLogger = logging.getLogger("1")
fLogger.setLevel(logging.WARNING)
fHandler = logging.FileHandler(pwd+"/"+user+"-"+fname+dtime+".log")
fHandler.setFormatter(logformat)
fLogger.addHandler(fHandler)
cLogger = logging.getLogger("2")
cHandler = logging.StreamHandler()
cHandler.setFormatter(logformat)
interval=0
def getargs():
    usage = "usage: ./%prog [option] [argument]"
    parser = OptionParser(usage=usage, version="%prog 1.0")
    parser.add_option("-c", "--create-spoke-vpc",action="store",type="string",dest="spokevpcstr",help="""Create spokeVPCs.Use format :
"{'"region"':spokeVPCs No.,'"region"':spokeVPCs No.}". e.g - "{'"us-east-1"':2}" or "{'"us-east-1"':1,'"us-west-1"':2}\"""")
    parser.add_option("-t", "--tag",action="store",type="string",dest="tagstr",help="""Usage  e.g - {'"transitvpc:spoke"':'"true"'}""")
    parser.add_option("-i", "--interval",action="store",type="int",dest="interval",help="interval in seconds. Usage : -i 20")
    parser.add_option("-n", "--cidr16",action="store",type="string",dest="cidr",help="Change first 2 octets only(10.10.x.x reserved). Usage e.g- 192.168.x.x or 10.2.x.x")
    parser.add_option("-v","--verbose",action="store",type="string",dest="loglevel",help="Usage :  -v debug ")
    parser.add_option("-d", "--del",action="store_true", dest="delete",default=False,help="Delete all VPCs")
    parser.add_option("-l", "--list",action="store_true",dest="lst",default=False,help="list all VPCs")
    (options, args) = parser.parse_args()
    if len(args) != 0:
        print ("incorrect number of  arguments")
        exit(1)
    else:
        spokevpcstr = options.spokevpcstr
        delete = options.delete
        lst = options.lst
        tagstr= options.tagstr
        cidr=options.cidr
        loglevel=options.loglevel
        interval=options.interval
    return (spokevpcstr, delete, lst, tagstr,cidr,loglevel,interval)
def clk(t):
    i=t
    while i !=0:
        sys.stdout.write("\r")
        sys.stdout.write("{:2d} seconds remaining...".format(i))
        sys.stdout.flush()
        time.sleep(1)
        i-=1
    sys.stdout.write("\r")
    sys.stdout.write("0 seconds remaining...\n")
def cSpokeVPC(region, vpcsubnet,cidr,**tag):
    global listVPC
    vpcsubnet="{}/24".format(vpcsubnet)
    cLogger.debug('Trying to connect to %s for creating the spokeVPC', region)
    fLogger.warning('Trying to connect to %s for creating the spokeVPC', region)
    conn= boto.vpc.connect_to_region(region)
    try:
        vpc = conn.create_vpc(vpcsubnet)
        print "Creating SpokeVPC %s in region %s" %(vpc.id,region)
        fLogger.warning('Creating SpokeVPC %s in region %s',vpc.id,region)
    except:
        s=traceback.format_exc()
        raise
    if vpc:
        try:
            fLogger.warning('Trying to create a VPGW')
            cLogger.debug('Trying to create a VPGW')
            vpg = conn.create_vpn_gateway("ipsec.1")
            time.sleep(2)
            fLogger.warning('Created VPGW %s', vpg.id)
            cLogger.debug('Created VPGW %s', vpg.id)
        except:
            vpcdelete=conn.delete_vpc(vpc.id)
            s=traceback.format_exc()
            print "Failed creating VPGW for %s so deleted VPC %s.\n" %(vpc.id,vpc.id)
            fLogger.warning('Failed creating VPGW for %s so deleted VPC %s.',vpc.id,vpc.id)
            raise
        else:
            if vpg:
                fLogger.warning('Trying to attach %s with %s',vpg.id,vpc.id)
                cLogger.debug('Trying to attach %s with %s',vpg.id,vpc.id)
                vpgattach= conn.attach_vpn_gateway(vpg.id, vpc.id)
                time.sleep(2)
                conn.create_tags([vpg.id], tag)
                createGroup=(vpg.id,vpc.id)
                createGroup=(region,vpc.id,vpg.id,tag,cidr)
                listVPC.append(createGroup)
def dSpokeVPC(arg):
    try:
        cLogger.debug('Trying to connect to %s for deleting the spokeVPC', arg[0])
        fLogger.warning('Trying to connect to %s for deleting the spokeVPC', arg[0])
        conn= boto.vpc.connect_to_region(arg[0])
        conn.delete_tags(arg[2], arg[3])
        conn.create_tags([arg[2]], {"dummy":"dummy"})
    except:
        print "Failed!!! Please delete SpokeVPC %s %s %s %s manually" %(arg[0],arg[1],arg[2],arg[3])
        s=traceback.format_exc()
        raise
    i=0
    while len(conn.get_all_vpn_connections(None, {"vpnGatewayId":arg[2],"state":"available"})) !=0:
        print "Waiting for Lambda to delete VPNs"
        clk(30)
        i+=1
        if i==2:
            conn.create_tags([arg[2]], {"dummy1":"dummy1"})
        elif i==5:
            print "Script Failed!!! Please delete SpokeVPC %s %s %s %s manually" %(arg[0],arg[1],arg[2],arg[3])
            exit(1)

    vpgdettach=conn.detach_vpn_gateway(arg[2],arg[1])
    while not vpgdettach:
        time.sleep(1)
    if vpgdettach:
        try:
            vpgdelete=conn.delete_vpn_gateway(arg[2])
        except:
            vpgattach= conn.attach_vpn_gateway(arg[2],arg[1])
            conn.create_tags(arg[2], arg[3])
            s=traceback.format_exc()
            raise
    while not vpgdelete:
        time.sleep(1)
    print "Deleting SpokeVPC %s in region %s. Please wait..." %(arg[1],arg[0])
    if vpgdelete:
        try:
            clk(10)
            vpcdelete=conn.delete_vpc(arg[1])
            print"Deleted!!!\n"
        except:
            s=traceback.format_exc()
            print s
            print "Trying to delete VPC again.If fails, please delete VPC %s manually.Please wait.." %(arg[1])
            clk(20)
            vpcdelete=conn.delete_vpc(arg[1])
def lSpokeVPC():
    fobj = open(pwd+"/vpclist", 'r')
    group=fobj.read()
    if group:
        group=spokevpc=ast.literal_eval(group)
    print "  REGION          VPC             VPGW                 TAG           CIDR/16"
    for i in group:
            print i
def cSubnet(totalSpoke,s):
    if totalSpoke <= 256:
        ipList = ["{}{}.0".format(s,j) for j in range(totalSpoke)]
    else:
        ipList1 = ["{}{}.0".format(s,j) for j in range(256)]
        ipList2 = ["10.10.{}.0".format(j) for j in range(totalSpoke - 256)]
        ipList = ipList1 + ipList2
    return ipList
def main ():
    os.system("touch vpclist")
    f1 = open(pwd+"/vpclist", 'r+')
    f2 = open(pwd+"/vpclist.bak", 'w+')
    f2.write(f1.read())
    f1.close()
    f2.close()
    (spokevpcstr,delete,lst,tagstr,cidr,loglevel,interval) = getargs()
    if loglevel=="debug":
        cLogger.setLevel(logging.DEBUG)
        cLogger.addHandler(cHandler)
    else:
        cLogger.setLevel(logging.WARNING)
        cLogger.addHandler(cHandler)
    fLogger.debug('main args received spokevpcstr-%s delete-%s lst-%s tagstr-%s cidr-%s',spokevpcstr,delete,lst,tagstr,cidr)
    if spokevpcstr:
        spokevpc=ast.literal_eval(spokevpcstr)
    if tagstr:
        tag=ast.literal_eval(tagstr)
    i=0
    if spokevpcstr and not delete and not lst and cidr:
        s=cidr.split("x")[0]
        totalSpoke=sum(spokevpc.values())
        fLogger.debug('Total %s spokeVPCs to be created',totalSpoke)
        vpcsubnet=cSubnet(totalSpoke,s)
        fLogger.debug('Usable subnet range for all spokeVPCs %s ',vpcsubnet)
        if spokevpc and not tagstr:
            print "Please add tag value using -t option"
        else:
            fobj = open(pwd+"/vpclist", 'r+')
            group=fobj.read()
            fobj.close()
            l=[]
            if group:
                group=ast.literal_eval(group)
                l=list(group)
            for k, v in spokevpc.iteritems():
                while v != 0:
                    cSpokeVPC(k, vpcsubnet[i],cidr,**tag)
                    i+=1
                    v-=1
                    fobj = open(pwd+"/vpclist", 'w+')
                    if len(l) > 0:
                        k=l+listVPC
                    else:
                        k=listVPC
                    fobj.write(str(k))
                    fobj.close()
                    if interval !=0 and totalSpoke > 1:
                        cLogger.debug("Will wait for %s seconds before creating next spokeVPC\n",interval)
                        totalSpoke -=1
                        clk(interval)

            print "All SpokeVPCs Created."
            fLogger.debug('All SpokeVPCs Created.')
    elif spokevpcstr and not delete and not lst and not cidr:
        print "Please provide cidr16"
    if not spokevpcstr and delete and not lst:
        fobj = open(pwd+"/vpclist", 'r+')
        group=fobj.read()
        fLogger.debug('Reading file for delete: %s', group)
        fobj.close()
        if group:
            group=ast.literal_eval(group)
            l=list(group)
        for j in group:
            conn= boto.vpc.connect_to_region(j[0])
            fLogger.debug('All vpn connections attached with  %s are : %s',j[2], conn.get_all_vpn_connections(None, {"vpnGatewayId":j[2]}))
            if len(conn.get_all_vpn_connections(None, {"vpnGatewayId":j[2],"state":"pending"})) !=0:
                cLogger.warning('Please Wait...VPNs are in Pending State\n')
                cLogger.debug('vpn connections in pending state for VPGW %s are : %s', j[2],conn.get_all_vpn_connections(None, {"vpnGatewayId":j[2],"state":"pending"}))
                exit(1)
            l.remove(j)
            fobj = open(pwd+"/vpclist", 'w+')
            fobj.write(str(l))
            fobj.close()
            fLogger.debug('Deleted %s from vpclist', j)
            dSpokeVPC(j)

        print "All SpokeVPCs Deleted."
    if not spokevpcstr and not delete and lst:
        lSpokeVPC()
if __name__ == '__main__':
    main()
