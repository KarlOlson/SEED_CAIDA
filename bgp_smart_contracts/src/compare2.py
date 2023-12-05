#!/usr/bin/python3

import subprocess
import csv
import sys
import itertools
import pymongo
from operator import countOf

client = pymongo.MongoClient('10.100.0.132', 27017)
collection=client["bgp_db"]["known_bgp"]

#python3 converter.py test.mrt dump.csv single.csv compare.csv 159

#infile=sys.argv[1] 
#dump=sys.argv[2]
#infile2=sys.argv[3]
#outfile=sys.argv[4]
#local_asn=sys.argv[5]

def compiler(infile,dump,infile2,outfile,local_asn):
  subprocess.run(["bgpdump", "-M", str(infile), "-O", str(dump)])

  with open(str(dump) ,'r', newline='' ) as singlecsv:
    output=[]
    blank_csv = csv.reader(singlecsv, delimiter='|')
    for row in blank_csv:
      x=row[5].split('/')
      output.append([x[0],x[1],row[6]])
    print(output)
    print('+++++++++++++++++++++')

  with open(str(infile2), 'r', newline='') as outputcsv1:
    inputcsv=[]
    checker=csv.reader(outputcsv1, delimiter='\t')
    for row in checker:
       inputcsv.append([row[1], row[3], row[4], row[5]])
    print("=====================")
    print(inputcsv)

  with open(str(outfile), 'w', newline='') as outputcsv:
    #write_out=csv.writer(outputcsv, delimiter='|')
    for i,j in itertools.product(inputcsv, output):
      #print(i[0])
      #print(j[0])
      print('================')
      if i[0]==j[0]:
        print(i[0],j[0])
        seg1=j[2].split(' ')
        seg2=list(map(str, seg1))
        print ("seg2 is: ",seg2)
        #path2,path3, path4=path_validate(seg2,local_asn)
        path2,path3, path4=sla_cost(seg2,local_asn)
        write_out=csv.writer(outputcsv, delimiter='|')
        write_out.writerow([i[0],i[1],i[2],i[3],j[0],path2,path3,path4])
      else:
         pass  

def sla_cost(segment_path, local_asn):
   segment_path.insert(0,local_asn)
   print("segment path is: ", segment_path)
   validation={}
   #print("validation is: ", validation)
   for indx, asn in enumerate(segment_path):
       print("validation is: ", validation)
       try:
         print(" checking ASN link to neighbor:",asn, segment_path[indx+1])
       except:
         pass
       if indx == len(segment_path)-1:
              print("summing values")
              cost = 0
              validation[asn]=0
              for item in validation.values():
                 cost+=float(item)
              #cost=sum(int(validation.values()))
              print("The cost of path is: ", cost)
              print("the segment costs are", validation)
              #duration=(time.time_ns() // 1_000_000) - start_time
              return validation, cost, indx
       else:
          try:
             ret2=collection.find_one({'labels.asn':str(asn)},{'labels.cost':1})
             print(ret2)
             ret3=ret2['labels']['cost']
             print ("ret3 is: ",ret3)
             if str(segment_path[indx+1]) in ret3:
                try:
                  validation[asn] = ret3[str(segment_path[indx+1])]
                  print ("adding cost to asn")
                  print ("neighbor cost", ret3[str(segment_path[indx+1])] )
                except:
                 print ("Looks like last node in path, moving to exit")
                 pass
             else:
                print("no neighbor value, setting max cost")
                validation[asn] = 1.2
          except:
            pass 
        
def path_validate(segment_path, local_asn):


    segment_path.insert(0,local_asn)
    validation={}
    #print("validating seg path:",segment_path)
    #print("type of second value is:", type(segment_path[1]))
    for indx, asn in enumerate(segment_path):
       #print("asn is: ", asn)
       #print("asn type is: ", type(asn))
       #print(" index is: ", indx)
       #print("next asn being checked is: ", segment_path[indx+1], type(segment_path[indx+1]))
       if indx == len(segment_path)-1:
          if all(value == True for value in validation.values()):
              print("Path is fully verified",validation)
              percent=100
              return validation, percent, indx 
          else:
              print("The percentage of path validated is: ", countOf(validation.values(), True)/len(validation))
              percent=countOf(validation.values(), True)/len(validation)
              return validation, percent, indx
              
       elif collection.count_documents({'labels.asn': str(asn), 'labels.neighbors': {'$in': [segment_path[indx+1]]}}) == 1:
          validation[asn] = True
           
       else:
          print("false path: ",  str(asn),  collection.count_documents({'labels.asn': str(asn), 'labels.neighbors': {'$in': [segment_path[indx+1]]}}) == 1)
          validation[asn] = False   

if __name__=='__main__':
   compiler(sys.argv[1],sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
