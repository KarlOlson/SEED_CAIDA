import argparse
import random
import csv

#####INSTRUCTIONS############
#Run python3 routingdb_builder.py -d 10
#after output, go into file and do find/replace for " with a space
#then do find and replace for }} with }},
#add array bracket at beginning of file [ and end of file ], save
#also need to replace all single quotes with double. python makes single.
###################################################################

#Process command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-d', type=int, required = False,
                    help="proxy deployment percentage")
FLAGS = parser.parse_args()

###############################################################################
# 5 Transit ASes -> 100-105
# 12 Stub ASes -> 106-117
# Total num ASes of 17
total_ASes =  80
if FLAGS.d:       
  dep_percentage = FLAGS.d/100
  true_count = int(total_ASes * dep_percentage)
  false_count = total_ASes - true_count
  proxy = [True] * true_count + [False] * false_count
  #random.seed(0) 
  random.shuffle(proxy)
else: # no percentage specified, do not deploy proxy
  proxy = [False] * total_ASes
############################################################

start=0
stop=100

array1=[
   
   [True,str({"labels": {"asn": "1", "net1_address": "10.1.0.0/24", "neighbors":[] }})],
   [proxy[0],str({"labels": {"asn": "2", "net1_address": "10.2.0.0/24", "neighbors":[190, 67, 68, 133, 11872, 113],"cost":{"190": str(random.randint(start,stop)/100), "67":str(random.randint(start,stop)/100), "68":str(random.randint(start,stop)/100), "133":str(random.randint(start,stop)/100), "11872":str(random.randint(start,stop)/100), "113":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "2", "net1_address": "10.2.0.0/24", "neighbors":[]}})],
   
   [proxy[1],str({"labels": {"asn": "3", "net1_address": "10.3.0.0/24", "neighbors":[191, 66, 126, 127, 113],"cost":{"191": str(random.randint(start,stop)/100), "67":str(random.randint(start,stop)/100), "66":str(random.randint(start,stop)/100), "126":str(random.randint(start,stop)/100), "127":str(random.randint(start,stop)/100), "113":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "3", "net1_address": "10.3.0.0/24", "neighbors":[]}})],
   
   [proxy[2],str({"labels": {"asn": "4", "net1_address": "10.4.0.0/24", "neighbors":[192, 65, 123, 124, 125, 126, 74, 80],"cost":{"192": str(random.randint(start,stop)/100), "126":str(random.randint(start,stop)/100), "65":str(random.randint(start,stop)/100), "123":str(random.randint(start,stop)/100), "124":str(random.randint(start,stop)/100), "125":str(random.randint(start,stop)/100), "74":str(random.randint(start,stop)/100), "80":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "4", "net1_address": "10.4.0.0/24", "neighbors":[]}})],
   
   [proxy[3],str({"labels": {"asn": "5", "net1_address": "10.5.0.0/24", "neighbors":[193, 64, 94, 95, 99, 124],"cost":{"193": str(random.randint(start,stop)/100), "64":str(random.randint(start,stop)/100), "94":str(random.randint(start,stop)/100), "95":str(random.randint(start,stop)/100), "99":str(random.randint(start,stop)/100), "124":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "5", "net1_address": "10.5.0.0/24", "neighbors":[]}})],
   
   [proxy[4],str({"labels": {"asn": "6", "net1_address": "10.6.0.0/24", "neighbors":[194, 63, 92, 93, 94],"cost":{"194": str(random.randint(start,stop)/100), "63":str(random.randint(start,stop)/100), "92":str(random.randint(start,stop)/100), "93":str(random.randint(start,stop)/100), "94":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "6", "net1_address": "10.6.0.0/24", "neighbors":[]}})],
   
   [proxy[5],str({"labels": {"asn": "7", "net1_address": "10.7.0.0/24", "neighbors":[195, 62, 81, 71, 112, 111],"cost":{"195": str(random.randint(start,stop)/100), "112":str(random.randint(start,stop)/100), "62":str(random.randint(start,stop)/100), "81":str(random.randint(start,stop)/100), "71":str(random.randint(start,stop)/100), "111":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "7", "net1_address": "10.7.0.0/24", "neighbors":[]}})],
   
   [proxy[6],str({"labels": {"asn": "8", "net1_address": "10.8.0.0/24", "neighbors":[196, 68, 69, 70, 112],"cost":{"196": str(random.randint(start,stop)/100), "68":str(random.randint(start,stop)/100), "69":str(random.randint(start,stop)/100), "70":str(random.randint(start,stop)/100), "112":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "8", "net1_address": "10.8.0.0/24", "neighbors":[]}})],
   
   [proxy[7],str({"labels": {"asn": "9", "net1_address": "10.9.0.0/24", "neighbors":[197, 128, 132, 133, 134],"cost":{"197": str(random.randint(start,stop)/100), "128":str(random.randint(start,stop)/100), "132":str(random.randint(start,stop)/100), "133":str(random.randint(start,stop)/100), "134":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "9", "net1_address": "10.9.0.0/24", "neighbors":[]}})],
   
   [proxy[8],str({"labels": {"asn": "10", "net1_address": "10.10.0.0/24", "neighbors":[198, 127, 128, 129, 84],"cost":{"198": str(random.randint(start,stop)/100), "127":str(random.randint(start,stop)/100), "128":str(random.randint(start,stop)/100), "129":str(random.randint(start,stop)/100), "84":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "10", "net1_address": "10.10.0.0/24", "neighbors":[]}})],
   
   [proxy[9],str({"labels": {"asn": "11", "net1_address": "10.11.0.0/24", "neighbors":[199, 125, 129, 83],"cost":{"199": str(random.randint(start,stop)/100), "125":str(random.randint(start,stop)/100), "129":str(random.randint(start,stop)/100), "83":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "11", "net1_address": "10.11.0.0/24", "neighbors":[]}})],
   
   [proxy[10],str({"labels": {"asn": "12", "net1_address": "10.12.0.0/24", "neighbors":[200, 110,  123, 83],"cost":{"200": str(random.randint(start,stop)/100), "110":str(random.randint(start,stop)/100), "123":str(random.randint(start,stop)/100), "83":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "12", "net1_address": "10.12.0.0/24", "neighbors":[]}})],
   
   [proxy[11],str({"labels": {"asn": "13", "net1_address": "10.13.0.0/24", "neighbors":[201,  99, 110, 87, 80],"cost":{"201": str(random.randint(start,stop)/100), "99":str(random.randint(start,stop)/100), "110":str(random.randint(start,stop)/100), "87":str(random.randint(start,stop)/100), "80":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "13", "net1_address": "10.13.0.0/24", "neighbors":[]}})],
   
   [proxy[12],str({"labels": {"asn": "14", "net1_address": "10.14.0.0/24", "neighbors":[202, 95, 96 ,  87],"cost":{"202": str(random.randint(start,stop)/100), "95":str(random.randint(start,stop)/100), "96":str(random.randint(start,stop)/100), "87":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "14", "net1_address": "10.14.0.0/24", "neighbors":[]}})],
   
   [proxy[13],str({"labels": {"asn": "15", "net1_address": "10.15.0.0/24", "neighbors":[203,  93, 96,  73],"cost":{"203": str(random.randint(start,stop)/100), "96":str(random.randint(start,stop)/100), "93":str(random.randint(start,stop)/100), "73":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "15", "net1_address": "10.15.0.0/24", "neighbors":[]}})],
   
   [proxy[14],str({"labels": {"asn": "16", "net1_address": "10.16.0.0/24", "neighbors":[204, 82, 92, 111, 73, 74],"cost":{"204": str(random.randint(start,stop)/100), "82":str(random.randint(start,stop)/100), "92":str(random.randint(start,stop)/100), "111":str(random.randint(start,stop)/100), "73":str(random.randint(start,stop)/100), "74":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "16", "net1_address": "10.16.0.0/24", "neighbors":[]}})],
   
   [proxy[15],str({"labels": {"asn": "17", "net1_address": "10.17.0.0/24", "neighbors":[205, 72, 81, 82],"cost":{"205": str(random.randint(start,stop)/100), "72":str(random.randint(start,stop)/100), "81":str(random.randint(start,stop)/100), "82":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "17", "net1_address": "10.17.0.0/24", "neighbors":[]}})],
   
   [proxy[16],str({"labels": {"asn": "18", "net1_address": "10.18.0.0/24", "neighbors":[206, 70, 71, 72, 90],"cost":{"206": str(random.randint(start,stop)/100), "70":str(random.randint(start,stop)/100), "71":str(random.randint(start,stop)/100), "72":str(random.randint(start,stop)/100), "90":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "18", "net1_address": "10.18.0.0/24", "neighbors":[]}})],
   
   [proxy[17],str({"labels": {"asn": "19", "net1_address": "10.19.0.0/24", "neighbors":[207, 69, 134, 90],"cost":{"207": str(random.randint(start,stop)/100), "69":str(random.randint(start,stop)/100), "134":str(random.randint(start,stop)/100), "90":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "19", "net1_address": "10.19.0.0/24", "neighbors":[]}})],
   
   [proxy[18],str({"labels": {"asn": "20", "net1_address": "10.20.0.0/24", "neighbors":[208,  132, 84],"cost":{"208": str(random.randint(start,stop)/100), "132":str(random.randint(start,stop)/100), "84":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "20", "net1_address": "10.20.0.0/24", "neighbors":[]}})],
   
   [True,str({"labels": {"asn": "21", "net1_address": "10.21.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "22", "net1_address": "10.22.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "23", "net1_address": "10.23.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "24", "net1_address": "10.24.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "25", "net1_address": "10.25.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "26", "net1_address": "10.26.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "27", "net1_address": "10.27.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "28", "net1_address": "10.28.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "29", "net1_address": "10.29.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "30", "net1_address": "10.30.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "31", "net1_address": "10.31.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "32", "net1_address": "10.32.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "33", "net1_address": "10.33.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "34", "net1_address": "10.34.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "35", "net1_address": "10.35.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "36", "net1_address": "10.36.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "37", "net1_address": "10.37.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "38", "net1_address": "10.38.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "39", "net1_address": "10.39.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "40", "net1_address": "10.40.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "41", "net1_address": "10.41.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "42", "net1_address": "10.42.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "43", "net1_address": "10.43.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "44", "net1_address": "10.44.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "45", "net1_address": "10.45.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "46", "net1_address": "10.46.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "10", "net1_address": "10.47.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "47", "net1_address": "10.48.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "48", "net1_address": "10.49.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "49", "net1_address": "10.50.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "50", "net1_address": "10.51.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "51", "net1_address": "10.52.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "52", "net1_address": "10.53.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "53", "net1_address": "10.54.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "54", "net1_address": "10.55.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "55", "net1_address": "10.56.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "56", "net1_address": "10.57.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "57", "net1_address": "10.58.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "59", "net1_address": "10.59.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "60", "net1_address": "10.60.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "61", "net1_address": "10.61.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "62", "net1_address": "10.62.0.0/24", "neighbors":[7,100],"cost":{"7": str(random.randint(start,stop)/100), "100":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "62", "net1_address": "10.62.0.0/24", "neighbors":[]}})],
   [proxy[19],str({"labels": {"asn": "63", "net1_address": "10.63.0.0/24", "neighbors":[6,100],"cost":{"6": str(random.randint(start,stop)/100), "100":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "63", "net1_address": "10.63.0.0/24", "neighbors":[]}})],
   [proxy[20],str({"labels": {"asn": "64", "net1_address": "10.64.0.0/24", "neighbors":[5,100],"cost":{"5": str(random.randint(start,stop)/100), "100":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "64", "net1_address": "10.64.0.0/24", "neighbors":[]}})],
   [proxy[21],str({"labels": {"asn": "65", "net1_address": "10.65.0.0/24", "neighbors":[4,100],"cost":{"4": str(random.randint(start,stop)/100), "100":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "65", "net1_address": "10.65.0.0/24", "neighbors":[]}})],
   [proxy[22],str({"labels": {"asn": "66", "net1_address": "10.66.0.0/24", "neighbors":[3,100],"cost":{"3": str(random.randint(start,stop)/100), "100":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "66", "net1_address": "10.66.0.0/24", "neighbors":[]}})],
   [proxy[23],str({"labels": {"asn": "67", "net1_address": "10.67.0.0/24", "neighbors":[2,100],"cost":{"2": str(random.randint(start,stop)/100), "100":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "67", "net1_address": "10.67.0.0/24", "neighbors":[]}})],
   [proxy[24],str({"labels": {"asn": "68", "net1_address": "10.68.0.0/24", "neighbors":[2,8],"cost":{"2": str(random.randint(start,stop)/100), "8":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "68", "net1_address": "10.68.0.0/24", "neighbors":[]}})],
   [proxy[25],str({"labels": {"asn": "69", "net1_address": "10.69.0.0/24", "neighbors":[8,19],"cost":{"8": str(random.randint(start,stop)/100), "19":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "69", "net1_address": "10.69.0.0/24", "neighbors":[]}})],
   [proxy[26],str({"labels": {"asn": "70", "net1_address": "10.70.0.0/24", "neighbors":[8,18],"cost":{"8": str(random.randint(start,stop)/100), "18":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "70", "net1_address": "10.70.0.0/24", "neighbors":[]}})],
   [proxy[27],str({"labels": {"asn": "71", "net1_address": "10.71.0.0/24", "neighbors":[7,18],"cost":{"7": str(random.randint(start,stop)/100), "18":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "71", "net1_address": "10.71.0.0/24", "neighbors":[]}})],
   [proxy[28],str({"labels": {"asn": "72", "net1_address": "10.72.0.0/24", "neighbors":[17,18],"cost":{"17": str(random.randint(start,stop)/100), "18":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "72", "net1_address": "10.72.0.0/24", "neighbors":[]}})],
   [proxy[29],str({"labels": {"asn": "73", "net1_address": "10.73.0.0/24", "neighbors":[15,16],"cost":{"15": str(random.randint(start,stop)/100), "16":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "73", "net1_address": "10.73.0.0/24", "neighbors":[]}})],
   [proxy[30],str({"labels": {"asn": "74", "net1_address": "10.74.0.0/24", "neighbors":[4,16],"cost":{"4": str(random.randint(start,stop)/100), "16":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "74", "net1_address": "10.74.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "75", "net1_address": "10.75.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "76", "net1_address": "10.76.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "77", "net1_address": "10.77.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "78", "net1_address": "10.78.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "79", "net1_address": "10.79.0.0/24", "neighbors":[] }})],
   [proxy[31],str({"labels": {"asn": "80", "net1_address": "10.80.0.0/24", "neighbors":[13,4],"cost":{"13": str(random.randint(start,stop)/100), "4":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "80", "net1_address": "10.80.0.0/24", "neighbors":[]}})],
   [proxy[32],str({"labels": {"asn": "81", "net1_address": "10.81.0.0/24", "neighbors":[17,7],"cost":{"17": str(random.randint(start,stop)/100), "7":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "81", "net1_address": "10.81.0.0/24", "neighbors":[]}})],
   [proxy[33],str({"labels": {"asn": "82", "net1_address": "10.82.0.0/24", "neighbors":[16,17],"cost":{"16": str(random.randint(start,stop)/100), "17":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "82", "net1_address": "10.82.0.0/24", "neighbors":[]}})],
   [proxy[34],str({"labels": {"asn": "83", "net1_address": "10.83.0.0/24", "neighbors":[11,12],"cost":{"11": str(random.randint(start,stop)/100), "12":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "83", "net1_address": "10.83.0.0/24", "neighbors":[]}})],
   [proxy[35],str({"labels": {"asn": "84", "net1_address": "10.84.0.0/24", "neighbors":[20,10],"cost":{"20": str(random.randint(start,stop)/100), "10":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "84", "net1_address": "10.84.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "85", "net1_address": "10.85.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "86", "net1_address": "10.86.0.0/24", "neighbors":[] }})],
   [proxy[36],str({"labels": {"asn": "87", "net1_address": "10.87.0.0/24", "neighbors":[14,13],"cost":{"14": str(random.randint(start,stop)/100), "13":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "87", "net1_address": "10.87.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "88", "net1_address": "10.88.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "89", "net1_address": "10.89.0.0/24", "neighbors":[] }})],
   [proxy[37],str({"labels": {"asn": "90", "net1_address": "10.90.0.0/24", "neighbors":[18,19],"cost":{"18": str(random.randint(start,stop)/100), "19":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "90", "net1_address": "10.90.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "91", "net1_address": "10.91.0.0/24", "neighbors":[] }})],
   [proxy[38],str({"labels": {"asn": "92", "net1_address": "10.92.0.0/24", "neighbors":[16,6] ,"cost":{"16": str(random.randint(start,stop)/100), "6":str(random.randint(start,stop)/100)}}},),str({"labels": {"asn": "92", "net1_address": "10.92.0.0/24", "neighbors":[]}})],
   [proxy[39],str({"labels": {"asn": "93", "net1_address": "10.93.0.0/24", "neighbors":[15,6],"cost":{"15": str(random.randint(start,stop)/100), "6":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "93", "net1_address": "10.93.0.0/24", "neighbors":[]}})],
   [proxy[40],str({"labels": {"asn": "94", "net1_address": "10.94.0.0/24", "neighbors":[6,5],"cost":{"6": str(random.randint(start,stop)/100), "5":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "94", "net1_address": "10.94.0.0/24", "neighbors":[]}})],
   [proxy[41],str({"labels": {"asn": "95", "net1_address": "10.95.0.0/24", "neighbors":[14,5],"cost":{"14": str(random.randint(start,stop)/100), "5":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "95", "net1_address": "10.95.0.0/24", "neighbors":[]}})],
   [proxy[42],str({"labels": {"asn": "96", "net1_address": "10.96.0.0/24", "neighbors":[15,14] ,"cost":{"15": str(random.randint(start,stop)/100), "14":str(random.randint(start,stop)/100)}}},),str({"labels": {"asn": "96", "net1_address": "10.96.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "97", "net1_address": "10.97.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "98", "net1_address": "10.98.0.0/24", "neighbors":[] }})],
   [proxy[43],str({"labels": {"asn": "99", "net1_address": "10.99.0.0/24", "neighbors":[5,13],"cost":{"5": str(random.randint(start,stop)/100), "13":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "99", "net1_address": "10.99.0.0/24", "neighbors":[]}})],
   [proxy[44],str({"labels": {"asn": "100", "net1_address": "10.100.0.0/24", "neighbors":[249, 62, 63, 64, 65, 66, 67],"cost":{"249": str(random.randint(start,stop)/100), "62":str(random.randint(start,stop)/100), "63":str(random.randint(start,stop)/100), "64":str(random.randint(start,stop)/100), "65":str(random.randint(start,stop)/100), "66":str(random.randint(start,stop)/100), "67":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "100", "net1_address": "10.100.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "101", "net1_address": "10.101.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "102", "net1_address": "10.102.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "103", "net1_address": "10.103.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "104", "net1_address": "10.104.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "105", "net1_address": "10.105.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "106", "net1_address": "10.106.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "107", "net1_address": "10.107.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "108", "net1_address": "10.108.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "109", "net1_address": "10.109.0.0/24", "neighbors":[] }})],
   [proxy[45],str({"labels": {"asn": "110", "net1_address": "10.110.0.0/24", "neighbors":[13,12],"cost":{"13": str(random.randint(start,stop)/100), "12":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "110", "net1_address": "10.110.0.0/24", "neighbors":[]}})],
   [proxy[46],str({"labels": {"asn": "111", "net1_address": "10.111.0.0/24", "neighbors":[16,7],"cost":{"16": str(random.randint(start,stop)/100), "17":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "111", "net1_address": "10.111.0.0/24", "neighbors":[]}})],
   [proxy[47],str({"labels": {"asn": "112", "net1_address": "10.112.0.0/24", "neighbors":[7,8],"cost":{"7": str(random.randint(start,stop)/100), "8":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "112", "net1_address": "10.112.0.0/24", "neighbors":[]}})],
   [proxy[48],str({"labels": {"asn": "113", "net1_address": "10.113.0.0/24", "neighbors":[2,3],"cost":{"2": str(random.randint(start,stop)/100), "3":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "113", "net1_address": "10.113.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "114", "net1_address": "10.114.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "115", "net1_address": "10.115.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "116", "net1_address": "10.116.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "117", "net1_address": "10.117.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "118", "net1_address": "10.118.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "119", "net1_address": "10.119.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "120", "net1_address": "10.120.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "121", "net1_address": "10.121.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "122", "net1_address": "10.122.0.0/24", "neighbors":[] }})],
   [proxy[49],str({"labels": {"asn": "123", "net1_address": "10.123.0.0/24", "neighbors":[4,12],"cost":{"4": str(random.randint(start,stop)/100), "12":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "123", "net1_address": "10.123.0.0/24", "neighbors":[]}})],
   [proxy[50],str({"labels": {"asn": "124", "net1_address": "10.124.0.0/24", "neighbors":[5,4],"cost":{"5": str(random.randint(start,stop)/100), "4":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "124", "net1_address": "10.124.0.0/24", "neighbors":[]}})],
   [proxy[51],str({"labels": {"asn": "125", "net1_address": "10.125.0.0/24", "neighbors":[4,11] ,"cost":{"4": str(random.randint(start,stop)/100), "11":str(random.randint(start,stop)/100)}}},),str({"labels": {"asn": "125", "net1_address": "10.125.0.0/24", "neighbors":[]}})],
   [proxy[52],str({"labels": {"asn": "126", "net1_address": "10.126.0.0/24", "neighbors":[3,4],"cost":{"3": str(random.randint(start,stop)/100), "4":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "126", "net1_address": "10.126.0.0/24", "neighbors":[]}})],
   [proxy[53],str({"labels": {"asn": "127", "net1_address": "10.127.0.0/24", "neighbors":[3,10],"cost":{"3": str(random.randint(start,stop)/100), "10":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "127", "net1_address": "10.127.0.0/24", "neighbors":[]}})],
   [proxy[54],str({"labels": {"asn": "128", "net1_address": "10.128.0.0/24", "neighbors":[9,10],"cost":{"9": str(random.randint(start,stop)/100), "10":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "128", "net1_address": "10.128.0.0/24", "neighbors":[]}})],
   [proxy[55],str({"labels": {"asn": "129", "net1_address": "10.129.0.0/24", "neighbors":[10,11],"cost":{"10": str(random.randint(start,stop)/100), "11":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "129", "net1_address": "10.129.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "130", "net1_address": "10.130.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "131", "net1_address": "10.131.0.0/24", "neighbors":[] }})],
   [proxy[56],str({"labels": {"asn": "132", "net1_address": "10.132.0.0/24", "neighbors":[9,20],"cost":{"9": str(random.randint(start,stop)/100), "20":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "132", "net1_address": "10.132.0.0/24", "neighbors":[]}})],
   [proxy[57],str({"labels": {"asn": "133", "net1_address": "10.133.0.0/24", "neighbors":[2,9],"cost":{"2": str(random.randint(start,stop)/100), "9":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "133", "net1_address": "10.133.0.0/24", "neighbors":[]}})],
   [proxy[58],str({"labels": {"asn": "134", "net1_address": "10.134.0.0/24", "neighbors":[9,19],"cost":{"9": str(random.randint(start,stop)/100), "19":str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "134", "net1_address": "10.134.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "135", "net1_address": "10.135.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "136", "net1_address": "10.136.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "137", "net1_address": "10.137.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "138", "net1_address": "10.138.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "139", "net1_address": "10.139.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "140", "net1_address": "10.140.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "141", "net1_address": "10.141.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "142", "net1_address": "10.142.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "143", "net1_address": "10.143.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "144", "net1_address": "10.144.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "145", "net1_address": "10.145.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "146", "net1_address": "10.146.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "147", "net1_address": "10.147.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "148", "net1_address": "10.148.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "149", "net1_address": "10.149.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "150", "net1_address": "10.150.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "151", "net1_address": "10.151.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "152", "net1_address": "10.152.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "153", "net1_address": "10.153.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "154", "net1_address": "10.154.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "155", "net1_address": "10.155.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "156", "net1_address": "10.156.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "157", "net1_address": "10.157.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "158", "net1_address": "10.158.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "159", "net1_address": "10.159.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "160", "net1_address": "10.160.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "161", "net1_address": "10.161.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "162", "net1_address": "10.162.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "163", "net1_address": "10.163.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "164", "net1_address": "10.164.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "165", "net1_address": "10.165.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "166", "net1_address": "10.166.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "167", "net1_address": "10.167.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "168", "net1_address": "10.168.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "169", "net1_address": "10.169.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "170", "net1_address": "10.170.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "171", "net1_address": "10.171.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "172", "net1_address": "10.172.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "173", "net1_address": "10.173.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "174", "net1_address": "10.174.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "175", "net1_address": "10.175.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "176", "net1_address": "10.176.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "177", "net1_address": "10.177.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "178", "net1_address": "10.178.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "179", "net1_address": "10.179.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "180", "net1_address": "10.180.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "181", "net1_address": "10.181.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "182", "net1_address": "10.182.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "183", "net1_address": "10.183.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "184", "net1_address": "10.184.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "185", "net1_address": "10.185.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "186", "net1_address": "10.186.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "187", "net1_address": "10.187.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "188", "net1_address": "10.188.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "189", "net1_address": "10.189.0.0/24", "neighbors":[] }})],
   [proxy[59],str({"labels": {"asn": "190", "net1_address": "10.190.0.0/24", "neighbors":[2],"cost":{"249": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "190", "net1_address": "10.190.0.0/24", "neighbors":[]}})],
   [proxy[60],str({"labels": {"asn": "191", "net1_address": "10.191.0.0/24", "neighbors":[3],"cost":{"3": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "191", "net1_address": "10.191.0.0/24", "neighbors":[]}})],
   [proxy[61],str({"labels": {"asn": "192", "net1_address": "10.192.0.0/24", "neighbors":[4],"cost":{"4": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "192", "net1_address": "10.192.0.0/24", "neighbors":[]}})],
   [proxy[62],str({"labels": {"asn": "193", "net1_address": "10.193.0.0/24", "neighbors":[5],"cost":{"5": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "193", "net1_address": "10.193.0.0/24", "neighbors":[]}})],
   [proxy[63],str({"labels": {"asn": "194", "net1_address": "10.194.0.0/24", "neighbors":[6],"cost":{"6": str(random.randint(start,stop)/100)}}},),str({"labels": {"asn": "194", "net1_address": "10.194.0.0/24", "neighbors":[]}})],
   [proxy[64],str({"labels": {"asn": "195", "net1_address": "10.195.0.0/24", "neighbors":[7],"cost":{"7": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "195", "net1_address": "10.195.0.0/24", "neighbors":[]}})],
   [proxy[65],str({"labels": {"asn": "196", "net1_address": "10.196.0.0/24", "neighbors":[8],"cost":{"8": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "196", "net1_address": "10.196.0.0/24", "neighbors":[]}})],
   [proxy[66],str({"labels": {"asn": "197", "net1_address": "10.197.0.0/24", "neighbors":[9],"cost":{"9": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "197", "net1_address": "10.197.0.0/24", "neighbors":[]}})],
   [proxy[67],str({"labels": {"asn": "198", "net1_address": "10.198.0.0/24", "neighbors":[10],"cost":{"10": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "198", "net1_address": "10.198.0.0/24", "neighbors":[]}})],
   [proxy[68],str({"labels": {"asn": "199", "net1_address": "10.199.0.0/24", "neighbors":[11],"cost":{"11": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "199", "net1_address": "10.199.0.0/24", "neighbors":[]}})],
   [proxy[69],str({"labels": {"asn": "200", "net1_address": "10.200.0.0/24", "neighbors":[12],"cost":{"12": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "200", "net1_address": "10.200.0.0/24", "neighbors":[]}})],
   [proxy[70],str({"labels": {"asn": "201", "net1_address": "10.201.0.0/24", "neighbors":[13],"cost":{"13": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "201", "net1_address": "10.201.0.0/24", "neighbors":[]}})],
   [proxy[71],str({"labels": {"asn": "202", "net1_address": "10.202.0.0/24", "neighbors":[14],"cost":{"14": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "202", "net1_address": "10.202.0.0/24", "neighbors":[]}})],
   [proxy[72],str({"labels": {"asn": "203", "net1_address": "10.203.0.0/24", "neighbors":[15],"cost":{"15": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "203", "net1_address": "10.203.0.0/24", "neighbors":[]}})],
   [proxy[73],str({"labels": {"asn": "204", "net1_address": "10.204.0.0/24", "neighbors":[16],"cost":{"16": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "204", "net1_address": "10.204.0.0/24", "neighbors":[]}})],
   [proxy[74],str({"labels": {"asn": "205", "net1_address": "10.205.0.0/24", "neighbors":[17],"cost":{"17": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "205", "net1_address": "10.205.0.0/24", "neighbors":[]}})],
   [proxy[75],str({"labels": {"asn": "206", "net1_address": "10.206.0.0/24", "neighbors":[18],"cost":{"18": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "206", "net1_address": "10.206.0.0/24", "neighbors":[]}})],
   [proxy[76],str({"labels": {"asn": "207", "net1_address": "10.207.0.0/24", "neighbors":[19],"cost":{"19": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "207", "net1_address": "10.207.0.0/24", "neighbors":[]}})],
   [proxy[77],str({"labels": {"asn": "208", "net1_address": "10.208.0.0/24", "neighbors":[20],"cost":{"20": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "208", "net1_address": "10.208.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "209", "net1_address": "10.209.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "210", "net1_address": "10.210.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "211", "net1_address": "10.211.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "212", "net1_address": "10.212.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "213", "net1_address": "10.213.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "214", "net1_address": "10.214.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "215", "net1_address": "10.215.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "216", "net1_address": "10.216.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "217", "net1_address": "10.217.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "218", "net1_address": "10.218.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "219", "net1_address": "10.219.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "220", "net1_address": "10.220.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "221", "net1_address": "10.221.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "222", "net1_address": "10.222.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "223", "net1_address": "10.223.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "224", "net1_address": "10.224.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "225", "net1_address": "10.225.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "226", "net1_address": "10.226.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "227", "net1_address": "10.227.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "228", "net1_address": "10.228.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "219", "net1_address": "10.229.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "230", "net1_address": "10.230.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "231", "net1_address": "10.231.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "232", "net1_address": "10.232.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "233", "net1_address": "10.233.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "234", "net1_address": "10.234.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "235", "net1_address": "10.235.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "236", "net1_address": "10.236.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "237", "net1_address": "10.237.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "238", "net1_address": "10.238.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "239", "net1_address": "10.239.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "240", "net1_address": "10.240.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "241", "net1_address": "10.241.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "242", "net1_address": "10.242.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "243", "net1_address": "10.243.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "244", "net1_address": "10.244.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "245", "net1_address": "10.245.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "246", "net1_address": "10.246.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "247", "net1_address": "10.247.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "248", "net1_address": "10.248.0.0/24", "neighbors":[] }})],
   [proxy[78],str({"labels": {"asn": "249", "net1_address": "10.249.0.0/24", "neighbors":[100],"cost":{"100": str(random.randint(start,stop)/100)} }},),str({"labels": {"asn": "249", "net1_address": "10.249.0.0/24", "neighbors":[]}})],
   [True,str({"labels": {"asn": "250", "net1_address": "10.250.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "251", "net1_address": "10.251.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "252", "net1_address": "10.252.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "253", "net1_address": "10.253.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "254", "net1_address": "10.254.0.0/24", "neighbors":[] }})],
   [True,str({"labels": {"asn": "11879", "net1_address": "0.0.0.0/24", "neighbors":[] }})]
 ]
 
def compile():
   with open('routingdbSLA.json', 'w', newline='') as fileout:
       write=csv.writer(fileout, delimiter=',')
       for element in array1:
         if element[0]==True:
           write.writerow([element[1]])
         else:
           write.writerow([element[2]])
     
if __name__=='__main__':
  compile()
   
