#!/usr/bin/python3

###############################################################################
# Security Group Dependency Grapher      								      #
# !!! Warning this is a python 3 project.                                     #
# ----------------------------------------------------------------------------#
#  Jason Cherry 2019.                                                         #
# ----------------------------------------------------------------------------#  
# A script to hash a file directory tree.                                     #  
# Software Requirements.
# -----------------------
# - Using Boto3 query the Amazon CLI to get the security groups information, 
#   then create a depandency graph relationship diagram. 
# 
###############################################################################
# Change list                                                                 #
# Date       		: Who 	: What                                            #
# -----------------------------------------------------------------------------
# 25th June 2019	: JC	: Initial version
# 22nd July 2019    : JC    : Modify to work with python 3.
#
#
# @Todo:
# optionally use .aws/credentials file.
# 
#
versionG = "1"
yearG = "23rd July 2019"

import stat, os
import sys
from pathlib import Path
import re

import string
import time
import datetime
import glob
import base64
import curses
#import threading	# For threading.
import inspect 		# For debugging line numbers.

#import codecs

#import gzip
#import zipfile
#import hashlib 

#import smtplib
#import ssl
#from email.mime.text import MIMEText

import boto3

from botocore.exceptions import ClientError



thisFileNameG = inspect.getframeinfo(inspect.currentframe()).filename
def lineNum():

    """Returns the current line number in our script. Pay homage to JCherry for this.
       Always, and I mean always give credit to your sources and original authors."""
    curFrT = inspect.currentframe()
    thisFileNameT = inspect.getframeinfo(curFrT.f_back).filename
    return str("[" + thisFileNameT + ":" + str(curFrT.f_back.f_lineno) +"] ")



##
# Global Parameter handling class.
#
# Most are set by the command line options.
#
class GlobalParamsG:

    def __init__(self):
        self.verboseM = 1                   # verbosity or debug output level.
        self.outputDirectoryM = None        # The output path.
        self.noClobberM = False             # Allow file overwrite.
        self.maxDepthSetM = False           # Is the max depth set?
        self.maxDepthM = 0                  # Max directory traversal depth.

        self.logFileM = None                # logfile file handle.
        self.loggingM = 3                   # logging level.

        self.noASCIIEscapeCodesM = True     # Set to true to use normal or old script output format.
        self.usingStdin = False

        self.generateHashesM = False # Generate the hashes from the file list.
        self.checkHashesM = False
        self.checkFileM = None
        self.monitorModeM = False
        self.monitorModeSleepM = 600
        self.writeOutputM = False

        self.usingCommandLineM = False

        self.testM = False


paramsG = GlobalParamsG()


def printInfo(stringP, infoLevelP):
    if paramsG.verboseM >= infoLevelP and paramsG.verboseM > 0:
        print(stringP)

    if paramsG.loggingM >= infoLevelP and paramsG.loggingM > 0:
        if paramsG.logFileM != None:
            paramsG.logFileM.write("printInfo(" + str(infoLevelP) + "): " + stringP + "\n")
            paramsG.logFileM.flush()

def printXYDebugNoLock(stringP, debugLevelP, Xp, Yp):
    
    if paramsG.verboseM >= debugLevelP and paramsG.verboseM > 0:
        #printXYClearText("printXYDebug(" + str(debugLevelP) + "): " + stringP, Xp, Yp)
        if len(stringP) < printXYMaxStringLengthG:
            pass
            for x in range(len(stringP), printXYMaxStringLengthG):
                stringP += ' '
        if paramsG.noASCIIEscapeCodesM == False:
            print("\033[" + str(Yp) + ";" + str(Xp) + "f" + "printXYDebug(" + str(debugLevelP) + "): " + stringP[:printXYMaxStringLengthG])
        else:
            print(stringP)

    if paramsG.loggingM >= debugLevelP and paramsG.loggingM > 0:
        if paramsG.logFileM != None:
            paramsG.logFileM.write("printXYDebug(" + str(debugLevelP) + "): " + stringP + '\n')

##
# calling lock more than once will cause a block.
# We need to not call the lock, if we've already called it.
#
def printDebugNoLock(stringP, debugLevelP):
    if paramsG.verboseM >= debugLevelP and paramsG.verboseM > 0:
        print("printDebug(" + str(debugLevelP) + "): " + stringP)

    if paramsG.loggingM >= debugLevelP and paramsG.loggingM > 0:
        if paramsG.logFileM != None:
            paramsG.logFileM.write("printDebug(" + str(debugLevelP) + "): " + stringP + '\n')

##
#
def printHelp():
    print("\n")
    print("-------------------------------------------------------------------------- ")
    print(" -** Security Group Grapher version <" + versionG + ".05> Date:" + yearG + " **-")
    print("-------------------------------------------------------------------------- ")
    print("  securityGroupGrapher.py <options>                                        ")
    print("         : Note -a is the default option.")
    print("           Options can be combined.")
    print("    -s   : Get the list of security groups.")
    print("    -i   : Get the list of security groups and dependant ec2 instances.")
    print("    -r   : Get the list of security groups and dependant rds databases.")
    print("    -e   : Get the list of security groups and dependant ecs services.")
    print("    -w   : Get the list of security groups and dependant network interfaces.")
    print("    -c   : Get the list of security groups for Elastic Cache.")
    print(".   -lb1 : Get the list of security groups for Load Balancers Version 1.")
    print(".   -lb2 : Get the list of security groups for Load Balancers Version 2.")
    print("    -a   : Get the list of security groups and all dependant ec2 instances.")
    print("           rds databases, ecs services, network interfaces, elastic cache.")
    print("    -g   : Write out graph file.\n")
    # print("\n  eg.                                                                      ",
    # print("\n     FIMChecker.py -q 3 -n -c hashList.txt /git/secure_rest                "
    # print("\n -**- Commands -**-                                                        ",
    # print("\n   -g : Generate a hash list from the passed path.                         ",
    # print("\n   -c <check file name> : check the hashes of the target files             ",
    # print("\n   -mm <n> : Monitor mode - Don't exit repeatedly check hashes. Sleep for  ",
    # print("\n       n seconds.                                                          "
    # print("\n -**- Options -**-                                                         ",
    # print("\n   -q <n> : Level to output Debug string to std out (1 to 10).             ",
    # print("\n   -l <n> : Level Log debug outtput to file.                               ",
    # print("\n   -o <output directory path> : Output directory to put files out to.      ",
    # print("\n      Try to create the output directory in the current directory.         ",
    # print("\n      Otherwise the directory named will be written to.                    ",
    # print("\n   -m <n> : Set the maximum directory depth to traverse                    ",
    # print("\n   -n : Set no clobber mode, so output files will not be over written.     "
    # print("\n -***-                                                                     ",
    print("   -cli : Use CLI Menu mode.")
    print("   -h   : Print this command line help.                                      ")
    print("--------------------------------------------------------------------------")

def printMenuHelp():
    #print("\n")
    print("-------------------------------------------------------------------------- ")
    print("--** Security Group Grapher Menu Help **-- ")
    print("-------------------------------------------------------------------------- ")
    print("help         : print the menu help.")
    print("help cli     : print the command line help.")
    print("switch profile : switch the current profile.")
    print('switch region  : switch the current region.')
    print('show dependancies  : Show the dependancies.')
    #print("show         : show the current settings.")
    print("show profile : display the current profile settings.")
    print("show profiles: display the currently available profiles from settings.")
    print("show region  : show the current region.")
    #print("write dependancies : Write out the current dependancy list.")
    #print("show sgs     : display the currently discovered security group dependancies.")
    print("clear        : clear the current security group dependancies.")
    #print("set profile  : set the current profile.")
    #print("set region   : set the current region.")
    print("exe <options>: execute the command line options as per the command line help.")
    #print("list regions : list the available regions.")
    print("list services: list the services available.")
    print("quit         : quit the program.")
    print("-------------------------------------------------------------------------- ")

##
# A class to store the loaded profile.
#
class AWSProfile:
    
    profilesG = None
    selectedProfileIndexG = -1
    selectedProfileNameG = None

    def __init__(self, nameP):
        nameT = str.strip(nameP)
        #
        # First initialisation fo the dict.
        #
        if AWSProfile.profilesG == None:
            AWSProfile.profilesG = {}
            AWSProfile.selectedProfileNameG = nameT # set the default profile.
            printInfo("Default Profile loaded: " + AWSProfile.selectedProfileNameG, 2)

        self.nameM = nameT

        self.accountM = ""
        self.regionM = None
        self.outputM = ""
        self.awsAccessKeyIDM = None
        self.awsSecretAccessKeyM = None

        if nameT not in AWSProfile.profilesG.keys():
            AWSProfile.profilesG[nameT] = self



    ##
    # Get the current profile object.
    #
    # return None if no profile is set. 
    # None will be the case if there is no config file.
    #
    @classmethod
    def GetSelected(cls):
        #print lineNum(), cls.selectedProfileIndexG
        #print lineNum(), str(cls.profilesG.keys())

        if cls.selectedProfileIndexG != -1:

            return cls.profilesG[list(cls.profilesG)[cls.selectedProfileIndexG]]
        else:
            return AWSProfile("default")


    ##
    # takes a name as a string, stores the index.
    #
    @classmethod
    def SetSelected(cls, nameP):
        indexT = -1
        if cls.profilesG != None:
            for x in cls.profilesG.keys():
                indexT+=1
                if nameP == x:
                    cls.selectedProfileIndexG = indexT
                    keyT = list(cls.profilesG)[indexT]

                    cls.selectedProfileNameG = cls.profilesG[keyT].nameM
                    #print(lineNum(), cls.selectedProfileNameG)
                    break


    def setAccount(self, nameP, accountP):
        nameT = str.strip(nameP)

        accountT = str.strip(accountP)
        self.accountM = accountT

        if nameT not in AWSProfile.profilesG.keys():
            AWSProfile.profilesG[nameT] = self
        else:
            AWSProfile.profilesG[nameT].accountM = accountT

    def setRegion(self, nameP, valueP):
        nameT = str.strip(nameP)

        valueT = str.strip(valueP)
        self.regionM = valueT

        if nameT not in AWSProfile.profilesG.keys():
            AWSProfile.profilesG[nameT] = self
        else:
            AWSProfile.profilesG[nameT].regionM = valueT

    def setOutput(self, nameP, valueP):
        nameT = str.strip(nameP)

        valueT = str.strip(valueP)
        self.outputM = valueT

        if nameT not in AWSProfile.profilesG.keys():
            AWSProfile.profilesG[nameT] = self
        else:
            AWSProfile.profilesG[nameT].outputM = valueT

    def setAWSAccessKeyID(self, nameP, valueP):
        nameT = str.strip(nameP)

        valueT = str.strip(valueP)
        self.awsAccessKeyIDM = valueT

        if nameT not in AWSProfile.profilesG.keys():
            AWSProfile.profilesG[nameT] = self
        else:
            AWSProfile.profilesG[nameT].awsAccessKeyIDM = valueT        

    def setAWSSecretAccessKey(self, nameP, valueP):
        nameT = str.strip(nameP)

        valueT = str.strip(valueP)
        self.awsSecretAccessKeyM = valueT

        if nameT not in AWSProfile.profilesG.keys():
            AWSProfile.profilesG[nameT] = self
        else:
            AWSProfile.profilesG[nameT].awsSecretAccessKeyM = valueT 

    ##
    # dislay the current profile.
    @classmethod
    def DisplayCurrentProfile(cls):

        if cls.selectedProfileIndexG == -1 and cls.profilesG != None:
            cls.SetSelected(cls.selectedProfileNameG)

        currentT = cls.GetSelected()
        #print lineNum(), str(currentT)
        if currentT != None:
            printInfo("The currently selected profile...",1)
            AWSProfile.DisplayProfile(currentT)
            
        else:
            printInfo("Profile: Default: " + str(cls.selectedProfileNameG), 1)

    @classmethod
    def DisplayProfile(cls, thisOneP):
        if thisOneP != None:
            
            printInfo("Name              : " + str(thisOneP.nameM),1)
            printInfo("Account number    : " + str(thisOneP.accountM),1)
            printInfo("Region            : " + str(thisOneP.regionM),1)
            printInfo("output Format     : " + str(thisOneP.outputM),1)
            printInfo("Access Key ID     : " + str(thisOneP.awsAccessKeyIDM),1)
            printInfo("Secret Access Key : " + str(thisOneP.awsSecretAccessKeyM),1)
            printInfo("",1)

    @classmethod
    def DisplayProfiles(cls):
        if cls.selectedProfileIndexG == -1 and cls.profilesG != None:
            cls.SetSelected(cls.selectedProfileNameG)

        for profileT in cls.profilesG.keys():
            #print lineNum(), profileT, cls.selectedProfileNameG
            if profileT == cls.selectedProfileNameG:
                printInfo(" -******************-",1)
                printInfo("-*Currently Selected*-",1)
                printInfo(" -******************-",1)

            AWSProfile.DisplayProfile(cls.profilesG[profileT])

    ##
    # This has some input processing.
    #
    @classmethod
    def SwitchProfile(cls, commandP):
        #print lineNum(), str(commandP)
        if cls.selectedProfileIndexG == -1 and cls.profilesG != None:
            cls.SetSelected(cls.selectedProfileNameG)
        exitT = False
        commandT = commandP
        while(exitT == False):
            indexT = -1
            printInfo("Select from the following list >",1)
            for profileT in AWSProfile.profilesG.keys():
                indexT +=1
                if profileT == AWSProfile.profilesG[list(AWSProfile.profilesG)[cls.selectedProfileIndexG]]:
                    printInfo(str(indexT) + ". " + AWSProfile.profilesG[profileT].nameM + str('*'),1)
                else:
                    printInfo(str(indexT) + ". " + AWSProfile.profilesG[profileT].nameM,1)


            #print lineNum(), str(commandP)
            if len(commandP) > 0:
                commandT = commandP[0]
            else:
                commandT = input("select profile] ")

            if commandT == 'q':
                break
            elif str.isdigit(commandT) == False or int(commandT) > indexT:
                printInfo("Invalid selection, try again or \'q\' to quit.",1)
            else:
                selectedT = list(AWSProfile.profilesG)[int(commandT)]
                AWSProfile.SetSelected(selectedT)
                break

##
    # This has some input processing.
    #
    @classmethod
    def SwitchRegion(cls, commandP):

        if cls.selectedProfileIndexG == -1 and cls.profilesG != None:
            cls.SetSelected(cls.selectedProfileNameG)
        
        exitT = False
        commandT = commandP
        
        while(exitT == False):
            indexT = -1
            printInfo("Select from the following list >",1)

            currentProfileT = AWSProfile.GetSelected()

            sessionT = boto3.session.Session(aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, aws_session_token=None, region_name=currentProfileT.regionM, botocore_session=None) #, profile_name=currentProfileT.nameM)

            regionListT = sessionT.get_available_regions('ec2')


            for regionT in regionListT:
                indexT +=1
                #print("Current: " + str.strip(str(currentProfileT.regionM.encode('ascii','ignore'))) + ", comparing to: " + str.strip(str(regionT.encode('ascii','ignore'))))

                if str.strip(str(regionT.encode('ascii','ignore'))) == str(currentProfileT.regionM.encode('ascii','ignore')):
                    printInfo(str(indexT) + ". " + regionT + str('*'),1)
                else:
                    printInfo(str(indexT) + ". " + regionT,1)


            #print lineNum(), str(commandP)
            if len(commandP) > 0:
                commandT = commandP[0]
            else:
                commandT = input("select region] ")

            if commandT == 'q':
                break
            elif str.isdigit(commandT) == False or int(commandT) > indexT:
                printInfo("Invalid selection, try again or \'q\' to quit.",1)
            else:
                selectedT = regionListT[int(commandT)]
                #print lineNum(), selectedT
                AWSProfile.GetSelected().regionM = selectedT
                break
    ##
    # dislay the current region.
    @classmethod
    def DisplayCurrentRegion(cls):
        
        if cls.selectedProfileIndexG == -1 and cls.profilesG != None:
            cls.SetSelected(cls.selectedProfileNameG)

        currentT = cls.GetSelected()
        if currentT != None:
            #printInfo("The currently select profile...",1)
            #printInfo("Name              : " + str(currentT.nameM),1)
            #printInfo("Account number    : " + str(currentT.accountM),1)
            printInfo("Current region is : " + str(currentT.regionM),1)
            #printInfo("output Format     : " + str(currentT.outputM),1)
            #printInfo("Access Key ID     : " + str(currentT.awsAccessKeyIDM),1)
            #printInfo("Secret Access Key : " + str(currentT.awsSecretAccessKeyM),1)
        else:
            printInfo("Profile: Default is set in your AWS config file, check there.", 1)


    def __str__(self):
        #print lineNum()
        return str(self.nameM) + " : " + str(self.accountM) + " : " + str(self.regionM) + " : " + str(self.outputM) + " : " + str(self.awsAccessKeyIDM) + " : " + str(self.awsSecretAccessKeyM)



class OutputFileHelper:


    def __init__(self):
        self.fileNamePrefixM = None
        self.outputDirM = None
        self.noClobberValueM = 0
        self.outputHashesFileM = None
        self.profileConfigFileM = None

        self.listOfDefaultPrefixesT = ['hashList','profiles','.aws/credentials']


    def setFileNamePrefix(self, fileNamePrefixP):
        self.fileNamePrefixM = fileNamePrefixP

    def closeFiles(self):

        if self.outputHashesFileM != None:
            self.outputHashesFileM.close()
        if self.profileConfigFileM != None:
            self.profileConfigFileM.close()


    def determineFilenamePrefix(self):

        fileNamePrefixT = ''

        if paramsG.verboseM > 3:
            printDebugNoLock(lineNum() + str(self.fileNamePrefixM), 1)

        if self.fileNamePrefixM != None:
            fileNamePrefixT = '_' + self.fileNamePrefixM # + '.txt'
        else:    
            fileNamePrefixT = ''
        
        self.fileNamePrefixM = fileNamePrefixT


    def determineOutputDirectory(self):
        
        outputDirT = "" #." 
        if paramsG.outputDirectoryM != None:
            outputDirT = os.path.join(outputDirT, paramsG.outputDirectoryM)
            printDebugNoLock(lineNum() + outputDirT + paramsG.outputDirectoryM,10)
        else:
            outputDirT = os.path.join(outputDirT, ".")
            printDebugNoLock(lineNum() + outputDirT, 10)

        self.outputDirM = outputDirT


    ##
    # FilenamePrefix must be obtained before this is run.
    #
    def determineNoClobberValue(self):

        # Figure out the noclobber value.
        noClobberValueT = 0
        if paramsG.noClobberM == True:
            wouldClobberT = False
            for y in xrange(0, 65535):
                wouldClobberT = False
                for x in xrange(0,len(self.listOfDefaultPrefixesT)):
                    
                    if noClobberValueT == 0:
                        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[x] + self.fileNamePrefixM + '.txt')
                        printDebugNoLock(lineNum() + " " + str(testT),5) 
                    else:
                        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[x] + self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.txt') # .padding('0',4) + '.txt')
                        printDebugNoLock(lineNum() + " " + str(testT),5)

                    if os.path.exists(testT):
                        #printInfo(lineNum(), testT
                        wouldClobberT = True
                        noClobberValueT += 1
                        break
                if wouldClobberT == False:
                    # We've got our value.
                    printDebugNoLock(lineNum() + "No Clobber value is: " + str(noClobberValueT), 5)
                    break

                self.noClobberValueM = noClobberValueT
  

    def openOutputHashesFile(self):

        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[0] + self.fileNamePrefixM + '.txt')
        if self.noClobberValueM != 0:
            testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[0] + self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.txt') #.pad('0',4) + '.txt')

        printDebugNoLock(lineNum() + "Opening File: " + testT , 4)

        self.outputHashesFileM = open(testT, 'w')


    def openConfigFile(self):

        # close if it's already open.
        if self.profileConfigFileM != None:
            self.profileConfigFileM.close()

        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[1] + self.fileNamePrefixM + '.cfg')
        # if self.noClobberValueM != 0:
        #     testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[0] + self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.txt') #.pad('0',4) + '.txt')

        printDebugNoLock(lineNum() + "Opening File: " + testT , 2)

        try:

            self.profileConfigFileM = open(testT, 'r')
        except Exception as extT:
            printInfo(str(extT),1)

        return self.profileConfigFileM


    def openAWSCredentialsFile(self):

        # close if it's already open.
        if self.profileConfigFileM != None:
            self.profileConfigFileM.close()

        testT = os.path.join(Path.home(), self.listOfDefaultPrefixesT[2])
        #print(lineNum(), testT)
        # if self.noClobberValueM != 0:
        #     testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[0] + self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.txt') #.pad('0',4) + '.txt')

        printDebugNoLock(lineNum() + "Opening File: " + testT , 2)
        try:

            self.profileConfigFileM = open(testT, 'r')
        except Exception as extT:
            printInfo(str(extT),1)
        return self.profileConfigFileM

    def loadAWSCredentialsFile(self):
        if self.profileConfigFileM != None:
            dataT = self.profileConfigFileM.readlines()

            #print lineNum(), str(dataT)
            currentProfileT = None
            for x in dataT:
                lineT = str.split(x,'=')
                #printInfo(lineNum() + str(lineT),1)
                #print(lineNum(), len(lineT))
                if len(lineT) >= 1:
                    tagT = str.strip(lineT[0])
                    #print(lineNum(), tagT)
                    if '[' in tagT:
                        indexEndT = tagT.find(']')
                        # We've got a name tag.
                        # starting a new profile Object.
                        currentProfileT = AWSProfile(tagT[1:indexEndT])
                        #print(lineNum(), currentProfileT)
                        pass
                    elif tagT == 'account':
                        currentProfileT.setAccount(currentProfileT.nameM, lineT[1])
                    elif tagT == 'region':
                        currentProfileT.setRegion(currentProfileT.nameM, lineT[1])
                    elif tagT == 'output':
                        currentProfileT.setOutput(currentProfileT.nameM, lineT[1])
                    elif tagT == 'aws_access_key_id':
                        currentProfileT.setAWSAccessKeyID(currentProfileT.nameM, lineT[1])
                    elif tagT == 'aws_secret_access_key':
                        currentProfileT.setAWSSecretAccessKey(currentProfileT.nameM, lineT[1])



                #print lineNum(), str(currentProfileT)
                #print lineNum(), x
                printDebugNoLock(lineNum() + str(AWSProfile.profilesG.keys()), 2)

    def loadConfigFile(self):
        if self.profileConfigFileM != None:
            dataT = self.profileConfigFileM.readlines()

            #print lineNum(), str(dataT)
            currentProfileT = None
            for x in dataT:
                lineT = str.split(x,'=')
                #print lineNum(), str(lineT)
                if len(lineT) >= 2:
                    tagT = str.strip(lineT[0])
                    if tagT == 'name':
                        # starting a new profile Object.
                        currentProfileT = AWSProfile(lineT[1])
                        pass
                    elif tagT == 'account':
                        currentProfileT.setAccount(currentProfileT.nameM, lineT[1])
                    elif tagT == 'region':
                        currentProfileT.setRegion(currentProfileT.nameM, lineT[1])
                    elif tagT == 'output':
                        currentProfileT.setOutput(currentProfileT.nameM, lineT[1])
                    elif tagT == 'aws_access_key_id':
                        currentProfileT.setAWSAccessKeyID(currentProfileT.nameM, lineT[1])
                    elif tagT == 'aws_secret_access_key':
                        currentProfileT.setAWSSecretAccessKey(currentProfileT.nameM, lineT[1])



                #print lineNum(), str(currentProfileT)
                #print lineNum(), x
                printDebugNoLock(lineNum() + str(AWSProfile.profilesG.keys()), 2)
            # for lineT in dataT:
            #     print lineNum(), dataT

    def openLogFileOld(self):

        testT = os.path.join(os.getcwd(), time.strftime('%Y%m%d_%H%M%S_') + 'debugLog' + '.log')

        try:
            logFileT = open(testT, 'w')
            paramsG.logFileM = logFileT
            printDebugNoLock(lineNum() + "Logging to file: " + str(testT), 4)
        except IOError as fileOpenException:
            paramsG.logFileM = None
            print(lineNum(), "I/O error({0}): {1}".format(fileOpenException.errno, fileOpenException.strerror))

        return logFileT

    ##
    # Put the log file in the output directory
    # 
    # @todo paramsG.logfileM should locate to this class.
    #
    def openLogFile(self):

        #testT = os.path.join(os.getcwd(), time.strftime('%Y%m%d_%H%M%S_') + 'debugLog' + '.log')
        testT = os.path.join(self.outputDirM, time.strftime('%Y%m%d_%H%M%S_') + 'debugLog' + self.fileNamePrefixM + '.log')

        if self.noClobberValueM != 0:
            testT = os.path.join(self.outputDirM, time.strftime('%Y%m%d_%H%M%S_') + 'debugLog'+ self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.log') #.pad('0',4) + '.txt')

        printDebugNoLock(lineNum() + "Opening File: " + testT , 4)

        try:
            logFileT = open(testT, 'w')
            paramsG.logFileM = logFileT
            printDebugNoLock(lineNum() + "Logging to file: " + str(testT), 4)
        except IOError as fileOpenException:
            paramsG.logFileM = None
            print(lineNum(), "I/O error({0}): {1}".format(fileOpenException.errno, fileOpenException.strerror))

        return logFileT


outputFilesG = OutputFileHelper()

##
# Security Group Dependancy List
#
DependancyListG = {}
NetworkInterfaceDependancyListG = {}
InstancesDependancyListG = {}

blankCountG = 0

#import tty

def processMenu(commandP):

    global DependancyListG
    global blankCountG
    
    #tty.setraw(sys.stdin)
    commandsT = str.split(commandP)

    numCommandsT = len(commandsT)
    #print lineNum(), numCommandsT
    if numCommandsT == 0:
        blankCountG += 1
        if blankCountG >= 4:
            print("type \'quit\' to quit!, type 'help' to display the menu help.")
            blankCountG = 0

    currentComandT = -1
    skipCommandT = False
    for commandT in commandsT:
        currentComandT += 1
        blankCountG = 0

        #print lineNum(), commandT
        
        # skip if the current command was part of the last one.
        if skipCommandT == True:
            skipCommandT = False
            #print lineNum(), "skipping..."
            continue

        # help... 
        if commandT == 'help':
            if numCommandsT > (currentComandT + 1):
                if commandsT[currentComandT + 1] == 'cli':
                    skipCommandT = True
                    printHelp()
                    continue
              
            printMenuHelp()
            continue

        # show... 
        if commandT == 'show':
            if numCommandsT > (currentComandT + 1):
                if commandsT[currentComandT + 1] == 'profile':
                    skipCommandT = True
                    AWSProfile.DisplayCurrentProfile()
                    continue
                if commandsT[currentComandT + 1] == 'profiles':
                    skipCommandT = True
                    AWSProfile.DisplayProfiles()
                    continue
                if commandsT[currentComandT + 1] == 'region':
                    skipCommandT = True
                    AWSProfile.DisplayCurrentRegion()
                    continue
                if commandsT[currentComandT + 1] == 'dependancies':
                    skipCommandT = True
                    showDependancyList()
                    continue

            
            printInfo("show what?", 1)  
            continue
            #printMenuHelp()

        if commandT == 's':
            printInfo("You can\'t go south!",1)
            continue
        if commandT == 'n':
            printInfo("You can\'t go north!",1)
            continue
        if commandT == 'w':
            printInfo("You go west!",1)
            time.sleep(2)
            printInfo("You enter a dark cave. You can see a glowing light at the end of the cave.",1)
            time.sleep(5)
            printInfo("You hear footsteps behind you.... you hear a moan in the dark in front of you.",1)
            time.sleep(5)
            printInfo("You are grabbed from behind, and realise a zombie has their arms around you...",1)
            time.sleep(5)
            printInfo("You smell the breath of the zombie as it bites you on the neck...",1)
            time.sleep(5)
            printInfo("You here other zombies approching from the dark...", 1)
            time.sleep(5)
            printInfo("..... you are dead.",1)
            time.sleep(5)
            printInfo("The End.",1)
            time.sleep(5)
            continue
        if commandT == 'e':
            print("You can\'t go east!")
            continue

        if commandT == 'list':
            if numCommandsT > (currentComandT + 1):
                if commandsT[currentComandT + 1] == 'regions':
                    skipCommandT = True
                    #AWSProfile.DisplayCurrentProfile()
                    continue
                if commandsT[currentComandT + 1] == 'services':
                    skipCommandT = True
                    listServices()
                    continue

            printInfo("list what?", 1)
            continue

        if commandT == 'exe':
            processCommandLine(None, cliP=commandsT)
            showDependancyList()
            break

        if commandT == 'clear':
            printInfo("Clearing all Dependancy lists. No second chances.",1)
            DependancyListG = {}
            NetworkInterfaceDependancyListG = {}
            InstancesDependancyListG = {}
            continue



        if commandT == 'switch':
            if numCommandsT > (currentComandT + 1):
                if commandsT[currentComandT + 1] == 'profile':
                    skipCommandT = True
                    AWSProfile.SwitchProfile(commandsT[currentComandT+2:])
                    break
                    #AWSProfile.DisplayCurrentProfile()
                    
                if commandsT[currentComandT + 1] == 'region':
                    skipCommandT = True

                    AWSProfile.SwitchRegion(commandsT[currentComandT+2:])
                    break
                    

            printInfo("switch what?", 1)
            continue

        if commandT == 'test':
            test()
            continue

        if commandT != 'quit':
        #print lineNum(), commandT
            printInfo("That didn\'t work...> " + str(commandT),1)


            #printMenuHelp()
        #currentComandT += 1
    

##
# processCommandLine()
#   
def processCommandLine(fileNameP, cliP=None):

    #print lineNum(), fileNameP

    listOfFilesT = None
    currentParamT = 1
    fileNameT = None
    paramsG.unicodeM = False
    skipT = 0
    topLevelDirT = None

    argumentListT = None
    
    #print lineNum(), cliP
    if cliP == None:
        argumentListT = sys.argv
        #print lineNum(), argumentListT
    else:

        argumentListT = cliP
                #argumentListT.append('securityGroupGrapher') 
        #for x in cliP:
        #    argumentListT.append(x)       
        #argumentListT = cliP

    #print(lineNum() + str(sys.argv) + " : " + str(argumentListT))

    #sys.exit()
    for argT in argumentListT[1:]:
        #print lineNum(), str(argT), len(argumentListT)
        #sys.exit()
        if skipT > 0:
            skipT = 0
            currentParamT += 1
            printDebugNoLock(lineNum() + "Skipping Paremeter: " + str(argT), 4)
            continue
        if os.path.isdir(argT) == True:
            printDebugNoLock(lineNum() + str(argT), 6)
            printDebugNoLock(lineNum() + "Maxdepth set to: " + str(paramsG.maxDepthM), 6)

            printInfo("%s" % ("[+] Building Directory List. Please wait..."),1)
            listOfFilesT, topLevelDirT = getAllFilesInDirectory(argT, paramsG.maxDepthM)
            fileReadT = argumentListT[currentParamT]

            if fileNameT == None:                
                for x in xrange(0,10):
                    fileNameT = string.split(fileReadT, ".")[x]
                    if len(fileNameT) > 0:
                        printDebugNoLock(lineNum() + "Directory name set to: " + str(fileNameT), 4)
                        break
                printDebugNoLock(lineNum() + fileNameT, 5)

            if (fileNameT != None): 
                fileNameP = fileNameT
                fileNameP = string.replace(fileNameP,'/','')
                fileNameP = string.replace(fileNameP,'\\','')
                fileNameT = fileNameP
            
            currentParamT += 1
            continue

        
        elif argT == '-o':
            if len(argumentListT[1:]) > currentParamT:
                printDebugNoLock(lineNum() + str(argumentListT[1:]) + " : " + str(currentParamT) + " : " + str(argT) + " : " + str(len(argumentListT[1:])), 6)
                printDebugNoLock(lineNum() + str(argumentListT[currentParamT + 1]) ,1)
                paramsG.outputDirectoryM = str(argumentListT[currentParamT + 1])
                printDebugNoLock(lineNum() + str(paramsG.outputDirectoryM) , 1)

                currentParamT += 1

                skipT = 1
                ##d = os.path.dirname(paramsG.outputDirectoryM)
                ##printDebugNoLock(lineNum() + str(d),1)
                if not os.path.exists(paramsG.outputDirectoryM):
                    os.makedirs(paramsG.outputDirectoryM)
                else:
                    if paramsG.verboseM >= 3:
                        printInfo("Output Directory \'%s\'%s" % (str(paramsG.outputDirectoryM), " already exists!"),1)
                continue
            else:
                currentParamT += 1
                continue
        elif argT == '-n': # Noclobber
            printInfo("[+] Noclobber set on.", 4)
            currentParamT += 1
            paramsG.noClobberM = True
            continue
        elif argT == '-m': # For maxdepth and level
            paramsG.maxDepthM = 0
            if len(argumentListT[1:]) > currentParamT:
                try:
                    paramsG.maxDepthM = int(argumentListT[currentParamT+1])
                    printDebugNoLock(lineNum() + "MaxDepth set to: " + str(paramsG.maxDepthM), 1)
                    if paramsG.maxDepthM == 0:
                        paramsG.maxDepthSetM = False
                    else:
                        paramsG.maxDepthSetM = True    
                    
                    currentParamT += 1
                    skipT = 1
                    
                except ValueError:
                    currentParamT += 1
                    paramsG.maxDepthSetM = False
                    paramsG.maxDepthM = 0

                printInfo("[+] MaxDepth set to: " + str(paramsG.maxDepthM), 1)

                
                continue
            else:
                paramsG.maxDepthSetM = False
                currentParamT += 1
                continue

        elif argT == '-q': # For verbose and level
            # Simply switch on quiet mode.
            # At the moment just set verbose mode to 3.
            # I envisage that we'll have multiple levels of verbosity.
            paramsG.verboseM = 0

            if len(argumentListT[1:]) > currentParamT:
                try:
                    paramsG.verboseM = int(argumentListT[currentParamT + 1])
                    currentParamT += 1
                    skipT = 1
                except ValueError:
                    currentParamT += 1
                    paramsG.verboseM = 0

                printInfo("[+] Verbosity set to: " + str(paramsG.verboseM), 4)
                printInfo("[+] Commandline: " + str(argumentListT[1:]), 4)                
                continue

            else:
                paramsG.verboseM = 0
                currentParamT += 1
                continue

        elif argT == '-mm': # For verbose and level
            # Simply switch on quiet mode.
            # At the moment just set verbose mode to 3.
            # I envisage that we'll have multiple levels of verbosity.
            paramsG.monitorModeM = True
            paramsG.monitorModeSleepM = 600

            if len(argumentListT[1:]) > currentParamT:
                try:
                    paramsG.monitorModeSleepM = int(argumentListT[currentParamT + 1])
                    currentParamT += 1
                    skipT = 1
                except ValueError:
                    currentParamT += 1
                    paramsG.monitorModeSleepM = 600

                printInfo("[+] Monitor Mode Sleep time set to: " + str(paramsG.monitorModeSleepM), 1)
                #printInfo("[+] Commandline: " + str(sys.argv[1:]), 4)                
                continue

            else:
                paramsG.monitorModeSleepM = 600
                paramsG.monitorModeM = False
                currentParamT += 1
                continue
                           
        elif argT == '-l': # For verbose and level logging

            paramsG.loggingM = 3

            if len(argumentListT[1:]) > currentParamT:
                try:
                    #printInfo(lineNum(), currentParamT, sys.argv[currentParamT], sys.argv[currentParamT+1])
                    paramsG.loggingM = int(argumentListT[currentParamT+1])
                    currentParamT += 1
                    skipT = 1
                except ValueError:
                    currentParamT += 1
                    paramsG.loggingM = 0

                if paramsG.loggingM > 0:
                    outputFilesG.openLogFileOld()           #### !!!!! Open the log file! only if logging value is set!

                printInfo(lineNum() + "Logging value: " + str(paramsG.loggingM),3)

                continue
            else:
                outputFilesG.openLogFileOld()               #### Open the log file...
                paramsG.loggingM = 3
                currentParamT += 1
                continue

        elif argT == '-d': # For very verbose debug output
            # Simply switch on quiet mode.
            # At the moment just set verbose mode to 3.
            # I envisage that we'll have multiple levels of verbosity.
            paramsG.verboseM = 11
            printInfo(lineNum() + "*** Debug Mode ***", 1)

            printInfo(lineNum() + "Outputting all output to stdout, verbose mode turned up to 11.", 3)
            currentParamT += 1

        elif argT == '-s': # Get security Groups
            #paramsG.generateHashesM = True
            currentParamT += 1

            printInfo("[+] Getting Security Groups...",1)
            getSecurityGroups()
            continue

        elif argT == '-i':
            currentParamT += 1
            printInfo("[+] Getting EC2 Instance Security Groups...",1)
            #getSecurityGroups()
        
            getInstancesSecurityGroups()
            continue



        elif argT == '-r':
            currentParamT +=1
            printInfo("[+] Getting RDS Database Security Groups...",1)

            #printInfo("[+] Getting Security Groups...",1)
            #getSecurityGroups()
            #getInstancesSecurityGroups()
            #getNetworkInterfacesSecurityGroups()

            getRDSSGs()
            #getECSs()
            continue

        elif argT == '-e':
            currentParamT +=1
            printInfo("[+] Getting ECS Security Groups...",1)
            #getSecurityGroups()
        
            #getInstancesSecurityGroups()
            #getNetworkInterfacesSecurityGroups()

            #getRDSSGs()
            getECSs()
            continue
        elif argT == '-w':
            currentParamT +=1
            printInfo("[+] Getting Network Interface Security Groups...",1)
            #getSecurityGroups()
        
            #getInstancesSecurityGroups()
            getNetworkInterfacesSecurityGroups()

            #getRDSSGs()
            #getECSs()
            continue
        elif argT == '-c':
            currentParamT += 1
            printInfo("[+] Getting Elastic Cache Security Groups...",1)
            getElasticCacheSecurityGroups()
            continue

        elif argT == '-lb1':
            currentParamT += 1
            printInfo("[+] Getting Load Balancers version 1 Security Groups...", 1)
            getLoadBalancerV1SecurityGroups()

            continue

        elif argT == '-lb2':
            currentParamT += 1
            printInfo("[+] Getting Load Balancers version 2 Security Groups...", 1)
            getLoadBalancerV2SecurityGroups()

            continue

        elif argT == '-a':
            currentParamT += 1
            
            printInfo("[+] Getting All Security Groups...",1)

            printInfo("[+] Getting Security Groups...",1)
            getSecurityGroups()
            printInfo("[+] Getting Instance Security Groups...",1)
            getInstancesSecurityGroups()
            printInfo("[+] Getting NW Interface Security Groups...",1)
            getNetworkInterfacesSecurityGroups()
            printInfo("[+] Getting RDS Security Groups...",1)
            getRDSSGs()
            printInfo("[+] Getting ECS Security Groups...",1)
            getECSs()
            printInfo("[+] Getting Elastic Cache Security Groups...",1)
            getElasticCacheSecurityGroups()
            printInfo("[+] Getting Load Balancer V1 Security Groups...",1)
            getLoadBalancerV1SecurityGroups()
            printInfo("[+] Getting Load Balancer V2 Security Groups...",1)
            getLoadBalancerV2SecurityGroups()

            continue

        elif argT == '-g':
            currentParamT += 1
            printInfo("[+] Writing out Graph file.",1)
            paramsG.writeOutputM = True
  
        elif argT == '-cli':
            paramsG.usingCommandLineM = True
            printMenuHelp()
            #sys.exit()

        elif argT == '-h': # help
            printHelp()

            sys.exit()

        elif argT == '-test':
            paramsG.testM = True

            #test()
            #sys.exit()

        else:
            listOfFilesT = []
            listOfFilesT.append(argT)
            currentParamT += 1
            printInfo("Syntax Error - Invalid Commandline Parameter: " + str(argT), 1)
            printInfo("Will exit program.... ", 1)

            printHelp()
            
            sys.exit()

    if (fileNameT != None):
        #printInfo(lineNum()
        fileNameP = fileNameT
        fileNameP = string.replace(fileNameP,'/','')
        fileNameP = string.replace(fileNameP,'\\','')
        fileNameP = string.replace(fileNameP,':',"_")
        fileNameT = fileNameP
    else:
        if len(argumentListT) == 1:
            printInfo("[+] Getting All Security Groups...",1)

            printInfo("[+] Getting Security Groups...",1)
            getSecurityGroups()
            printInfo("[+] Getting Instance Security Groups...",1)
            getInstancesSecurityGroups()
            printInfo("[+] Getting NW Interface Security Groups...",1)
            getNetworkInterfacesSecurityGroups()
            printInfo("[+] Getting RDS Security Groups...",1)
            getRDSSGs()
            printInfo("[+] Getting ECS Security Groups...",1)
            getECSs()
            printInfo("[+] Getting Elastic Cache Security Groups...",1)
            getElasticCacheSecurityGroups()
            printInfo("[+] Getting Load Balancer V1 Security Groups...",1)
            getLoadBalancerV1SecurityGroups()
            printInfo("[+] Getting Load Balancer V2 Security Groups...",1)
            getLoadBalancerV2SecurityGroups()
    #printDebugNoLock(lineNum() + str(fileNameT) + " : " + str(listOfFilesT), 10)

    return  fileNameT, listOfFilesT, topLevelDirT


def parseNetworkInterfaceSecurityGroups(interfaceP, securityGroupListP):

    securityGroupPoliciesG = ['Groups']

    if 1==1 or interfaceP['NetworkInterfaceId'] == "eni-02751f5c64db1cad1":
        printDebugNoLock(lineNum() + str(len(interfaceP)) + " " + str(interfaceP),4)
        currentNetworkInterfaceT = str(interfaceP['NetworkInterfaceId'])

        printInfo("\n\nNetworkInterfaceId:  " + currentNetworkInterfaceT, 2)
        if currentNetworkInterfaceT not in DependancyListG.keys():
            printDebugNoLock(lineNum() + 'Adding ' + currentNetworkInterfaceT + ' dependancy list.',4)
            DependancyListG[currentNetworkInterfaceT] = []

        printInfo("Description:         " + str(interfaceP['Description']),2)
        printDebugNoLock(lineNum() + "Keys:        " + str(interfaceP.keys()),4)

        for groupPolicyT in securityGroupPoliciesG:
            printDebugNoLock(lineNum() + "************",4)
            printDebugNoLock(lineNum() + groupPolicyT,4)
            printDebugNoLock(lineNum() + "************",4)

            for sgT in interfaceP[groupPolicyT]:
                printDebugNoLock(lineNum() + "Keys:  " + str(sgT.keys()),4)

                for attribT in sgT:

                    if attribT == 'GroupName':
                        printDebugNoLock(lineNum() + str(sgT[attribT]),4)
                    if attribT == 'GroupId':
                        dependantGroupT = str(sgT[attribT])
                        printDebugNoLock(lineNum() + dependantGroupT,4)
                        securityGroupListP[dependantGroupT] = sgT

                        if dependantGroupT in DependancyListG.keys():
                            if currentNetworkInterfaceT not in DependancyListG[dependantGroupT] and currentNetworkInterfaceT != dependantGroupT:
                                DependancyListG[dependantGroupT].append(currentNetworkInterfaceT)

                                printDebugNoLock(lineNum() + "Adding to existing " + currentNetworkInterfaceT + " to " + dependantGroupT + " dependancy.",4)

                            else:
                                printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentNetworkInterfaceT + " to " + dependantGroupT + " dependancy.",4)

                        else:
                            DependancyListG[dependantGroupT] = []
                            DependancyListG[dependantGroupT].append(currentNetworkInterfaceT)
                            printDebugNoLock(lineNum() + "Initially adding   " + currentNetworkInterfaceT + " to " + dependantGroupT + " dependancy.",4)


        if len(securityGroupListP.keys()) > 0:
            # Sort and eliminate duplicates.
            printDebugNoLock(lineNum() + str(securityGroupListP),4)
            printInfo("\nSecurity Group Dependancy List for this Network Interface: " + str(currentNetworkInterfaceT),2)
            printDebugNoLock(lineNum() + str(securityGroupListP.keys()), 4)
            for securityGroupIDT in securityGroupListP.keys():
                printDebugNoLock(lineNum() + str(securityGroupIDT),4)
                testT = securityGroupListP[securityGroupIDT]
                printDebugNoLock(lineNum() + str(testT.keys()),4)
                printInfo("\n",2)
                for attributeT in testT.keys():
                    printInfo(str(testT[attributeT]),2)

def parseECSSecurityGroup(serviceNameP, securityGroupP, securityGroupListP):

    #securityGroupPoliciesG = ['Groups']
    try:
        if 1==1 or interfaceP['NetworkInterfaceId'] == "eni-02751f5c64db1cad1":
            #printDebugNoLock(lineNum() + str(len(interfaceP)) + " " + str(interfaceP),4)
            currentServiceNameT = serviceNameP

            printInfo("\n\nService Name.  : " + currentServiceNameT,2)
            printInfo("Security Group : " + securityGroupP,2)
            if currentServiceNameT not in DependancyListG.keys():
                printDebugNoLock(lineNum() + 'Adding ' + currentServiceNameT + ' dependancy list.',4)
                DependancyListG[currentServiceNameT] = []

            #printInfo("Description:         " + str(interfaceP['Description'])
            #printDebugNoLock(lineNum() + "Keys:        " + str(interfaceP.keys()),1)

            # for groupPolicyT in securityGroupPoliciesG:
            #     printDebugNoLock(lineNum() + "************",4)
            #     printDebugNoLock(lineNum() + groupPolicyT,4)
            #     printDebugNoLock(lineNum() + "************",4)

            #     for key3T in interfaceP[groupPolicyT]:
            #         printDebugNoLock(lineNum() + "Keys:  " + str(key3T.keys()),4)

            #         for idT in key3T:

                        #if idT == 'GroupName':
                        #    printDebugNoLock(lineNum() + str(key3T[idT]),4)
                        #if idT == 'GroupId':
            dependantGroupT = securityGroupP
            printDebugNoLock(lineNum() + dependantGroupT,4)
            securityGroupListP[dependantGroupT] = serviceNameP

            if dependantGroupT in DependancyListG.keys():
                if currentServiceNameT not in DependancyListG[dependantGroupT] and currentServiceNameT != dependantGroupT:
                    DependancyListG[dependantGroupT].append(currentServiceNameT)

                    printDebugNoLock(lineNum() + "Adding to existing " + currentServiceNameT + " to " + dependantGroupT + " dependancy.",4)

                else:
                    printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentServiceNameT + " to " + dependantGroupT + " dependancy.",4)

            else:
                DependancyListG[dependantGroupT] = []
                DependancyListG[dependantGroupT].append(currentServiceNameT)
                printDebugNoLock(lineNum() + "Initially adding   " + currentServiceNameT + " to " + dependantGroupT + " dependancy.",4)


            if len(securityGroupListP.keys()) > 0:
                # Sort and eliminate duplicates.
                printDebugNoLock(lineNum() + str(securityGroupListP),4)
                printInfo("\nSecurity Group Dependancy List for this ECS Service: " + str(currentServiceNameT),2)
                printDebugNoLock(lineNum() + str(securityGroupListP.keys()), 4)
                for securityGroupIDT in securityGroupListP.keys():
                    printDebugNoLock(lineNum() + str(securityGroupIDT),4)

                    #printInfo("\n",
                    #for attributeT in testT.keys():
                    #    printInfo(str(testT[attributeT])
    except ClientError as e:            
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))

def parseSecurityGroup(secGrpP, securityGroupListP, ipRangesListP):


    try:
        securityGroupPoliciesG = ['IpPermissionsEgress','IpPermissions']

        groupIDKeyT = 'DBSecurityGroupName'
        if groupIDKeyT not in secGrpP.keys():
            groupIDKeyT = 'VpcSecurityGroupId'
        if groupIDKeyT not in secGrpP.keys():
            groupIDKeyT = 'GroupId'

        printDebugNoLock(lineNum() + "Group ID set to: " + str(groupIDKeyT), 5)

        printDebugNoLock(lineNum() + str(secGrpP.keys()),5)
        
        if 1== 1 or secGrpP[groupIDKeyT] == 'sg-0a675ba76560bf0d2' or secGrpP[groupIDKeyT] == 'sg-00b5869f03235e921': # or secGrpP[groupIDKeyT] == 'sg-5c722b21' or secGrpP[groupIDKeyT] == 'sg-0606207b':
            isDefaultGroupT = False
            printDebugNoLock(lineNum() + str(secGrpP),4)
            currentSecurityGroupT = str(secGrpP[groupIDKeyT])
            if "GroupName" in secGrpP.keys():
                #printInfo("GroupName  : " + str(secGrpP['GroupName']),1)
                if str(secGrpP['GroupName']) == 'default':
                    printDebugNoLock(lineNum() + "Group: " + str(secGrpP[groupIDKeyT]) + " is a default group.", 2)
                    currentSecurityGroupT += '*'
                    #print lineNum() + str(currentSecurityGroupT)
            printInfo("\n\n" + groupIDKeyT + ":     " + currentSecurityGroupT,1)
            if currentSecurityGroupT not in DependancyListG.keys():
                printDebugNoLock(lineNum() + 'Adding ' + currentSecurityGroupT + ' dependancy list.',4)
                DependancyListG[currentSecurityGroupT] = []
            if "GroupName" in secGrpP.keys():
                printInfo("GroupName  : " + str(secGrpP['GroupName']),1)
                # if str(secGrpP['GroupName']) == 'default':
                #     printDebugNoLock(lineNum() + "Group: " + str(secGrpP[groupIDKeyT]) + " is a default group.", 1)
                #     isDefaultGroupT = True
                #     if isDefaultGroupT == True:
                #         dependantGroupT += '*'
                #         print lineNum() + str(dependantGroupT)
            if "Status" in secGrpP.keys():
                printInfo("Status     : " + str(secGrpP['Status']),1)
            if 'Description' in secGrpP.keys():
                printInfo("Description: " + str(secGrpP['Description']),1)

            #print lineNum() + str(secGrpP.keys())
            printDebugNoLock(lineNum() + "Keys:        " + str(secGrpP.keys()),4)
            for groupPolicyT in securityGroupPoliciesG:
                #print lineNum() + str(groupPolicyT)
                printDebugNoLock(lineNum() + "************",4)
                printDebugNoLock(lineNum() + groupPolicyT,4)
                printDebugNoLock(lineNum() + "************",4)
                #printInfo(lineNum()
                if groupPolicyT in secGrpP.keys():
                    #print lineNum() + str(secGrpP)
                    for ipPermissionsT in secGrpP[groupPolicyT]:

                        printDebugNoLock(lineNum() + "Keys:  " + str(ipPermissionsT.keys()),4)
                        printDebugNoLock(lineNum() + str(secGrpP[groupPolicyT]),4)
                        for xT in ipPermissionsT:

                            if (xT == 'UserIdGroupPairs'):
                                #print lineNum() + str(isDefaultGroupT)
                                if len(ipPermissionsT[xT]) > 0:
                                    printDebugNoLock(lineNum() + str(ipPermissionsT[xT]), 3)
                                for sgGroupT in ipPermissionsT[xT]:
                                    #print lineNum() + str(sgGroupT)
                                    for idT in sgGroupT.keys():
                                        if idT == groupIDKeyT:
                                            #print lineNum()
                                            dependantGroupT = str(sgGroupT[idT])
                                            
                                           #if depen
                                            printDebugNoLock(lineNum() + dependantGroupT,4)
                                            securityGroupListP.append(dependantGroupT)
                                            if dependantGroupT in DependancyListG.keys():
                                                if currentSecurityGroupT not in DependancyListG[dependantGroupT] and currentSecurityGroupT != dependantGroupT:
                                                    DependancyListG[dependantGroupT].append(currentSecurityGroupT)

                                                    printDebugNoLock(lineNum() + "Adding to existing " + currentSecurityGroupT + " to " + dependantGroupT + " dependancy.",4)

                                                else:
                                                    printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentSecurityGroupT + " to " + dependantGroupT + " dependancy.",4)

                                            else:
                                                DependancyListG[dependantGroupT] = []
                                                DependancyListG[dependantGroupT].append(currentSecurityGroupT)
                                                printDebugNoLock(lineNum() + "Initially adding   " + currentSecurityGroupT + " to " + dependantGroupT + " dependancy.",4)

                            ipToPortT = 0
                            ipFromPortT = 0
                            ipPrototcolT = ''
                            ipDescriptionT = ''
                            
                            if 'ToPort' in ipPermissionsT.keys() or xT == 'ToPort':
                                printDebugNoLock(lineNum() + "ToPort:    " + str(ipPermissionsT['ToPort']),3)
                                ipToPortT = str(ipPermissionsT['ToPort'])
                            if 'FromPort' in ipPermissionsT.keys() or xT == 'FromPort':
                                printDebugNoLock(lineNum() + "FromPort:  " + str(ipPermissionsT['FromPort']),3)
                                ipFromPortT = str(ipPermissionsT['FromPort'])
                            if 'IpProtocol' in ipPermissionsT.keys() or xT == 'IpProtocol':
                                printDebugNoLock(lineNum() + "IpProtocol:" + str(ipPermissionsT['IpProtocol']),3)
                                ipPrototcolT = str(ipPermissionsT['IpProtocol'])
                            if 'Description' in ipPermissionsT.keys() or xT == 'Description':
                                printDebugNoLock(lineNum() + "Description: " + str(ipPermissionsT['Description']),1)
                                ipDescriptionT = str(ipPermissionsT['Description'])

                            if (xT == 'IpRanges' or xT =='Ipv6Ranges'):
                                
                                if len(ipPermissionsT[xT]) > 0:
                                    printDebugNoLock(lineNum() + "Property: IPRanges" ,3)#+ str(xT),4)
                                    printDebugNoLock(lineNum() + str(ipPermissionsT[xT]), 3)

                                for ipPropertiesT in ipPermissionsT[xT]:
                                    for idT in ipPropertiesT.keys():
                                        if 'Description' in ipPropertiesT.keys():
                                            printDebugNoLock(lineNum() + idT + ": " + str(ipPropertiesT['Description']),4)
                                            if len(str(ipPropertiesT['Description'])) > 0:
                                                ipDescriptionT = str(ipPropertiesT['Description'])
                                            else:
                                                ipDescriptionT = "No Description set."

                                        else:
                                            ipDescriptionT = "No Description set."

                                        if idT == 'CidrIp' or idT =='CidrIpv6':
                                            printDebugNoLock(lineNum() + idT + ": " + str(ipPropertiesT[idT]),3)
                                            ipRangesListP.append(str(ipPropertiesT[idT]) + ": To Port: " + str(ipToPortT) + ": From Port: " + str(ipFromPortT) + ": Protocol : " + str(ipPrototcolT) + ": Description : " + ipDescriptionT)
                                            printDebugNoLock(lineNum() + str(ipPropertiesT[idT]) + ": To Port: " + str(ipToPortT) + ": From Port: " + str(ipFromPortT) + ": Protocol : " + str(ipPrototcolT) + ": Description : " + ipDescriptionT,3)
                            if (xT == 'PrefixListIds'):
                                if len(ipPermissionsT[xT]) > 0:
                                    printDebugNoLock(lineNum() + "PrefixListId: " + str(ipPermissionsT[xT]),4)

                #lse if :
    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as exT:
        print(lineNum() + str(exT))


def parseDBSecurityGroup(secGrpP, securityGroupListP, dbInstanceIDP):

    #securityGroupPoliciesG = ['IpPermissionsEgress','IpPermissions', 'DBInstanceIdentifier']
    printDebugNoLock(lineNum() + str(secGrpP) + " : " + dbInstanceIDP,4)
    groupIDKeyT = 'DBSecurityGroupName'
    if groupIDKeyT not in secGrpP.keys():
        groupIDKeyT = 'VpcSecurityGroupId'
    if groupIDKeyT not in secGrpP.keys():
        groupIDKeyT = 'GroupId'

    printDebugNoLock(lineNum() + "Group ID set to: " + str(groupIDKeyT), 4)

    printDebugNoLock(lineNum() + str(secGrpP.keys()),4)
    try:
        if 1==1 or secGrpP[groupIDKeyT] == 'sg-1115746d' or secGrpP[groupIDKeyT] == 'sg-5c722b21' or secGrpP[groupIDKeyT] == 'sg-0606207b':
            currentSecurityGroupT = str(secGrpP[groupIDKeyT])

            printInfo("\n" + groupIDKeyT + ":     " + currentSecurityGroupT,2)
            if currentSecurityGroupT not in DependancyListG.keys():
                printDebugNoLock(lineNum() + 'Adding ' + currentSecurityGroupT + ' dependancy list.',4)
                DependancyListG[currentSecurityGroupT] = []
            if "GroupName" in secGrpP.keys():
                printInfo("GroupName  : " + str(secGrpP['GroupName']),2)
            if "Status" in secGrpP.keys():
                printInfo("Status     : " + str(secGrpP['Status']),2)
            if 'Description' in secGrpP.keys():
                printInfo("Description: " + str(secGrpP['Description']),2)
            printDebugNoLock(lineNum() + "Keys:        " + str(secGrpP.keys()),4)
            #for groupPolicyT in securityGroupPoliciesG:
            groupPolicyT = groupIDKeyT
            printDebugNoLock(lineNum() + "************",4)
            printDebugNoLock(lineNum() + groupPolicyT,4)
            printDebugNoLock(lineNum() + "************",4)

            if groupPolicyT in secGrpP.keys():
                #printInfo(lineNum()
        
                dependantGroupT = str(secGrpP[groupPolicyT])
                printDebugNoLock(lineNum() + str(dependantGroupT) + "dbinstance: " + dbInstanceIDP,4)
                if dbInstanceIDP not in securityGroupListP:
                    securityGroupListP[dbInstanceIDP] = []
                securityGroupListP[dbInstanceIDP].append(dependantGroupT)
                #printInfo(lineNum()
                if dependantGroupT in DependancyListG.keys():
                    if currentSecurityGroupT not in DependancyListG[dependantGroupT] and currentSecurityGroupT != dependantGroupT:
                        DependancyListG[dependantGroupT].append(currentSecurityGroupT)

                        printDebugNoLock(lineNum() + "Adding to existing " + currentSecurityGroupT + " to " + dependantGroupT + " dependancy.",1)

                    else:
                        printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentSecurityGroupT + " to " + dependantGroupT + " dependancy.",4)

                else:
                    DependancyListG[dependantGroupT] = []
                    DependancyListG[dependantGroupT].append(currentSecurityGroupT)
                    printDebugNoLock(lineNum() + "Initially adding   " + currentSecurityGroupT + " to " + dependantGroupT + " dependancy.",1)

                    

    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as exT:
        print(lineNum() + str(exT))


def parseElasticCacheSecurityGroups(interfaceP, securityGroupListP):

    securityGroupPoliciesG = ['SecurityGroups']

    if 1==1 or interfaceP['CacheClusterId'] == "eni-02751f5c64db1cad1":
        printDebugNoLock(lineNum() + str(len(interfaceP)) + " " + str(interfaceP),4)
        currentCacheClusterT = str(interfaceP['CacheClusterId'])

        printInfo("\nCache Cluster ID:  " + currentCacheClusterT, 2)
        if currentCacheClusterT not in DependancyListG.keys():
            printDebugNoLock(lineNum() + 'Adding ' + currentCacheClusterT + ' dependancy list.',4)
            DependancyListG[currentCacheClusterT] = []

        #printInfo("Description:         " + str(interfaceP['Description']))
        printDebugNoLock(lineNum() + "Keys:        " + str(interfaceP.keys()),4)

        for groupPolicyT in securityGroupPoliciesG:
            printDebugNoLock(lineNum() + "************",4)
            printDebugNoLock(lineNum() + groupPolicyT,4)
            printDebugNoLock(lineNum() + "************",4)

            for sgT in interfaceP[groupPolicyT]:
                printDebugNoLock(lineNum() + "Keys:  " + str(sgT.keys()),4)

                for attribT in sgT:

                    if attribT == 'Status':
                        printInfo("Status: " + str(sgT[attribT]),2)
                    if attribT == 'SecurityGroupId':
                        dependantGroupT = str(sgT[attribT])
                        printInfo("Security Group ID: " + dependantGroupT,2)
                        securityGroupListP[dependantGroupT] = sgT

                        if dependantGroupT in DependancyListG.keys():
                            if currentCacheClusterT not in DependancyListG[dependantGroupT] and currentCacheClusterT != dependantGroupT:
                                DependancyListG[dependantGroupT].append(currentCacheClusterT)

                                printDebugNoLock(lineNum() + "Adding to existing " + currentCacheClusterT + " to " + dependantGroupT + " dependancy.",4)

                            else:
                                printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentCacheClusterT + " to " + dependantGroupT + " dependancy.",4)

                        else:
                            DependancyListG[dependantGroupT] = []
                            DependancyListG[dependantGroupT].append(currentCacheClusterT)
                            printDebugNoLock(lineNum() + "Initially adding   " + currentCacheClusterT + " to " + dependantGroupT + " dependancy.",4)


        if len(securityGroupListP.keys()) > 0:
            # Sort and eliminate duplicates.
            printDebugNoLock(lineNum() + str(securityGroupListP),4)
            printInfo("\nSecurity Group Dependancy List for this Network Interface: " + str(currentCacheClusterT),2)
            printDebugNoLock(lineNum() + str(securityGroupListP.keys()), 4)
            for securityGroupIDT in securityGroupListP.keys():
                printDebugNoLock(lineNum() + str(securityGroupIDT),4)
                testT = securityGroupListP[securityGroupIDT]
                printDebugNoLock(lineNum() + str(testT.keys()),4)
                printInfo("\n",2)
                for attributeT in testT.keys():
                    printInfo(str(testT[attributeT]),2)


def addDependancy(currentLoadBalancerT, dependantGroupT):
    try:

        if dependantGroupT in DependancyListG.keys():
            if currentLoadBalancerT not in DependancyListG[dependantGroupT] and currentLoadBalancerT != dependantGroupT:
                DependancyListG[dependantGroupT].append(currentLoadBalancerT)

                printDebugNoLock(lineNum() + "Adding to existing " + currentLoadBalancerT + " to " + dependantGroupT + " dependancy.",4)

            else:
                printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentLoadBalancerT + " to " + dependantGroupT + " dependancy.",4)

        else:
            DependancyListG[dependantGroupT] = []
            DependancyListG[dependantGroupT].append(currentLoadBalancerT)
            printDebugNoLock(lineNum() + "Initially adding   " + currentLoadBalancerT + " to " + dependantGroupT + " dependancy.",4)
    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))


def parseLoadBalancerSecurityGroups(interfaceP, securityGroupListP):

    try:

        securityGroupPoliciesG = ['SecurityGroups'] #, 'SourceSecurityGroup'] # We don't need to parse SourceSecurityGroups

        if 1==1 or interfaceP['LoadBalancerName'] == "eni-02751f5c64db1cad1":
            printDebugNoLock(lineNum() + str(len(interfaceP)) + " " + str(interfaceP),4)
            currentLoadBalancerT = str(interfaceP['LoadBalancerName'])

            #printInfo("\nLoad Balancer Name:  " + currentLoadBalancerT)
            if currentLoadBalancerT not in DependancyListG.keys():
                printDebugNoLock(lineNum() + 'Adding ' + currentLoadBalancerT + ' dependancy list.',4)
                DependancyListG[currentLoadBalancerT] = []

            printDebugNoLock(lineNum() + "Keys:        " + str(interfaceP.keys()),4)

            for groupPolicyT in securityGroupPoliciesG:
                printDebugNoLock(lineNum() + "************",4)
                printDebugNoLock(lineNum() + groupPolicyT,4)
                printDebugNoLock(lineNum() + "************",4)

                if groupPolicyT == 'SecurityGroups':
                    for sgT in interfaceP[groupPolicyT]:
                        #print lineNum() + str(sgT)
                        dependantGroupT = str(sgT)

                        if dependantGroupT not in securityGroupListP.keys():
                            securityGroupListP[dependantGroupT] = []

                        addDependancy(currentLoadBalancerT, dependantGroupT)

                else:
                    #print lineNum() + str(groupPolicyT)
                    #if groupPolicyT != "":
                    #print lineNum() + str(interfaceP.keys())
                    if groupPolicyT in interfaceP.keys():
                        for attribT in interfaceP[groupPolicyT]:
                           #print lineNum() + str(attribT)
                            #printDebugNoLock(lineNum() + "Keys:  " + str(sgT.keys()),1)
                            #print lineNum() + sgT
                            #for attribT in sgT:

                                #if attribT == 'Status':
                                #    printInfo("Status: " + str(sgT[attribT]),1)
                            testT = interfaceP[groupPolicyT]
                            if attribT == 'GroupName':
                                dependantGroupT = str(testT[attribT])
                                printInfo("Security Group Name: " + dependantGroupT,4)
                                securityGroupListP[dependantGroupT] = sgT
                                #print lineNum() + str(sgT)
                                addDependancy(currentLoadBalancerT, dependantGroupT)


                addDependancy(currentLoadBalancerT, dependantGroupT)

                # if dependantGroupT in DependancyListG.keys():
                #     if currentLoadBalancerT not in DependancyListG[dependantGroupT] and currentLoadBalancerT != dependantGroupT:
                #         DependancyListG[dependantGroupT].append(currentLoadBalancerT)

                #         printDebugNoLock(lineNum() + "Adding to existing " + currentLoadBalancerT + " to " + dependantGroupT + " dependancy.",1)

                #     else:
                #         printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentLoadBalancerT + " to " + dependantGroupT + " dependancy.",1)

                # else:
                #     DependancyListG[dependantGroupT] = []
                #     DependancyListG[dependantGroupT].append(currentLoadBalancerT)
                #     printDebugNoLock(lineNum() + "Initially adding   " + currentLoadBalancerT + " to " + dependantGroupT + " dependancy.",1)


            if len(securityGroupListP.keys()) > 0:
                # Sort and eliminate duplicates.
                printDebugNoLock(lineNum() + str(securityGroupListP),4)
                printInfo("\nSecurity Group Dependancy List for this Load Balancer: " + str(currentLoadBalancerT),2)
                printDebugNoLock(lineNum() + str(securityGroupListP.keys()), 4)
                for securityGroupIDT in securityGroupListP.keys():
                    printInfo(str(securityGroupIDT),2)
                    #testT = securityGroupListP[securityGroupIDT]
                    # printDebugNoLock(lineNum() + str(testT.keys()),1)
                    # printInfo("\n")
                    # for attributeT in testT.keys():
                    #     printInfo(str(testT[attributeT]))
    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + "Exception Thrown: " + str(e2))


def getLoadBalancerV2SecurityGroups():

    #AWSProfile.DisplayCurrentProfile()

    #print lineNum()
    currentProfileT = AWSProfile.GetSelected()
    elb = boto3.client('elbv2', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)

    try:
        x = 0
        global DependancyListG

        response1T = elb.describe_load_balancers()

        printDebugNoLock(lineNum() + str(response1T),5)

        for loadBalancerT in response1T["LoadBalancers"]:
            printDebugNoLock(lineNum() + str('*****************************************************'),4)
            printInfo("\nVersion 2 Load Balancer",2)
            printInfo("Load Balancer Name : " + str(loadBalancerT['LoadBalancerName']),2)
            printInfo("DNS Name           : " + str(loadBalancerT['DNSName']),2)
            printInfo("VPC ID             : " + str(loadBalancerT['VpcId']),2)
            #printInfo("Cache Node Type     : " + str(loadBalancerT['CacheNodeType']),1)
            #instancesT = loadBalancerT['Instances']
            #for instanceT in instancesT:
            #    printInfo("Instance ID: " + str(instanceT['InstanceId']),1)

            for lBPropertyT in loadBalancerT:
                printDebugNoLock(lineNum() + str(lBPropertyT),4)

            printDebugNoLock(lineNum() + str(loadBalancerT),4)
            SecurityGroupList = {}
            IPRangersListG    = []

            parseLoadBalancerSecurityGroups(loadBalancerT, SecurityGroupList)

            if len(IPRangersListG) > 0:
                # Sort and eliminate duplicates.
                IPRangersListG = sorted(set(IPRangersListG))
                printDebugNoLock(lineNum() + str(IPRangersListG),2)

                printInfo("\nIP Address Ranges in this Security Group:",2)
                for x in IPRangersListG:
                    printInfo(x,2)

        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))


def getLoadBalancerV1SecurityGroups():

    #AWSProfile.DisplayCurrentProfile()

    #print lineNum()
    currentProfileT = AWSProfile.GetSelected()
    elb = boto3.client('elb', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)

    try:
        x = 0
        global DependancyListG

        response1T = elb.describe_load_balancers()

        printDebugNoLock(lineNum() + str(response1T),5)

        for loadBalancerT in response1T["LoadBalancerDescriptions"]:
            printDebugNoLock(lineNum() + str('*****************************************************'),4)
            printInfo("\nVersion 1 Load Balancer",2)
            printInfo("Load Balancer Name : " + str(loadBalancerT['LoadBalancerName']),2)
            printInfo("DNS Name              : " + str(loadBalancerT['DNSName']),2)
            printInfo("VPC ID: " + str(loadBalancerT['VPCId']),2)
            #printInfo("Cache Node Type     : " + str(loadBalancerT['CacheNodeType']),1)
            instancesT = loadBalancerT['Instances']
            for instanceT in instancesT:
                printInfo("Instance ID: " + str(instanceT['InstanceId']),2)

            for lBPropertyT in loadBalancerT:
                printDebugNoLock(lineNum() + str(lBPropertyT),4)

            printDebugNoLock(lineNum() + str(loadBalancerT),4)
            SecurityGroupList = {}
            IPRangersListG    = []

            parseLoadBalancerSecurityGroups(loadBalancerT, SecurityGroupList)

            if len(IPRangersListG) > 0:
                # Sort and eliminate duplicates.
                IPRangersListG = sorted(set(IPRangersListG))
                printDebugNoLock(lineNum() + str(IPRangersListG),2)

                printInfo("\nIP Address Ranges in this Security Group:",2)
                for x in IPRangersListG:
                    printInfo(x,2)

        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))

def getElasticCacheSecurityGroups():

    #AWSProfile.DisplayCurrentProfile()

    #print lineNum()
    currentProfileT = AWSProfile.GetSelected()
    ec = boto3.client('elasticache', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)

    #securityGroupPoliciesG = ['Groups']
    try:
        x = 0
        global DependancyListG

        #responseT = 
        response1T = ec.describe_cache_clusters()
        #response2T = ec.describe_cache_security_groups(CacheSecurityGroupName='sg-09707c6b2edcd00a8')

        printDebugNoLock(lineNum() + str(response1T),4)

        #print lineNum() + str(type(response1T['CacheClusters']))
        #print lineNum() + str(response2T)


        for clusterT in response1T["CacheClusters"]:
            printDebugNoLock(lineNum() + str('*****************************************************'),4)
            printInfo("\nCache Cluster ID.   : " + str(clusterT['CacheClusterId']),2)
            printInfo("Engine              : " + str(clusterT['Engine']),2)
            printInfo("Cache Cluster Status: " + str(clusterT['CacheClusterStatus']),2)
            printInfo("Cache Node Type     : " + str(clusterT['CacheNodeType']),2)
            #printInfo("Cache Cluster ID: " + str(clusterT['CacheClusterId']),1)
            #printInfo("Cache Cluster ID: " + str(clusterT['CacheClusterId']),1)
            for clusterPropertyT in clusterT:
                printDebugNoLock(lineNum() + str(clusterPropertyT),4)

            printDebugNoLock(lineNum() + str(clusterT),4)
            SecurityGroupList = {}
            IPRangersListG    = []

            #parseNetworkInterfaceSecurityGroups(clusterT, SecurityGroupList)
            parseElasticCacheSecurityGroups(clusterT, SecurityGroupList)

            if len(IPRangersListG) > 0:
                # Sort and eliminate duplicates.
                IPRangersListG = sorted(set(IPRangersListG))
                printDebugNoLock(lineNum() + str(IPRangersListG),4)

                printInfo("\nIP Address Ranges in this Security Group:",2)
                for x in IPRangersListG:
                    printInfo(x,2)

        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))

def getNetworkInterfacesSecurityGroups():

    #AWSProfile.DisplayCurrentProfile()

    #print lineNum()
    currentProfileT = AWSProfile.GetSelected()

    ec2 = boto3.client('ec2', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)

    #securityGroupPoliciesG = ['Groups']
    try:
        x = 0
        global DependancyListG

        responseNWIT = ec2.describe_network_interfaces()

        for keyT in responseNWIT["NetworkInterfaces"]:
            printDebugNoLock(lineNum() + str('*****************************************************'),4)
            
            SecurityGroupList = {}
            IPRangersListG    = []

            parseNetworkInterfaceSecurityGroups(keyT, SecurityGroupList)

            if len(IPRangersListG) > 0:
                # Sort and eliminate duplicates.
                IPRangersListG = sorted(set(IPRangersListG))
                printDebugNoLock(lineNum() + str(IPRangersListG),4)

                printInfo("\nIP Address Ranges in this Security Group:",2)
                for x in IPRangersListG:
                    printInfo(x,2)

        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))



def getInstancesSecurityGroups():

    #AWSProfile.DisplayCurrentProfile()

    #print lineNum()
    currentProfileT = AWSProfile.GetSelected()
    ec2 = boto3.client('ec2', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)

    securityGroupPoliciesG = ['Groups', 'SecurityGroups']
    try:
        x = 0
        global DependancyListG

        responseNWIT = ec2.describe_instances()
        responseIT = responseNWIT['Reservations']
        #response2T = responseNWIT['Instances']
        #printInfo(lineNum() + str(responseNWIT)
        printInfo("Number of Instances: " + str(len(responseIT)),2)
        for attributeT in responseIT:
            printDebugNoLock(lineNum() + str(attributeT.keys()),4)
            #printInfo(lineNum() + str(attributeT['Groups'])

            #printInfo(lineNum() + str(responseIT)
            ##
            # Check the groups label.
            #for groupT in attributeT.keys():
            #    printInfo(lineNum() + str(attributeT[groupT])

            printDebugNoLock(lineNum() + str('*****************************************************'),4)
            
            SecurityGroupList = {}
            IPRangersListG    = []

            #printInfo(lineNum() + "Number of Instances: " + str(len(attributeT['Instances']))

            for instanceT in attributeT['Instances']:
                if 1==1 or instanceT['InstanceId'] == "i-0e389684831187b27":
                    printDebugNoLock(lineNum() + str(instanceT.keys()),4)
                    for x in instanceT.keys():
                        #printInfo(""
                        printDebugNoLock(lineNum() + str(x), 4)
                        printDebugNoLock(lineNum() + str(instanceT[x]),4)

                    printDebugNoLock(lineNum() + str(instanceT),4)
                    printInfo("\n\nPublic DNS Name   : " + str(instanceT['PublicDnsName']),2)
                    printInfo("Instance ID       : " + str(instanceT['InstanceId']),2)
                    printInfo("VPC ID            : " + str(instanceT['VpcId']),2)
                    stateT = instanceT['State']
                    printInfo("Current State     : " + str(stateT['Name']),2)
                    pubIPT = instanceT['PublicIpAddress']
                    printInfo("Public IP Address : " + str(pubIPT),2)
                    printInfo("Private IP Address: " + str(instanceT['PrivateIpAddress']),2)
                    interfaceT = instanceT['NetworkInterfaces']
                    for intT in interfaceT:
                        parseNetworkInterfaceSecurityGroups(intT, SecurityGroupList)

                    for groupT in instanceT['SecurityGroups']:
                        parseSecurityGroup(groupT, SecurityGroupList, IPRangersListG)




                #SecurityGroupList = {}
                # IPRangersListG    = []

                
                    printDebugNoLock(lineNum() + str(len(instanceT)) + " " + str(instanceT),4)
                    currentInstanceT = str(instanceT['InstanceId'])

                    printInfo("\n\nInstance ID:  " + currentInstanceT,2)
                    if currentInstanceT not in DependancyListG.keys():
                        printDebugNoLock(lineNum() + 'Adding ' + currentInstanceT + ' dependancy list.',4)
                        DependancyListG[currentInstanceT] = []

                    if 'Description' in instanceT.keys():
                        printInfo("Description:         " + str(instanceT['Description']),2)
                    printDebugNoLock(lineNum() + "Keys:        " + str(instanceT.keys()),4)

                    for groupPolicyT in securityGroupPoliciesG:
                        printDebugNoLock(lineNum() + "************",4)
                        printDebugNoLock(lineNum() + groupPolicyT,4)
                        printDebugNoLock(lineNum() + "************",4)

                        if groupPolicyT in instanceT.keys():
                            for key3T in instanceT[groupPolicyT]:
                                printDebugNoLock(lineNum() + "Keys:  " + str(key3T.keys()),4)

                                for idT in key3T:

                                    if idT == 'GroupName':
                                        printDebugNoLock(lineNum() + str(key3T[idT]),4)
                                    if idT == 'GroupId':
                                        dependantGroupT = str(key3T[idT])
                                        printDebugNoLock(lineNum() + dependantGroupT,4)
                                        SecurityGroupList[dependantGroupT] = key3T

                                        if dependantGroupT in DependancyListG.keys():
                                            if currentInstanceT not in DependancyListG[dependantGroupT] and currentInstanceT != dependantGroupT:
                                                DependancyListG[dependantGroupT].append(currentInstanceT)

                                                printDebugNoLock(lineNum() + "Adding to existing " + currentInstanceT + " to " + dependantGroupT + " dependancy.",4)
                                            else:
                                                printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentInstanceT + " to " + dependantGroupT + " dependancy.",1)
                                        else:
                                            DependancyListG[dependantGroupT] = []
                                            DependancyListG[dependantGroupT].append(q)
                                            printDebugNoLock(lineNum() + "Initially adding   " + currentInstanceT + " to " + dependantGroupT + " dependancy.",1)


                if len(SecurityGroupList.keys()) > 0:
                    # Sort and eliminate duplicates.
                    printDebugNoLock(lineNum() + str(SecurityGroupList),4)
                    #printInfo("\nSecurity Group Dependancy List for this Network Interface: " + str(currentNetworkInterfaceT)
                    printDebugNoLock(lineNum() + str(SecurityGroupList.keys()), 4)
                    for securityGroupIDT in SecurityGroupList.keys():
                        printDebugNoLock(lineNum() + str(securityGroupIDT),4)
                        testT = SecurityGroupList[securityGroupIDT]
                        # printDebugNoLock(lineNum() + str(testT.keys()),4)
                        # printInfo("\n",
                        # for attributeT in testT.keys():
                        #     printInfo(str(testT[attributeT])

                if len(IPRangersListG) > 0:
                    # Sort and eliminate duplicates.
                    IPRangersListG = sorted(set(IPRangersListG))
                    printDebugNoLock(lineNum() + str(IPRangersListG),4)

                    printInfo("\nIP Address Ranges in this Security Group:",2)
                    for x in IPRangersListG:
                        printInfo(x,2)
            #break

        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))


def getRDSSGs():

    try:

        SecurityGroupList = None
        securityGroupPoliciesG = ['DBSecurityGroups', 'VpcSecurityGroups']
        
        #print lineNum()
        #AWSProfile.DisplayCurrentProfile()

        #print lineNum()
        currentProfileT = AWSProfile.GetSelected()

        #print lineNum(), str(currentProfileT)

        #print lineNum()
        rds = boto3.client('rds', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)
        #print lineNum()
        responseT = rds.describe_db_security_groups()
        response2T = rds.describe_db_instances()

        printDebugNoLock(lineNum() + str(responseT),4)
        #printInfo(lineNum() + str(response2T['DBInstances'])

        for singleDBInstanceT in response2T['DBInstances']:
            #print lineNum(), singleDBInstanceT
            #dataBaseNameT = str(singleDBInstanceT['DBName']
            
            

            #if dataBaseNameT == 'tappas':

            #printInfo(lineNum() + str(type(singleDBInstanceT))
            printDebugNoLock(lineNum() + str(singleDBInstanceT.keys()),4)

            printDebugNoLock(lineNum() + str(singleDBInstanceT),4)

            printInfo("\n",2)
            if 'DBName' in singleDBInstanceT.keys():
                dataBaseNameT = str(singleDBInstanceT['DBName'])
                printInfo("Database Name       : " + dataBaseNameT,2)

            if 'DBInstanceIdentifier' in singleDBInstanceT.keys():
                dataBaseInstanceIDT = str(singleDBInstanceT['DBInstanceIdentifier'])
                printInfo("Database Instance ID: " + dataBaseInstanceIDT,2)

            DBSubnetGroupT = singleDBInstanceT['DBSubnetGroup']
            printInfo("VPC ID              : " + str(DBSubnetGroupT['VpcId']),2)
            DBsgsT = singleDBInstanceT['DBSecurityGroups']
            vpcSgsT = singleDBInstanceT['VpcSecurityGroups']

            SecurityGroupList = {}
            IPRangersListG    = []


            for sgT in vpcSgsT:
                parseDBSecurityGroup(sgT, SecurityGroupList, dataBaseInstanceIDT)

            for sgT in DBsgsT:
                parseDBSecurityGroup(sgT, SecurityGroupList, dataBaseInstanceIDT)

            printDebugNoLock(lineNum() + str(len(singleDBInstanceT)) + " " + str(singleDBInstanceT),4)
            currentInstanceT = str(singleDBInstanceT['DBInstanceIdentifier'])

            printInfo("\n\nDatabase Instance ID:  " + currentInstanceT,2)
            if currentInstanceT not in DependancyListG.keys():
                printDebugNoLock(lineNum() + 'Adding ' + currentInstanceT + ' dependancy list.',4)
                DependancyListG[currentInstanceT] = []

            if 'Description' in singleDBInstanceT.keys():
                printInfo("Description:         " + str(singleDBInstanceT['Description']),2)
            printDebugNoLock(lineNum() + "Keys:        " + str(singleDBInstanceT.keys()),4)

            for groupPolicyT in securityGroupPoliciesG:
                printDebugNoLock(lineNum() + "************",4)
                printDebugNoLock(lineNum() + groupPolicyT,4)
           
                #if groupPolicyT in singleDBInstanceT.keys():
                for sgAttributeT in singleDBInstanceT[groupPolicyT]:
                    #printDebugNoLock(lineNum() + "Keys:  " + str(sgAttributeT.keys()),4)

                    for idT in sgAttributeT:

                        if idT == 'DBSecurityGroupName' or idT == 'VpcSecurityGroupId':
                            #printInfo(lineNum()
                            if (idT in sgAttributeT.keys()):
                                #printInfo(lineNum()
                                dependantGroupT = str(sgAttributeT[idT])
                                printDebugNoLock(lineNum() + dependantGroupT,4)
                                printDebugNoLock(lineNum() + str(SecurityGroupList),4)
                                SecurityGroupList[dependantGroupT] = sgAttributeT
                                #printInfo(lineNum()
                                if dependantGroupT in DependancyListG.keys():
                                    if currentInstanceT not in DependancyListG[dependantGroupT] and currentInstanceT != dependantGroupT:
                                        

                                        printDebugNoLock(lineNum() + "Adding to existing " + currentInstanceT + " to " + dependantGroupT + " dependancy.",4)
                                        DependancyListG[dependantGroupT].append(currentInstanceT)
                                    else:
                                        printDebugNoLock(lineNum() + "Didn\'t Add.         " + currentInstanceT + " to " + dependantGroupT + " dependancy.",4)
                                else:
                                    printDebugNoLock(lineNum() + "Initially adding   " + currentInstanceT + " to " + dependantGroupT + " dependancy.",4)
                                    DependancyListG[dependantGroupT] = []
                                    DependancyListG[dependantGroupT].append(currentInstanceT)
                                    


        if SecurityGroupList != None and len(SecurityGroupList.keys()) > 0:
            # Sort and eliminate duplicates.
            printDebugNoLock(lineNum() + str(SecurityGroupList),4)
            #printInfo("\nSecurity Group Dependancy List for this Network Interface: " + str(currentNetworkInterfaceT)
            printDebugNoLock(lineNum() + str(SecurityGroupList.keys()), 4)
            for securityGroupIDT in SecurityGroupList.keys():
                printDebugNoLock(lineNum() + str(securityGroupIDT),4)
                # testT = SecurityGroupList[securityGroupIDT]
                # printDebugNoLock(lineNum() + str(testT.keys()),4)
                # printInfo("\n",
                # for attributeT in testT.keys():
                #     printInfo(str(testT[attributeT])

        # if len(IPRangersListG) > 0:
        #     # Sort and eliminate duplicates.
        #     IPRangersListG = sorted(set(IPRangersListG))
        #     printDebugNoLock(lineNum() + str(IPRangersListG),4)

        #     printInfo("\nIP Address Ranges in this Security Group:"
        #     for x in IPRangersListG:
        #         printInfo(x
    #break
        #print lineNum()
        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))


def getECSs():
    #AWSProfile.DisplayCurrentProfile()
    currentProfileT = AWSProfile.GetSelected()
    #print lineNum(), currentProfileT
    ecs = boto3.client('ecs', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)
    try:

        nextTokenT = ''
        #responseT = ecs.describe_services(services=['unknown'])
        responseT = ecs.list_clusters()
        response2T = None

        SecurityGroupList = {}
        IPRangersListG    = []

        printDebugNoLock(lineNum() + str(responseT),4)

        for x in responseT['clusterArns']:
            #printInfo(lineNum() + str(x)
            response2T = ecs.list_services(cluster=x)

            response3T = ecs.list_tasks(cluster=x)

            printDebugNoLock(lineNum() + str(response2T['serviceArns']),4)
            for serviceT in response2T['serviceArns']:
                printDebugNoLock(lineNum() + str(serviceT),4)
            
                response4T = ecs.describe_services(cluster=x, services=response2T['serviceArns'])
                for servicePropertyT in response4T['services']:
                    #printInfo(lineNum() + str(type(servicePropertyT))
                    printDebugNoLock(lineNum() + str(servicePropertyT.keys()),4)
                    printInfo("Name          : " + str(servicePropertyT['serviceName']),2)
                    printInfo("Cluster Arn   : " + str(servicePropertyT['clusterArn']),2)
                    printInfo("Service Arn   : " + str(servicePropertyT['serviceArn']),2)
                    lbListT = servicePropertyT['loadBalancers']
                    for lbT in lbListT:
                        #printInfo(lineNum() + str(lbT.keys())
                        printInfo("Load Balancers: " + str(lbT['targetGroupArn']),2)

                    #printInfo("Name          : " + str(servicePropertyT['serviceName'])
                    printInfo("Status        : " + str(servicePropertyT['status']),2)

                    netConfigT = servicePropertyT['networkConfiguration']
                    printDebugNoLock(lineNum() + "Network       : " + str(servicePropertyT['networkConfiguration']),4)
                    printDebugNoLock(lineNum() + str(netConfigT['awsvpcConfiguration']),4)
                    awsvpcConfigT = netConfigT['awsvpcConfiguration']
                    printDebugNoLock(lineNum() + str(awsvpcConfigT['securityGroups']),4)

                    for sgT in awsvpcConfigT['securityGroups']:
                        parseECSSecurityGroup(servicePropertyT['serviceName'], sgT, SecurityGroupList)

                #printInfo(lineNum() + str(response4T['services']
            printDebugNoLock(lineNum() + str(response3T['taskArns']),4)
            for taskT in response3T['taskArns']:
                printDebugNoLock(lineNum() + str(taskT),4)
            #break



            


        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)






        #for y in response2T['serviceArns']:
        #    printInfo(lineNum() + str(y)
    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))

def listServices():

    AWSProfile.DisplayCurrentProfile()
    currentProfileT = AWSProfile.GetSelected()

    sessionT = boto3.session.Session(aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, aws_session_token=None, region_name=currentProfileT.regionM, botocore_session=None) #, profile_name=currentProfileT.nameM)

    print(lineNum(), str(sessionT.available_profiles))
    print(lineNum(), str(sessionT.get_available_regions('ec2')))
    print(lineNum(), str(sessionT.profile_name))
    print(lineNum(), str(sessionT.region_name))
    print(lineNum(), str(sessionT.get_credentials()))
    print(lineNum(), str(sessionT.get_available_partitions()))
    print(lineNum(), str(sessionT.get_available_resources()))
    print(lineNum(), str(sessionT.get_available_services()))
    print(lineNum(), str(sessionT.resource('s3')))

    try:

        responseT = boto3.client('ec2',aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM).describe_security_groups(GroupIds=[''])


        secListT = []
        ipListT = []

        for x in responseT['SecurityGroups']:
            parseSecurityGroup(x, secListT, ipListT)

        if len(secListT) > 0:
            # Sort and eliminate duplicates.
            secListT = sorted(set(secListT))
            printDebugNoLock(lineNum() + str(secListT),4)
            printInfo("\nSecurity Group Dependancy List:",1)
            for x in secListT:
                printInfo(x,1)

    except Exception as exT:
        printDebugNoLock(lineNum() + str(exT), 1)

def test():
    listServices()

def getSecurityGroups():

    #AWSProfile.DisplayCurrentProfile()
    currentProfileT = AWSProfile.GetSelected()
    ec2 = boto3.client('ec2', aws_access_key_id=currentProfileT.awsAccessKeyIDM, aws_secret_access_key=currentProfileT.awsSecretAccessKeyM, region_name=currentProfileT.regionM)

    
    try:
        x = 0
        global DependancyListG

        responseT = ec2.describe_security_groups(GroupIds=[''])
        #responseNWIT = ec2.describe_network_interfaces()
        #responseIT = ec2.describe_instances()
        for keyT in responseT["SecurityGroups"]:


            printDebugNoLock(lineNum() + str('*****************************************************'),5)
            
            SecurityGroupList = []
            IPRangersListG    = []

            parseSecurityGroup(keyT, SecurityGroupList, IPRangersListG)


            if len(SecurityGroupList) > 0:
                # Sort and eliminate duplicates.
                SecurityGroupList = sorted(set(SecurityGroupList))
                printDebugNoLock(lineNum() + str(SecurityGroupList),4)
                printInfo("\nSecurity Group Dependancy List:",2)
                for x in SecurityGroupList:
                    printInfo(x,2)

            if len(IPRangersListG) > 0:

                # Sort and eliminate duplicates.
                IPRangersListG = sorted(set(IPRangersListG))
                printDebugNoLock(lineNum() + str(IPRangersListG),4)

                printInfo("\nIP Address Ranges in this Security Group:",1)
                for x in IPRangersListG:
                    printInfo(x,1)


        if len(DependancyListG.keys()) > 0:
            #showDependancyList()
            printDebugNoLock(lineNum() + str(DependancyListG),4)


    except ClientError as e:
        print(lineNum() + str(e))
    except Exception as e2:
        print(lineNum() + str(e2))


def writeDependancyListToFile():
    outputFilesG.openOutputHashesFile()

    counterT = 1
    outputFilesG.outputHashesFileM.write("nodes:[\n{name:\"zero\"},\n")

    # Do the notes list.
    firstTimeT = True
    for x in DependancyListG.keys():
        if firstTimeT == False:
            outputFilesG.outputHashesFileM.write("},\n")
        if firstTimeT == True:
            firstTimeT = False

        
        #printInfo(lineNum() + str(x)
        #if "eni-" not in x and "i-" not in x and "sg-" in x:
        printInfo('\nSecurity Group: ' + str(x),2)
        outputFilesG.outputHashesFileM.write(str("{name:\""+str(x)+"\""))

    outputFilesG.outputHashesFileM.write("}\n],\nedges:[\n")

    # Now write the nodes.
    targetT = 0
    sourceT = 0
    firstTimeT = True
    for x in DependancyListG.keys():
        targetT += 1
        sourceT = 0
        #printInfo(lineNum() + str(x), targetT
        # if firstTimeT == False:
        #     outputFilesG.outputHashesFileM.write(",\n")

        # if firstTimeT == True:
        #     firstTimeT = False

        

        #if "eni-" not in x and "i-" not in x and "sg-" in x:
        printInfo('\nSecurity Group: ' + str(x),2)

        printDebugNoLock(lineNum() + str(DependancyListG.keys()) + str(len(DependancyListG.keys())), 4)


        if len(DependancyListG[x]) <= 0:
            printInfo("No dependancies for this group.",2)

            if firstTimeT == False:
                outputFilesG.outputHashesFileM.write(",\n")


            if firstTimeT == True:
                firstTimeT = False
            
            outputFilesG.outputHashesFileM.write("{source:" + str(targetT) + ", target: " + str(targetT) + "}")
        else:
            printInfo("Dependancies, these Security Groups, Network Interfaces or Instances depend on this Security Group.",2)
            
            for y in DependancyListG[x]:

                if firstTimeT == False:
                    outputFilesG.outputHashesFileM.write(",\n")
                if firstTimeT == True:
                    firstTimeT = False
                sourceT = 0
                #sourceT +=1
                #printInfo(lineNum(), y
                
                for z in DependancyListG.keys():
                    sourceT += 1
                    #printInfo(lineNum(), z, y
                    if y == z:
                        #printInfo(lineNum(), y, z, sourceT
                        break
                #printInfo(lineNum(), y, sourceT
                printDebugNoLock(lineNum() + str(y) +str(sourceT) + str(x) + str(targetT), 4)

                outputFilesG.outputHashesFileM.write("{source:" + str(sourceT) + ", target: " + str(targetT) + "}")
            
    outputFilesG.outputHashesFileM.write("\n]")


def showDependancyList():
    
    global DependancyListG
    printInfo("\n\n*** Security Group Dependancy List ***\n",1)

    #outputFilesG.openOutputHashesFile()

    #print lineNum() + str(DependancyListG) + "Number of Dependants: " + str(DependancyListG.keys())
    tempListT = []
    for x in DependancyListG.keys():
        #printInfo(lineNum() + str(x))
        if "eni-" not in x and "i-" not in x and "sg-" in x:
            printInfo('\nSecurity Group: ' + str(x),1)
            if len(DependancyListG[x]) <= 0:
                printInfo("No dependancies for this group.",1)
            else:
                printInfo("Dependancies, these Security Groups, Network Interfaces or Instances depend on this Security Group.",1)
                for y in DependancyListG[x]:
                    printInfo(y,1)
                    if y not in tempListT:
                        tempListT.append(y)
                        printDebugNoLock("Count of dependants is: " + str(len(tempListT)), 4)


def setSessionObject():
    session = boto3.Session(aws_access_key_id='XXXX', aws_secret_access_key='XXX')

##
# main function, where good things happen!
#
def main():

    global fileListG

    retValT = False
    

    fileNameT = None
    
    outputFilesG.setFileNamePrefix(fileNameT) # set the prefix of the output files generated.
    outputFilesG.determineFilenamePrefix()
    outputFilesG.determineOutputDirectory()
    outputFilesG.determineNoClobberValue()

    awsCredsFileT = outputFilesG.openAWSCredentialsFile()

    if awsCredsFileT != None:
        printInfo('Loading AWS Credentials File: ' + str(Path.home()) + ".aws/credentials",1)
        outputFilesG.loadAWSCredentialsFile()

    else:
        cfgFileT = outputFilesG.openConfigFile()

        if cfgFileT != None:
            printInfo("Loading Config File: " + "profile.cfg",1)

            outputFilesG.loadConfigFile()

    fileNameT, listOfFilesT, topLevelDirT = processCommandLine(fileNameT)

    #print lineNum(), fileNameT, listOfFilesT, topLevelDirT

    if paramsG.testM == True:
        test()
        sys.exit()

    if paramsG.writeOutputM: # write out the graph file.
        writeDependancyListToFile()

    commandT = ""
    while(1==1 and str.upper(commandT) != str.upper("quit")):
        # printInfo("[+] Getting Security Groups...",1)
        # getSecurityGroups()
        if paramsG.usingCommandLineM == True:
            #print("FIM ]")
            
            try:
                #key = win.getkey()
                #win.clear()
                #printInfo("keydown:", str(key))

                commandT = input("SG] ") #This will need to change to the input() function for python3

            except Exception as e:
                pass


            processMenu(commandT)
            #print("hello")
            #print(str(commandT))
            continue
            #sys.exit()
        # getInstancesSecurityGroups()
        # getNetworkInterfacesSecurityGroups()

        # getRDSSGs()
        # getECSs()
        showDependancyList()
        break
        
    retValT = True
    
    outputFilesG.closeFiles()

    return retValT

##
# Default function.
#
if __name__ == "__main__":

    if main() == True:
        printInfo("[+] Processed OK!", 4)
    else:
        printDebugNoLock("\n *** Processing Error!!!! ***\n", 1)



## EOF ########################################################################