import base64
from cryptography.fernet import Fernet
from enum import IntEnum
import datetime
from getpass import getpass
import hashlib
import inspect
import os
from os import path, mkdir, getpid
import pyperclip
import random
import sys
import Tools
import traceback
import readline

class Logger:

    def __init__(self, func = ""):

        self.CWD = os.getcwd()
        self.logfile = path.join(self.CWD, "logs", f"log_{datetime.datetime.now():%Y%m%d}.log")
        self.configFile = path.join(self.CWD, "config.mpl")
        self.intMaxValue = 4294967295
        self.consoleLogLevel = -1
        self.fileLogLevel = -1
        self.func = func

        #
        ############################
        # Check log directory

        if not path.isdir(path.join(self.CWD, "logs")):
            mkdir(path.join(self.CWD, "logs"))

        #
        ############################
        # Set output log levels

        if path.isfile(self.configFile):
            self.consoleLogLevel = self.isLogLevel(Tools.readMapleTag(self.configFile, "CMD", "Log settings"))
            self.fileLogLevel = self.isLogLevel(Tools.readMapleTag(self.configFile, "FLE", "Log settings"))

    #
    #####################
    # Set log level enum

    class LogLevel(IntEnum):

        TRACE = 0
        DEBUG = 1
        INFO = 2
        WARN = 3
        ERROR = 4
        FATAL = 5

    #
    ################
    # Check log level

    def isLogLevel(self, lLStr: str) -> LogLevel:

        for lLevel in self.LogLevel:
            if lLStr == lLevel.name:
                return lLevel

        return -1

    #
    #################################
    # Logger

    def logWriter(self, loglevel: LogLevel, message: any):

        """
        Output log to log file and console.
        """

        ''' - - - - - - -*
        *                *
        * Logging Object *
        *                *
        * - - - - - - -'''

        f = open(self.logfile, "a")

        # Get caller informations

        callerFunc = inspect.stack()[1].function
        callerLine = inspect.stack()[1].lineno

        try:

            # Export to console and log file

            if loglevel >= self.consoleLogLevel:
                print(f"[{loglevel.name:5}][{self.func}] {callerFunc}({callerLine}) {message}")
        
            if loglevel >= self.fileLogLevel:
                print(f"({getpid()}) {datetime.datetime.now():%Y-%m-%d %H:%M:%S} [{loglevel.name:5}][{self.func}] {callerFunc}({callerLine}) {message}", file=f)

        except Exception as ex:

            # If faled to export, print error info to console

            print(f"[ERROR] {ex}")

        finally:
            f.close()

        # Check file size

        try:

            if path.getsize(self.logfile) > 3000000:

                i = 0
                logCopyFile = f"{self.logfile}{i}.log"

                while path.isfile(logCopyFile):

                    i += 1
                    logCopyFile = f"{self.logfile}{i}.log"

                os.rename(self.logfile, logCopyFile)

        except Exception as ex:
            print(f"[ERROR] {ex}")

    #
    ################################
    # Error messages

    def ShowError(self, ex: Exception):

        ''' - - - - - - - - -*
        *                    *
        * Show and log error *
        *                    *
        * - - - - - - - - -'''

        self.logWriter(self.LogLevel.ERROR, ex)
        self.logWriter(self.LogLevel.ERROR, traceback.format_exc())

class GenManPw:

    def __init__(self, iterations):

        self.EXIT_OPS = {"Q", "E", "C", "QUIT", "EXIT", "CANCEL"}
        self.CHOICE = [True, False]
        self.DATA_TAG = "DATAS"
        self.HASH_TYPE = "sha256"
        self.ITERATIONS = iterations

        self.Logger = Logger("GenManPw")
        self.logger = self.Logger.logWriter
        self.logLevel = self.Logger.LogLevel
        self.password = "".encode()

        # Get current working directory from configuration file

        cwd = Tools.readMapleTag(path.join(os.getcwd(), "config.mpl"), "CWD", "Application settings")

        if cwd == "":

            # If the directory is not configured

            self.CWD = os.getcwd()

        else:

            if not path.isdir(cwd):

                # Create if it does not exist

                self.logger(self.logLevel.INFO, f"Working directory does not exists: {cwd}")

                try:

                    os.mkdir(cwd)
                    self.CWD = cwd

                except Exception as ex:

                    self.logger(self.logLevel.WARN, "Failed to create working directory.")
                    self.Logger.ShowError(ex)
                    self.CWD = os.getcwd()

            else:

                self.CWD = cwd

        self.logger(self.logLevel.DEBUG, f"CWD is: {self.CWD}")

        self.DATA_FILE = path.join(self.CWD, "datas", "datas.mpl")
        self.PASS_LIST = path.join(self.CWD, "datas", "pwList.mpl.tmp")
        self.PASS_LIST_ENC = path.join(self.CWD, "datas", "pwList.mpl")

        # Check the OS for clear screen

        if sys.platform.startswith("win"):

            self.clearCommand = "cls"

        else:

            self.clearCommand = "clear"

        # Check data file

        if not path.isdir(path.join(self.CWD, "datas")):

            os.mkdir(path.join(self.CWD, "datas"))

        if not path.isfile(self.DATA_FILE):

            f = None

            try:

                f = open(self.DATA_FILE, "w")
                f.write(
"""
MAPLE
H DATAS
E
EOF
"""             )

            except Exception as ex:

                self.Logger.ShowError(ex)

            finally:

                if f is not None:

                    f.close()

        if not path.isfile(self.PASS_LIST):

            f = None

            try:

                f = open(self.PASS_LIST, "w")
                f.write(
"""
MAPLE
H PW
E
H SALTS
E
EOF
"""
                )
                f.close()

            except Exception as ex:

                self.Logger.ShowError(ex)

            finally:

                if f is not None:

                    f.close()

    ####################################
    # Clear screen

    def clearScreen(self):

        try:

            os.system(self.clearCommand)

        except Exception as ex:

            self.logger(self.logLevel.WARN, "Could not clear the screen.")
            self.Logger.ShowError(ex)

    #
    ####################################
    # Encode file

    def encodeFile(self, deleteDecodedFile: bool = False) -> bool:

        f = None

        try:

            f = open(self.PASS_LIST, "r")
            fileData = f.read().encode()
            f.close()

            salt = os.urandom(16).hex()
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))
            fileData = Fernet(key).encrypt(fileData).decode()

            f = open(self.PASS_LIST_ENC, "w")
            f.write(fileData)
            f.close()

            Tools.saveTagLine(self.DATA_FILE, "KEY", salt, "SECURITY_INFO")
            self.logger(self.logLevel.INFO, "File encrypted.")

        except Exception as ex:

            self.logger(self.logLevel.WARN, "File encryption failed.")
            self.Logger.ShowError(ex)
            return False

        finally:

            if f is not None:
                f.close()

        # Delete original file

        if deleteDecodedFile:

            try:

                os.remove(self.PASS_LIST)
                self.logger(self.logLevel.INFO, "Removed decoded file.")

            except Exception as ex:

                self.logger(self.logLevel.WARN, "Failed to remove decoded file.")
                self.Logger.ShowError(ex)

        return True

    #
    ####################################
    # Decode file

    def decodeFile(self) -> bool:

        f = None

        try:

            f = open(self.PASS_LIST_ENC, "r")
            fileData = f.read()
            f.close()
        
            salt = Tools.readMapleTag(self.DATA_FILE, "KEY", "SECURITY_INFO").encode()
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt, self.ITERATIONS))
            fileData = Fernet(key).decrypt(fileData.encode()).decode()

            f = open(self.PASS_LIST, "w")
            f.write(fileData)
            f.close()
            self.logger(self.logLevel.INFO, "File decrypted.")

        except Exception as ex:

            self.Logger.ShowError(ex)
            self.logger(self.logLevel.ERROR, "Decryption failed.")
            return False

        finally:

            if f is not None:

                f.close()

        return True
    
    #
    ####################################
    # Encode file for save data

    def saveData(self, deleteFile: bool = False) -> None:

        if self.encodeFile(deleteFile):

            self.logger(self.logLevel.INFO, "Data saved.")

        else:

            self.logger(self.logLevel.WARN, "Failed to save data.")
            print("Failed to save data.")

    #
    ####################################
    # Change system password

    def changeSysPasswd(self) -> str:

        try:
            
            while True:

                strPassWd = getpass("\nNew password: ")

                if len(strPassWd) < 8:

                    print("\n"
                        "* PASSWORD MUST BE OVER 8 CHARACTERS.")
                    
                    continue

                confPassWd = getpass("\nConfirm password: ")

                if strPassWd == confPassWd:

                    self.clearScreen()
                    break

                print("\n"
                        "* PASSWORD DOESN'T MATCH\n"
                        "* Please try again.")
                
            # Save password

            binPassWd = strPassWd.encode()
            passSalt = os.urandom(16).hex()
            salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
            hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

            Tools.saveTagLine(self.DATA_FILE, "PW", hashedPw, "SECURITY_INFO")
            Tools.saveTagLine(self.DATA_FILE, "SALT", passSalt, "SECURITY_INFO")

            self.logger(self.logLevel.INFO, "Hashed password saved.")
            self.password = binPassWd
            self.encodeFile()

            # Log

            self.logger(self.logLevel.INFO, "System login password updated.")
            print("\nPassword updated!")

            return hashedPw
        
        except Exception as ex:

            self.Logger.ShowError(ex)
            self.logger(self.logLevel.ERROR, "Failed to change password.")

        return ""

    #
    ####################################
    # Random capitalize

    def randCap(self, baseStr: str) -> str:

        capCount = len(baseStr) // 6 + 1

        for _ in range(capCount):

            if random.choice(self.CHOICE + [True]):
                    
                randIndex = random.randint(1, len(baseStr) - 1)
                indexLetter = baseStr[randIndex].lower()
                willCange = random.choice(self.CHOICE + [True])

                if indexLetter == "o" and willCange:

                    indexLetter = "0"

                elif indexLetter in ("i", "l") and willCange:

                    indexLetter = "1"

                elif indexLetter == "a" and willCange:

                    indexLetter = random.choice(["4", "@"])

                elif indexLetter == "s" and willCange:

                    indexLetter = "5"

                elif indexLetter == "e" and willCange:

                    indexLetter = "3"

                elif indexLetter == "b" and willCange:

                    indexLetter = "8"

                else:

                    indexLetter = indexLetter.upper()

                baseStr = baseStr[:randIndex] + indexLetter + baseStr[randIndex + 1:]

        return baseStr

    ####################################
    # Generate password string

    def generatePasswordStr(self) -> str:

        pwStr = ""
        secondRound = False

        try:

            # Get lists

            f = open(path.join(self.CWD, "Symbols.txt"))
            symList = f.readlines()
            f.close()

            self.logger(self.logLevel.DEBUG, "Symbol list loaded")

            f = open(path.join(self.CWD, "NameList.txt"))
            nameList = f.readlines()
            f.close()

            self.logger(self.logLevel.DEBUG, "Names list loaded")

            f = open(path.join(self.CWD, "WordList.txt"))
            wordList = f.readlines()
            f.close()

            self.logger(self.logLevel.DEBUG, "Word list loaded")

            f = open(path.join(self.CWD, "VerbList.txt"))
            verbList = f.readlines()
            f.close()

            self.logger(self.logLevel.DEBUG, "Verbs list loaded")

        except Exception as ex:

            self.Logger.ShowError(ex)
            
            return ""

        # First letter

        if random.choice(self.CHOICE):

            pwStr += random.choice(symList).rstrip("\n")

        while len(pwStr) < 16:

            # Subject

            pwStr += self.randCap(random.choice(wordList).rstrip("\n"))

            if secondRound and len(pwStr) > 16:

                break

            # Verb

            pwStr += self.randCap(random.choice(verbList).rstrip("\n"))

            # Symbol?

            if random.choice(self.CHOICE):

                pwStr += random.choice(symList).rstrip("\n")

            # Number?

            if not any(c.isdigit() for c in pwStr) or random.choice(self.CHOICE + [False]):

                pwStr += random.choice(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])
            
            if secondRound and len(pwStr) > 16:

                break

            # Name

            pwStr += self.randCap(random.choice(nameList).rstrip("\n"))
            
            if len(pwStr) < 14:

                pwStr += "\'s"

            else:

                pwStr += random.choice(["\'s", ""])

            # Symbol

            pwStr += random.choice(symList).rstrip("\n")

            secondRound = True
        
        return pwStr
    
    #
    ####################################
    # Confirm password

    def confPassword(self) -> str:

        self.logger(self.logLevel.INFO, "Auto generate password.")

        while True:

            newPassword = self.generatePasswordStr()
            question = random.choice(["You like it?", "How about this? "])

            while True:

                print(f"\nNew password: {newPassword}")
                res = input(f"\n{question} (y/n) > ")
                resU = res.upper()
                self.clearScreen()

                if resU == "Y":

                    return newPassword
                
                elif resU == "N":

                    break

                elif resU == "COPY":

                    pyperclip.copy(newPassword)
                    self.clearScreen()
                    self.logger(self.logLevel.INFO, "Password copied to clipboard.")
                    print("Password copied to clipboard.")
                    continue

                elif resU in self.EXIT_OPS:

                    return ""
                
                else:

                    print(f"\n{res} is not on the menu.")
                    continue

    #
    ##########################
    # Manually input password

    def manualPassword(self) -> str:

        self.logger(self.logLevel.INFO, "Manually create password.")

        while True:

            pwStr = input("\nInput new password > ")

            if pwStr.upper() in self.EXIT_OPS:

                self.clearScreen()
                return ""
            
            elif pwStr == "":

                self.clearScreen()
                continue

            else:

                while True:

                    res = input(f"\n Will you use [{pwStr}] as a password? (y/n) > ")
                    resU = res.upper()

                    if resU == "Y":

                        self.clearScreen()
                        return pwStr
                    
                    elif resU == "N":

                        self.clearScreen()
                        break

                    elif resU == "COPY":

                        pyperclip.copy(pwStr)
                        self.clearScreen()
                        self.logger(self.logLevel.INFO, "Password copied to clipboard.")
                        print("\nPassword copied to clipboard.")
                        continue

                    else:

                        print(f"\n{res} is not on the menu.")
        
    #
    ##########################
    # List select

    def selectFromList(self, selectList: list[str], menuStr: str, i = 0) -> str:

        self.logger(self.logLevel.INFO, f"{menuStr} Selection Menu")
        listLen = len(selectList)

        while True:

            menuChoice = []

            print(f"\n\n * {menuStr} Selection Menu *")
            self.logger(self.logLevel.INFO, f"Page {i + 1} / {listLen // 10 + 1}")

            if listLen > 10:

                print(f" > Page {i + 1} / {listLen // 10 + 1} <")

            print("")

            for j in range(10):

                if j + i * 10 >= listLen:

                    break

                print(f" {j}) {selectList[j + i * 10]}")
                menuChoice.append(f"{j}")

            if j + i * 10 < listLen - 1:

                print(" N) >> Next page")
                menuChoice.append("N")

            if i > 0:

                print(" P) << Previous page")
                menuChoice.append("P")

            print(" E) Exit menu")

            res = input(f"\nSelect > ")
            resU = res.upper()
            self.clearScreen()

            if resU in self.EXIT_OPS:

                self.logger(self.logLevel.INFO, "Selected none.")
                return ""
            
            elif resU in menuChoice:

                if resU == "N":

                    i += 1

                elif resU == "P":

                    i -= 1

                else:

                    self.logger(self.logLevel.INFO, f"[{selectList[int(res) + i * 10]}] selected.")
                    return selectList[int(res) + i * 10]
                
            elif resU.startswith("SEARCH "):

                # If there is no search string after the command

                if len(resU) < 8:

                    print("Search string empty.")
                    continue

                # Get search string

                self.logger(self.logLevel.INFO, resU)
                searchStr = res[7:]

                # Create list

                newSelectList = []

                for listElement in selectList:

                    if searchStr.upper() in listElement.upper():

                        newSelectList.append(listElement)

                # If there is no match element in the list

                if len(newSelectList) == 0:

                    print(f"Could not find \"{searchStr}\" in the list.")
                    self.logger(self.logLevel.INFO, "No match data.")
                    continue

                print(f"\nFound {len(newSelectList)} items from {menuStr}.")
                selectedItem = self.selectFromList(newSelectList, f"Search Result")

                if selectedItem != "":

                    return selectedItem
            
            else:

                print(f"\n{res} is not on the menu.\n")
            
    #
    ##########################
    # Create new account
    
    def generateNewPassword(self, siteName: str, accountName: str, newData: bool = True) -> bool:

        newOrEdit = ("Edit", "Create new")
        self.logger(self.logLevel.INFO, f"{newOrEdit[newData]} data.")

        while True:

            res = input("\nGenerate a password or create it manually?\n\n"
                        "A) Auto generate\n" \
                        "M) Create it manually\n" \
                        "C) Cancel\n\n" \
                        "Will you... > ")
            resU = res.upper()
            self.clearScreen()

            if resU in self.EXIT_OPS:

                # Exit

                return False

            elif resU == "A":

                # Generate password

                newPassword = self.confPassword()

            elif resU == "M":

                # Create password manually

                newPassword = self.manualPassword()

            else:

                print(f"{res} is not on the menu.")
                continue

            if newPassword != "":

                break

        try:
            
            # Encrypt password

            passSalt = os.urandom(16).hex()
            saltStr = passSalt + siteName + accountName
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, saltStr.encode(), self.ITERATIONS))
            token = Fernet(key).encrypt(newPassword.encode()).decode()
            
            if newData:
                    
                # Create new tag

                try:

                    tagList = Tools.getTags(self.PASS_LIST, "PW")
                    i = 0
                    pwTag = f"PW{i}"

                    while pwTag in tagList:

                        i += 1
                        pwTag = f"PW{i}"

                except Exception as ex:

                    self.Logger.ShowError(ex)

                # Save tag

                Tools.saveTagLine(self.DATA_FILE, accountName, pwTag, self.DATA_TAG, siteName)

            else:

                # Get pw tag

                pwTag = Tools.readMapleTag(self.DATA_FILE, accountName, self.DATA_TAG, siteName)

            # Log results

            self.logger(self.logLevel.INFO, f"VV Create new data VV")
            self.logger(self.logLevel.INFO, f"Site   : {siteName}")
            self.logger(self.logLevel.INFO, f"Account: {accountName}")
            self.logger(self.logLevel.INFO, f"PassWd : {newPassword[:4]}******{newPassword[10:]}")
            self.logger(self.logLevel.INFO, f"^^ Create complete ^^")

            print(("\nPassword updated", "\nNew data created!")[newData])

            # Save

            Tools.saveTagLine(self.PASS_LIST, pwTag, token, "PW")
            Tools.saveTagLine(self.PASS_LIST, pwTag, passSalt, "SALTS")

            self.saveData()

        except Exception as ex:

            self.logger(self.logLevel.ERROR, "Failed to generate new password.")
            self.Logger.ShowError(ex)

    #
    ####################################################
    # Create new account name

    def createNewAccountName(self, siteName: str) -> str:

        while True:

            newAccount = input("\nAccount name > ").replace(" ", "_")
            self.clearScreen()

            if newAccount.upper() in self.EXIT_OPS:

                return ""
            
            elif newAccount == "":

                print("Account name is empty.")
                continue
            
            accountList = Tools.getTags(self.DATA_FILE, self.DATA_TAG, siteName)

            if newAccount in accountList:

                while True:

                    res = input(f"\n{newAccount} is already exists in {siteName}\n"
                                f"You cannot access the old data after editing.\n\n"
                          f"Will you edit {newAccount} for {siteName} (y/n/c(ancel)) > ").upper()
                    self.clearScreen()
                    
                    if res in self.EXIT_OPS:

                        return ""
                    
                    elif res in {"Y", "N"}:

                        break
                    
                    else:

                        print(f"{res} is not on the menu.")

                if res == "N":

                    print(f"\n\nSite name > {siteName}")
                    continue

                elif res == "Y":

                    self.generateNewPassword(siteName, newAccount, False)
                    return ""

            return newAccount

    #
    ##########################
    # Site selection menu

    def selectSite(self, pageInd = 0) -> str:

        self.clearScreen()
        siteList = Tools.getHeaders(self.DATA_FILE, self.DATA_TAG)
        siteList.sort()
        
        if len(siteList) == 0:

            print("\nNo data has been saved yet.")
            return ""
        
        return self.selectFromList(siteList, "Site", pageInd)

    #
    ##########################
    # Account selection menu

    def selectAccountName(self, siteName: str, pageInd = 0) -> str:

        self.clearScreen()
        accList = Tools.getTags(self.DATA_FILE, self.DATA_TAG, siteName)
        accList.sort()

        if len(accList) == 0:

            print("\nNo account data has been saved.")
            return ""

        return self.selectFromList(accList, "Account", pageInd)

    #
    ####################################
    # New site data

    def newSiteData(self):

        siteList = Tools.getHeaders(self.DATA_FILE, self.DATA_TAG)

        while True:

            newSite = input("\n\nSite name > ")

            if newSite in siteList:

                while True:

                    res = input(f"\n[{newSite}] is already existing in the list\n\n"
                                "Will you add new account? (y/n) > ").upper()
                    self.clearScreen()
                    
                    if res in {"Y", "N"}:

                        break

                    elif res in self.EXIT_OPS:

                        return
                    
                    else:

                        print(f"{res} is not on the menu.")

                if res == "N":
    
                    continue

                print(f"\n\nSite name > {newSite}")

            elif newSite.upper() in self.EXIT_OPS:

                self.clearScreen()
                return
            
            elif newSite == "":

                print("Site name is empty.")
                continue

            newAccount = self.createNewAccountName(newSite)

            if newAccount == "":

                return
            
            # Generate new password

            self.generateNewPassword(newSite, newAccount)
            break

    #
    ####################################
    # Generate Password menu

    def GeneratePasswordMain(self):

        self.logger(self.logLevel.INFO, "Generate Password menu loaded.")
        self.clearScreen()

        while True:

            print("\n\n * Generate Password *\n\n"
                  " 1) New site (or system)\n" \
                  " 2) New account (for saved site)\n" \
                  " E) Back to main menu\n")
            select = input("Generate password for... > ").upper()
            self.clearScreen()
            
            if select == "1":

                try:
                    
                    self.newSiteData()

                except Exception as ex:

                    self.Logger.ShowError(ex)
                    
                continue

            elif select == "2":

                try:

                    siteName = self.selectSite()

                    if siteName != "":

                        newAccount = self.createNewAccountName(siteName)

                        if newAccount != "":

                            self.generateNewPassword(siteName, newAccount)

                except Exception as ex:

                    self.Logger.ShowError(ex)

                continue

            elif select in self.EXIT_OPS:

                return
            
            else:

                print(f"\n{select} is not on the menu.\n")

    #
    ##########################
    # Show password

    def getPassWd(self, siteName: str, accountName: str):

        try:

            # Get account tag

            accountTag = Tools.readMapleTag(self.DATA_FILE, accountName, self.DATA_TAG, siteName)

            # Decrypt password

            passWdToken = Tools.readMapleTag(self.PASS_LIST, accountTag, "PW").encode()
            salt = Tools.readMapleTag(self.PASS_LIST, accountTag, "SALTS") + siteName + accountName

            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))
            return Fernet(key).decrypt(passWdToken).decode()

        except Exception as ex:

            self.Logger.ShowError(ex)

        self.logger(self.logLevel.WARN, f"Failed to get password string. Site: {siteName} / Account: {accountName}")
        print("\nFailed to get password.")
        return ""
        
    #
    ##########################
    # Password search menu

    def selectAccount(self) -> list[str]:
        
        while True:
        
            siteName = self.selectSite()

            if siteName == "":

                return "", ""
            
            accountName = self.selectAccountName(siteName)

            if accountName != "":

                self.logger(self.logLevel.INFO, f"Account selected [Site: {siteName} / Account: {accountName}]")
                return siteName, accountName
            
    #
    ##########################
    # Manage Password

    def managePassword(self) -> None:

        self.logger(self.logLevel.INFO, f"Manage Password Menu")
        siteName, accountName = self.selectAccount()

        if siteName == "":

            return
        
        while True:

            print(f"\n"
                  f" * Manage Password *\n\n"
                  f"  Site   : {siteName}\n"
                  f"  Account: {accountName}\n\n"
                  f"1) Show password\n"
                  f"2) Change password\n"
                  f"D) Delete data\n"
                  f"E) Exit\n\n")
            res = input("Will you... > ").upper()
            self.clearScreen()

            if res == "1":

                # Show saved password

                self.logger(self.logLevel.INFO, "Showing saved password.")
                password = self.getPassWd(siteName, accountName)

                # Get max string length

                xLen = max([len(siteName), len(accountName), len(password)]) + 11

                print("\n"
                        f" *{"".join("-" for _ in range(xLen))}*\n"
                        f" * Site    : {siteName}\n"
                        f" * Account : {accountName}\n"
                        f" * PassWd  : {password}\n"
                        f" *{"".join("-" for _ in range(xLen))}*")
                
                while True:

                    res = input("\nCopy password to clipboard? (y/n) > ")
                    self.clearScreen()
                    resU = res.upper()

                    if resU == "Y":

                        # Copy password to clipboard

                        pyperclip.copy(password)
                        self.logger(self.logLevel.INFO, "Password copied to clipboard.")
                        print("\nPassword copied to clipboard.\n")
                        break

                    elif resU == "N":

                        break

                    else:

                        print(f"\n{res} is not on the menu.")

                continue

            elif res == "2":

                # Confirm and change

                while True:

                    print("\nYou cannot access the old password after changing it.")
                    res = input("\nWill you change the password? (y/n) > ")
                    resU = res.upper()
                    self.clearScreen()

                    if resU == "Y":

                        self.generateNewPassword(siteName, accountName, False)
                        break

                    elif resU == "N":

                        break

                    else:

                        print(f"\n{res} is not on the menu.")

                continue

            elif res == "D":

                # Confirm and delete

                while True:

                    print("\nYou cannot recover data after it has been deleted.")
                    res = input("\nAre you sure? (y/n) > ")
                    resU = res.upper()
                    self.clearScreen()

                    if resU == "Y":

                        # Delete account data

                        try:
                                
                            # Find account tag

                            accountTag = Tools.readMapleTag(self.DATA_FILE, accountName, self.DATA_TAG, siteName)

                            # Delete password and account data

                            Tools.deleteTag(self.PASS_LIST, accountTag, "PW")
                            Tools.deleteTag(self.PASS_LIST, accountTag, "SALTS")
                            Tools.deleteTag(self.DATA_FILE, accountName, self.DATA_TAG, siteName)
                            print("Account data deleted.")
                            self.logger(self.logLevel.INFO, f"Account data has been deleted: [Site: {siteName} / Account: {accountName}]")
                            
                            self.saveData()

                        except Exception as ex:

                            self.logger(self.logLevel.ERROR, "Failed to delete account data.")
                            self.Logger.ShowError(ex)
                            break

                        # Delete site data if all accounts have been deleted

                        try:

                            if len(Tools.getTags(self.DATA_FILE, self.DATA_TAG, siteName)) == 0:

                                Tools.deleteHeader(self.DATA_FILE, siteName, self.DATA_TAG)
                                print("Site data deleted.")
                                self.logger(self.logLevel.INFO, f"Site data has been deleted: {siteName}")

                        except Exception as ex:

                            self.Logger.ShowError(ex)

                        return

                    elif resU == "N":

                        break

                    else:

                        print(f"\n{res} is not on the menu.")

                continue

            elif res in self.EXIT_OPS:

                self.logger(self.logLevel.INFO, "Exit Manage Password Menu.")
                return
            
            else:

                print(f"\n{res} is not on the menu.\n")

    #
    ##########################
    # Settings Menu

    def settingsMenu(self) -> bool:

        self.logger(self.logLevel.INFO, "Settings menu loaded.")

        while True:

            print("\n"
                  " * Settings *\n\n"
                  "1) Change Login Password\n"
                  "X) Export data\n"
                  "I) Import data\n"
                  "E) Exit to the main menu\n")
            res = input("Will you... > ")
            resU = res.upper()
            self.clearScreen()

            if resU in self.EXIT_OPS:

                self.logger(self.logLevel.INFO, "Exit settings menu.")
                return False
            
            elif resU == "1":

                self.logger(self.logLevel.INFO, "Changing login password.")

                try:

                    password = Tools.readMapleTag(self.DATA_FILE, "PW", "SECURITY_INFO")
                    
                    for i in range(3):

                        strPassWd = getpass("\nCurrent password: ")

                        binPassWd = strPassWd.encode()
                        passSalt = Tools.readMapleTag(self.DATA_FILE, "SALT", "SECURITY_INFO")
                        salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
                        hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

                        isMatch = hashedPw == password

                        if isMatch:

                            self.password = binPassWd
                            self.logger(self.logLevel.INFO, "Authenticated.")
                            break

                        print("\n* Password incorrect.\n"
                            "* Please try again.")
                        self.logger(self.logLevel.INFO, f"Authentication failed {i + 1}")

                    if not isMatch:

                        print("\n\n* Authentication failed *\n\n"
                              "And you are kicked out.")
                        self.logger(self.logLevel.INFO, "Failed to authenticate to change login password")
                        return True
                    
                    self.clearScreen()
                    self.changeSysPasswd()

                except Exception as ex:

                    self.Logger.ShowError(ex)

            else:

                print(f"{res} is not on the menu.")
                continue
                
    #
    ##########################
    # Main menu

    def mainMenu(self) -> int:

        try:
                
            try:

                self.logger(self.logLevel.INFO, "START")
                password = Tools.readMapleTag(self.DATA_FILE, "PW", "SECURITY_INFO")

                # If the first time to use

                if password == "":

                    self.logger(self.logLevel.INFO, "First time to login.")

                    password = self.changeSysPasswd()

                    if password == "":

                        return -1
                    
                    self.encodeFile(True)

                # Login to the system
                    
                for i in range(3):

                    strPassWd = getpass("\nPassword: ")

                    binPassWd = strPassWd.encode()
                    passSalt = Tools.readMapleTag(self.DATA_FILE, "SALT", "SECURITY_INFO")
                    salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
                    hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

                    isMatch = hashedPw == password

                    if isMatch:

                        self.logger(self.logLevel.INFO, "Password match.")
                        self.password = binPassWd
                        break

                    print("\n* Password incorrect.\n"
                        "* Please try again.")
                    self.logger(self.logLevel.INFO, f"Login failed {i + 1}")

                if not isMatch:

                    print("\n* Authentication failed *")
                    return -9
                
                elif self.decodeFile():

                    self.logger(self.logLevel.INFO, "System login.")
                    print("Password correct!")

                else:

                    print("\nFaliled to login.")
                    return -1
                
            except Exception as ex:

                self.logger(self.logLevel.FATAL, "Failed to startup.")
                self.Logger.ShowError(ex)
                return -98

            try:

                self.clearScreen()
                print("""
 Welcome to...

*--------------------------------------------------------------------*

  ::::::::::::::n,
  "::::M^^^^^\\::::M
   ::::M      :::::M
   ::::M      ;::;M
   :::::..,,;::;M"   ........_     ......_     ......_
   ::::M^^^^^^"     ::v^^^^:::A   ::v^^\\::A   ::v^^\\::A
   ::::M            "^.... :::M   ':...,`^^   ':...,`^^
   ::::M           :::W^^^':::M    `"\""`;::\\   `"\""`;::\\
   ::::M           '::.....:::.A  ::.....;:;N ::.....;:;N
   "^^^^            `^^^^^^^^^^   `^^^^^^^^   `^^^^^^^^

   ::::q          ::::n
   :::::.,      .:::::M
   :::::::.,  .:::::::M
   :::::::::.:::'W::::M
   ::::M;:::::'W" ::::M     ........_   .........._     ........_
   ::::M "'::W"   ::::M    ::v^^^^:::A  ":::v^^^:::A   ::v^^^^:::A
   ::::M    '"    ::::M    "^.... :::M   :::M   :::M   "^.... :::M
   ::::M          ::::M   :::W^^^':::M   :::M   :::M  :::W^^^':::M
  ::::::A        ::::::A  '::.....:::.A  :::M   ::::A '::.....:::.A
  "^^^^^^        "^^^^^^   `^^^^^^^^^^   "^^^   "^^^^  `^^^^^^^^^^

*--------------------------------------------------------------------*

""")
                
                while True:

                    self.logger(self.logLevel.INFO, "Main menu loaded.")

                    print("\n\n"
                        " * Main Menu *\n\n"
                        " 1) Generate Password\n"
                        " 2) Manage Password\n"
                        " S) Settings\n"
                        " Q) Quit\n")
                    select = input("Select menu > ").upper()
                    self.clearScreen()

                    if select == "1":

                        self.GeneratePasswordMain()

                    elif select == "2":

                        self.managePassword()

                    elif select == "S":

                        if self.settingsMenu():

                            return -9

                    elif select in self.EXIT_OPS:

                        self.logger(self.logLevel.INFO, "System logout.")
                        return 0

                    else:

                        print(f"\n{select} is not on the menu.")

            except Exception as ex:

                self.Logger.ShowError(ex)
                self.logger(self.logLevel.FATAL, "Could not handled the error.")
                self.logger(self.logLevel.FATAL, "Exit the program.")
                return -99

            finally:

                self.encodeFile(True)

        finally:

            self.logger(self.logLevel.INFO, "END\n- - - - - - - - - - - - - - - -")
            print(f"\n\n {random.choice(["See ya!", "Bye!", "Adios!", "Hasta luego!", "Пока!", "Sayonara!"])}\n")

#############################
# Main method (test)

gmp = GenManPw(1)
gmp.mainMenu()

# TODO_List:

# Settings menu
    # Change system password
    # Export data
    # Import data
    # etc...
