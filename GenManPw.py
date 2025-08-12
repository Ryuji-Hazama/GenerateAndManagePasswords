import base64
from cryptography.fernet import Fernet
from enum import IntEnum
import datetime
from getpass import getpass
import hashlib
import inspect
import os
from os import path, mkdir, getpid
import random
import Tools
import traceback

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
            self.consoleLogLevel = self.isLogLevel(Tools.readMapleTag(self.configFile, "CMD", "Log settings", "MapleDeEncoder"))
            self.fileLogLevel = self.isLogLevel(Tools.readMapleTag(self.configFile, "FLE", "Log settings", "MapleDeEncoder"))

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

        self.EXIT_OPS = {"Q", "E", "QUIT", "EXIT", "CANCEL"}
        self.CHOICE = [True, False]
        self.CWD = os.getcwd()
        self.DATA_FILE = path.join(self.CWD, "datas", "datas.mpl")
        self.PASS_LIST = path.join(self.CWD, "datas", "pwList.mpl")
        self.DATA_TAG = "DATAS"
        self.HASH_TYPE = "sha256"
        self.ITERATIONS = iterations

        self.Logger = Logger("GenManPw")
        self.logger = self.Logger.logWriter
        self.logLevel = self.Logger.LogLevel
        self.password = "".encode()

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
    # Encode file

    def encodeFile(self):

        f = None

        try:

            f = open(self.PASS_LIST, "r")
            fileData = f.read().encode()
            f.close()

            salt = os.urandom(16).hex()
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))
            fileData = Fernet(key).encrypt(fileData).decode()

            f = open(self.PASS_LIST, "w")
            f.write(fileData)
            f.close()

            Tools.saveTagLine(self.DATA_FILE, "KEY", salt, "SECURITY_INFO")
            self.logger(self.logLevel.INFO, "File encrypted.")

        except Exception as ex:

            self.Logger.ShowError(ex)
            self.logger(self.logLevel.ERROR, "File encryption failed.")

        finally:

            if f is not None:

                f.close()

    #
    ####################################
    # Decode file

    def decodeFile(self):

        f = None

        try:

            f = open(self.PASS_LIST, "r")
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
            raise

        finally:

            if f is not None:

                f.close()

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

                    break

                print("\n"
                        "* PASSWORD DOESN'T MATCH\n"
                        "* Please try again.")
                
            # Save password

            binPassWd = strPassWd.encode()
            salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, b"", self.ITERATIONS)
            hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

            Tools.saveTagLine(self.DATA_FILE, "PW", hashedPw, "SECURITY_INFO")

            # Re-encode password file

            self.password = binPassWd

            # Log

            self.logger(self.logLevel.INFO, "System login password updated.")
            self.logger(self.logLevel.INFO, f"Password: *******{strPassWd[7:]}")
            self.logger(self.logLevel.INFO, f"Hashed  : {hashedPw}")
            print("\nPassword updated!")

            return hashedPw
        
        except Exception as ex:

            self.Logger.ShowError(ex)
            self.logger(self.logLevel.ERROR, "Failed to change password.")

        return ""

    #
    ####################################
    # Random capitalize

    def randCap(self, baseStr) -> str:

        capCount = len(baseStr) // 8 + 1

        for i in range(capCount):

            if random.choice(self.CHOICE):
                    
                randIndex = random.randint(0, len(baseStr) - 1)
                indexLetter = baseStr[randIndex]
                willCange = random.choice(self.CHOICE)

                if indexLetter == "o" and willCange:

                    indexLetter = "0"

                elif indexLetter in {"i", "l"} and willCange:

                    indexLetter = "1"

                elif indexLetter == "a" and willCange:

                    indexLetter = "4"

                else:

                    indexLetter = indexLetter.upper()

                baseStr = baseStr[:randIndex] + indexLetter + baseStr[randIndex + 1:]

        return baseStr

    ####################################
    # Generate password string

    def generatePasswordStr(self):

        pwStr = ""
        secondRound = False

        try:

            # Get lists

            f = open(path.join(self.CWD, "Symbols.txt"))
            symList = f.readlines()
            f.close()

            self.logger(self.logLevel.INFO, "Symbol list loaded")

            f = open(path.join(self.CWD, "NameList.txt"))
            nameList = f.readlines()
            f.close()

            self.logger(self.logLevel.INFO, "Names list loaded")

            f = open(path.join(self.CWD, "WordList.txt"))
            wordList = f.readlines()
            f.close()

            self.logger(self.logLevel.INFO, "Word list loaded")

            f = open(path.join(self.CWD, "VerbList.txt"))
            verbList = f.readlines()
            f.close()

            self.logger(self.logLevel.INFO, "Verbs list loaded")

        except Exception as ex:

            self.Logger.ShowError(ex)
            
            return ""

        # First letter

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

            if not any(c.isdigit() for c in pwStr) or random.choice(self.CHOICE):

                pwStr += random.choice(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])
            
            if secondRound and len(pwStr) > 16:

                break

            # Name

            pwStr += self.randCap(random.choice(nameList).rstrip("\n") + random.choice(["\'s", ""]))

            # Symbol

            pwStr += self.randCap(random.choice(symList).rstrip("\n"))
        
        return pwStr
    
    #
    ####################################
    # Confirm password

    def confPassword(self) -> str:

        while True:

            newPassword = self.generatePasswordStr()
            print(f"New password: {newPassword}")
            question = random.choice(["You like it?", "How about this? "])

            while True:

                res = input(f"\n{question} (y/n) > ").upper()

                if res == "Y":

                    return newPassword
                
                elif res == "N":

                    break

                elif res in self.EXIT_OPS:

                    return ""
                
                else:

                    continue
    
    #
    ##########################
    # List select

    def selectFromList(self, selectList, menuStr, i) -> str:

        listLen = len(selectList)

        while True:

            menuChoice = []

            print(f"\n\n * {menuStr} Selection Menu *")
            if listLen > 10:

                print(f"> Page {i + 1} / {listLen // 10 + 1} <")

            print("\n")

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

            res = input(f"\nSelect > ").upper()

            if res in self.EXIT_OPS:

                return ""
            
            elif res in menuChoice:

                if res == "N":

                    i += 1

                elif res == "P":

                    i -= 1

                else:

                    return selectList[int(res) + i * 10]
            
            else:

                print(f"\n{res} is not on the menu.\n")

    #
    ##########################
    # Create new account
    
    def createNewAccount(self, siteName, overwrite = False):

        if overwrite:

            self.logger(self.logLevel.INFO, "Edit account password.")

        else:

            self.logger(self.logLevel.INFO, "Generate account password.")

        while True:

            ################################
            # TODO_                        #
            # If overwrite: select account #
            # If not: enter account name   #
            ################################

            newAccount = input("\nAccount name > ").replace(" ", "_")

            if newAccount.upper() in self.EXIT_OPS:

                return False
            
            accountList = Tools.getTags(self.DATA_FILE, self.DATA_TAG, siteName)

            if newAccount in accountList and not overwrite:

                while True:

                    res = input(f"\n{newAccount} is already exists in {siteName}\n"
                          f"Will you edit {newAccount} for {siteName} (y/n/c(ancel)) > ").upper()
                    
                    if res in self.EXIT_OPS + ["C"]:

                        return False
                    
                    elif res in {"Y", "N"}:

                        break
                    
                    else:

                        print(f"{res} is not on the menu.")

                if res == "N":

                    continue
            
            newPassword = self.confPassword()

            if newPassword == "":

                return False
            
            # Encrypt password

            passSalt = os.urandom(16).hex()
            saltStr = passSalt + siteName + newAccount
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, saltStr.encode(), self.ITERATIONS))
            token = Fernet(key).encrypt(newPassword.encode()).decode()
            
            # Create new tag

            try:

                tagList = Tools.getTags(self.PASS_LIST, "PW")
                i = 0
                pwTag = f"PW{i}"

                while pwTag in tagList:

                    i += 1
                    pwTag = f"PW{i}"

                # Save

                Tools.saveTagLine(self.PASS_LIST, pwTag, token, "PW")
                Tools.saveTagLine(self.PASS_LIST, pwTag, passSalt, "SALTS")

            except Exception as ex:

                self.Logger.ShowError(ex)
                self.logger(self.logLevel.ERROR, "Could not save the password info.")
                return False

            Tools.saveTagLine(self.DATA_FILE, newAccount, pwTag, self.DATA_TAG, siteName)

            self.logger(self.logLevel.INFO, f"VV Create new data VV")
            self.logger(self.logLevel.INFO, f"Site   : {siteName}")
            self.logger(self.logLevel.INFO, f"Account: {newAccount}")
            self.logger(self.logLevel.INFO, f"PassWd : {newPassword[:4]}******{newPassword[10:]}")
            self.logger(self.logLevel.INFO, f"^^ Create complete ^^")
            print("\nNew data created!\n")

            break

    #
    ##########################
    # Site selection menu

    def selectSite(self, pageInd = 0) -> str:

        siteList = Tools.getHeaders(self.DATA_FILE, self.DATA_TAG)
        
        if len(siteList) == 0:

            print("No data has been saved yet.")
            return ""
        
        return self.selectFromList(siteList, "Site", pageInd)

    #
    ##########################
    # Account selection menu

    def selectAccount(self, siteName: str, page: str) -> str:

        accList = Tools.getTags(self.DATA_FILE, self.DATA_TAG, siteName)

        if len(accList) == 0:

            print("No account data has been saved.")
            return ""

        return self.selectFromList(accList, "Account", page)

    #
    ####################################
    # New site data

    def newSiteData(self):

        siteList = Tools.getHeaders(self.DATA_FILE, self.DATA_TAG)

        while True:

            newSite = input("\nSite name > ")

            if newSite in siteList:

                while True:

                    res = input(f"\n{newSite} is already existing in the list\n"
                                "Will you add new account? (y/n) > ").upper()
                    
                    if res in {"Y", "N"}:

                        break

                    elif res in self.EXIT_OPS:

                        return
                    
                    else:

                        print(f"{res} is not on the menu.")

                if res == "N":
    
                    continue

            elif newSite.upper() in self.EXIT_OPS:

                return

            self.createNewAccount(newSite)

            break

    #
    ####################################
    # Generate Password menu

    def GeneratePasswordMain(self):

        print("\n\n * Generate Password *")
        self.logger(self.logLevel.INFO, "Generate Password menu loaded.")

        while True:

            print("\n\n * Generate Password *\n\n"
                  " 1) New site (or system)\n" \
                  " 2) New account (for saved site)\n" \
                  " E) Back to main menu\n")
            select = input("Generate password for... > ").upper()

            if select == "1":

                try:
                    
                    self.newSiteData()

                except Exception as ex:

                    self.Logger.ShowError(ex)
                    
                continue

            elif select == "2":

                try:

                    siteName = self.selectSite()

                    if siteName == 0:

                        continue

                    self.createNewAccount(siteName)

                except Exception as ex:

                    self.Logger.ShowError(ex)

                continue

            elif select in self.EXIT_OPS:

                return
            
            else:

                print(f"\n{select} is not on the menu.\n")

    #
    ##########################
    # Password serch menu

    def serchPassword(self):

        sitePage = 0

        while True:
            
            siteName = self.selectSite(sitePage)

            if siteName == "":

                return
            
            accPage = 0

            while True:
                    
                accountName = self.selectAccount(siteName, accPage)

                if accountName == "":

                    break
                    
                accountTag = Tools.readMapleTag(self.DATA_FILE, accountName, self.DATA_TAG, siteName)

                # Decrypt password

                passWdToken = Tools.readMapleTag(self.PASS_LIST, accountTag, "PW").encode()
                salt = Tools.readMapleTag(self.PASS_LIST, accountTag, "SALTS") + siteName + accountName

                key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))
                password = Fernet(key).decrypt(passWdToken).decode()

                # Get max string length

                xLen = max([len(siteName), len(accountName), len(password)]) + 11

                print("\n"
                     f" *{"".join("-" for _ in range(xLen))}*\n"
                     f" * Site    : {siteName}\n"
                     f" * Account : {accountName}\n"
                     f" * PassWd  : {password}\n"
                     f" *{"".join("-" for _ in range(xLen))}*")
            
    #
    ##########################
    # Main menu

    def mainMenu(self) -> int:

        try:

            password = Tools.readMapleTag(self.DATA_FILE, "PW", "SECURITY_INFO")

            # If the first time to use

            if password == "":

                self.logger(self.logLevel.INFO, "First time to login.")

                password = self.changeSysPasswd()

                if password == "":

                    return
                
                self.encodeFile()

        except Exception as ex:

            self.Logger.ShowError(ex)
            self.logger(self.logLevel.ERROR, "Could not get login info.")
            
            return

        # Login to the system

        for i in range(3):

            strPassWd = getpass("\nPassword: ")

            binPassWd = strPassWd.encode()
            salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, b"", self.ITERATIONS)
            hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

            isMatch = hashedPw == password

            if isMatch:

                self.password = strPassWd.encode()
                self.logger(self.logLevel.INFO, "System login.")
                break

            print("\n* Password incorrect.\n"
                  "* Please try again.")
            self.logger(self.logLevel.INFO, f"Login failed {i + 1}")

        if not isMatch:

            print("\n* Authentication failed *\n")

            return
        
        else:

            print("Password correct!")

        try:

            self.decodeFile()
            print("\n"
                " * - - - - - - - - -*\n" \
                " * Password Manager *\n" \
                " * - - - - - - - - -*\n")
            
            while True:

                self.logger(self.logLevel.INFO, "Main menu loaded.")

                print("\n\n"
                    " * Main Menu *\n\n"
                    " 1) Generate Password\n"
                    " 2) Search Password\n"
                    " 3) Manage Passwords\n"
                    " S) Settings\n"
                    " Q) Quit\n")
                select = input("Select menu > ").upper()

                if select == "1":

                    self.GeneratePasswordMain()

                elif select == "2":

                    self.serchPassword()

                elif select == "3":

                    print("Coming soon...")
                    continue

                elif select == "S":

                    print("Coming soon...")
                    continue

                elif select in self.EXIT_OPS:

                    self.logger(self.logLevel.INFO, "System logout.")
                    return 0

                else:

                    print(f"{select} is not in the menu.\n")

        except Exception as ex:

            self.Logger.ShowError(ex)
            self.logger(self.logLevel.FATAL, "Could not handled the error.")
            self.logger(self.logLevel.FATAL, "Exit the program.")
            return

        finally:

            self.encodeFile()
            print("\nSee ya!\n\n")

#############################
# Main method (test)

gmp = GenManPw(1)
gmp.mainMenu()

# TODO_List:

# Manage menu
    # Edit passwords
    # Delete datas
    # etc...

# Settings menu
    # Change system password
    # Export data
    # Import data
    # etc...
