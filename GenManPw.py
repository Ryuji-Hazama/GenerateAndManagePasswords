import base64
from cryptography.fernet import Fernet
from getpass import getpass
import hashlib
import maplex
from maplex import mapleExceptions as mpex
import os
from os import path, getpid
import pyperclip
import random
import shutil
import sys

from src.consts import *

class GenManPw:

    def __init__(self, iterations: int | None = None):

        cwd = os.getcwd()

        # Check configuration directory

        if not path.isdir(path.join(cwd, WORKING_DIRECTORY)):

            os.mkdir(path.join(cwd, WORKING_DIRECTORY))

        # Check configuration file

        if not path.isfile(path.join(cwd, WORKING_DIRECTORY, CONFIG_FILE)) and path.isfile(path.join(cwd, CONFIG_FILE)):

            shutil.copy(path.join(cwd, CONFIG_FILE), path.join(cwd, WORKING_DIRECTORY, CONFIG_FILE))

        # Set const

        self.EXIT_OPS = {"Q", "E", "C", "QUIT", "EXIT", "CANCEL"}
        self.CHOICE = [True, False]
        self.DATA_TAG = KEY_DATAS
        self.HASH_TYPE = "sha256"

        self.logger = maplex.Logger("GenManPw", os.path.join(cwd, WORKING_DIRECTORY, "logs"), configFile=os.path.join(cwd, WORKING_DIRECTORY, CONFIG_FILE))
        self.password = "".encode()

        # Load configuration

        self.conf = maplex.MapleJson(path.join(cwd, WORKING_DIRECTORY, CONFIG_FILE))
        self.confJson = self.conf.read()
        self.appSettings = self.confJson.get(KEY_APPLICATION_SETTINGS, None)

        if self.appSettings is None:

            self.logger.warn("Application settings not found in configuration file.")
            self.appSettings = {}
            self.confJson[KEY_APPLICATION_SETTINGS] = self.appSettings
            self.conf.write(self.confJson)

        # Set iterations

        if iterations is not None:

            self.ITERATIONS = iterations

        else:

            iterConf = self.appSettings.get("Iterations", None)

            if iterConf is None:

                self.ITERATIONS = 100000
                self.appSettings["Iterations"] = self.ITERATIONS
                self.confJson[KEY_APPLICATION_SETTINGS] = self.appSettings
                self.conf.write(self.confJson)

            else:

                self.ITERATIONS = iterConf

        # Check the OS for clear screen

        if sys.platform.startswith("win"):

            self.clearCommand = "cls"

        else:

            self.clearCommand = "clear"

        # Get current working directory from configuration file

        cwd = self.appSettings.get("WorkingDirectory", "")

        if cwd == "":

            # If the directory is not configured

            self.CWD = os.getcwd()

        else:

            if not path.isdir(cwd):

                # Create if it does not exist

                self.logger.info(f"Working directory does not exists: {cwd}")

                try:

                    os.mkdir(cwd)
                    self.CWD = cwd

                except Exception as ex:

                    self.logger.warn("Failed to create working directory.")
                    self.logger.ShowError(ex)
                    self.CWD = os.getcwd()

            else:

                self.CWD = cwd

        self.logger.debug(f"Working directory is: {self.CWD}")

        self.DATA_FILE = path.join(self.CWD, WORKING_DIRECTORY, KEY_DATAS, "datas.json")
        self.PASS_LIST = path.join(self.CWD, WORKING_DIRECTORY, KEY_DATAS, "pwList.json")
        self.dataFileInstance = maplex.MapleJson(self.DATA_FILE)

        # Check data directory

        if not path.isdir(path.join(self.CWD, WORKING_DIRECTORY, KEY_DATAS)):

            os.makedirs(path.join(self.CWD, WORKING_DIRECTORY, KEY_DATAS))

        # Check temp directory

        if not path.isdir(path.join(self.CWD, WORKING_DIRECTORY, "temp")):

            os.mkdir(path.join(self.CWD, WORKING_DIRECTORY, "temp"))

        # Check data files

        if not path.isfile(self.DATA_FILE):

            try:

                self.dat = {KEY_DATAS: [], KEY_SECURITY_INFO: {}}
                self.dataFileInstance.write(self.dat)

            except Exception as ex:

                self.logger.error("Failed to initialize data file.", ex)

        # Load data file

        self.dat = self.dataFileInstance.read()

    #
    ####################################
    # Clear screen

    def clearScreen(self):

        try:

            os.system(self.clearCommand)

        except Exception as ex:

            self.logger.error("Failed to clear the screen.", ex)

    #
    ####################################
    # Change key (maybe not need this function but just in case)

    def changeKey(self) -> bool:

        try:

            salt = os.urandom(16).hex()
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))

            # Save new key and salt

            securityInfo = self.dat.get(KEY_SECURITY_INFO, {})
            securityInfo[KEY_KEY] = salt
            self.dat[KEY_SECURITY_INFO] = securityInfo
            self.dataFileInstance.write(self.dat)
            currentPasswords = self.pwfile.read()
            self.pwfile.setEncryption(True, key)
            self.pwfile.write(currentPasswords)
            self.logger.info("Encryption key changed.")
            return True
        
        except Exception as ex:

            self.logger.error("Failed to change encryption key.", ex)
            return False

    #
    ####################################
    # Encode file (replace this with maples.MapleJson().encrypt() later)

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

            self.dat.saveValue("KEY", salt, "SECURITY_INFO", save=True)
            self.logger.info("File encrypted.")

        except Exception as ex:

            self.logger.warn("File encryption failed.")
            self.logger.ShowError(ex)
            return False

        finally:

            if f is not None:
                f.close()

        # Delete original file

        if deleteDecodedFile:

            try:

                os.remove(self.PASS_LIST)
                self.logger.info("Removed decoded file.")

            except Exception as ex:

                self.logger.warn("Failed to remove decoded file.")
                self.logger.ShowError(ex)

        return True
    
    #
    ##########################
    # Decode password

    def getPassWd(self, siteName: str, accountName: str):

        try:

            # Get account tag

            accountTag = self.dat.readMapleTag(accountName, self.DATA_TAG, siteName)

            # Decrypt password

            passWdToken = self.pwfile.readMapleTag(accountTag, "PW").encode()
            salt = self.pwfile.readMapleTag(accountTag, "SALTS") + siteName + accountName

            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))
            return Fernet(key).decrypt(passWdToken).decode()

        except Exception as ex:

            self.logger.ShowError(ex)

        self.logger.warn(f"Failed to get password string. Site: {siteName} / Account: {accountName}")
        print("\nFailed to get password.")
        return ""

    #
    ####################################
    # Encode password string and save

    def encodePassword(self, newPassword: str, pwTag: str, siteAndAccount: str, keyPassword: bytes) -> bool:

        # Encrypt password

        passSalt = os.urandom(16).hex()
        saltStr = passSalt + siteAndAccount
        key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, keyPassword, saltStr.encode(), self.ITERATIONS))
        token = Fernet(key).encrypt(newPassword.encode()).decode()
    
        # Save

        passDict = self.pwfile.read()
        passwordList = passDict.get(KEY_PASSWORD_LIST, {})
        saltList = passDict.get(KEY_SALT_LIST, {})

        passwordList[pwTag] = token
        saltList[pwTag] = passSalt

        # Update in-memory lists
        passDict[KEY_PASSWORD_LIST] = passwordList
        passDict[KEY_SALT_LIST] = saltList

        self.pwfile.write(passDict)

    #
    ####################################
    # Change system password

    def changeSysPasswd(self) -> str:

        try:
            
            while True:

                strPassWd = getpass("\nNew password: ")

                if len(strPassWd) < 8:

                    print("\n* PASSWORD MUST BE OVER 8 CHARACTERS.")
                    
                    continue

                confPassWd = getpass("\nConfirm password: ")

                if strPassWd == confPassWd:

                    self.clearScreen()
                    break

                print("\n"
                        "* PASSWORD DOESN'T MATCH\n"
                        "* Please try again.")
                
            # Hash password

            binPassWd = strPassWd.encode()
            passSalt = os.urandom(16).hex()
            salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
            hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

            # Re-hash saved passwords

            for siteData in self.dat.get(KEY_DATAS, []):

                siteName = siteData.get("Site", "")
                accountList = siteData.get("Accounts", [])

                for accountName in accountList:

                    savedPass = self.getPassWd(siteName, accountName)
                    self.encodePassword(savedPass, self.dat.readMapleTag(accountName, self.DATA_TAG, siteName),
                                        siteName + accountName, binPassWd)

            # Save new password

            securityInfo = self.dat.get(KEY_SECURITY_INFO, {})
            securityInfo[KEY_PASSWORD] = hashedPw
            securityInfo[KEY_SALT] = passSalt

            self.dat[KEY_SECURITY_INFO] = securityInfo
            self.dataFileInstance.write(self.dat)

            self.logger.info("Hashed new password saved.")
            self.password = binPassWd
            self.changeKey()

            # Log

            self.logger.info("System login password updated.")
            print("\nPassword updated!")

            return hashedPw
        
        except Exception as ex:

            self.logger.error("Failed to change password.", ex)

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

            self.logger.debug("Symbol list loaded")

            f = open(path.join(self.CWD, "NameList.txt"))
            nameList = f.readlines()
            f.close()

            self.logger.debug("Names list loaded")

            f = open(path.join(self.CWD, "WordList.txt"))
            wordList = f.readlines()
            f.close()

            self.logger.debug("Word list loaded")

            f = open(path.join(self.CWD, "VerbList.txt"))
            verbList = f.readlines()
            f.close()

            self.logger.debug("Verbs list loaded")

        except Exception as ex:

            self.logger.ShowError(ex)
            
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

        self.logger.info("Auto generate password.")

        try:

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

                        try:

                            pyperclip.copy(newPassword)
                            self.clearScreen()
                            self.logger.info("Password copied to clipboard.")
                            print("Password copied to clipboard.")

                        except Exception as ex:

                            self.logger.ShowError(ex)
                            print("\nCopy password to clipboard failed.")

                        continue

                    elif resU in self.EXIT_OPS:

                        return ""
                    
                    else:

                        print(f"\n{res} is not on the menu.")
                        continue

        except Exception as ex:

            self.logger.error("Failed to generate password.")
            self.logger.ShowError(ex)

        return ""

    #
    ##########################
    # Manually input password

    def manualPassword(self) -> str:

        self.logger.info("Manually create password.")

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

                        try:
                                
                            pyperclip.copy(pwStr)
                            self.clearScreen()
                            self.logger.info("Password copied to clipboard.")
                            print("\nPassword copied to clipboard.")

                        except Exception as ex:

                            self.logger.ShowError(ex)
                            print("\nCopy password to clipboard failed.")

                        continue

                    else:

                        print(f"\n{res} is not on the menu.")
        
    #
    ##########################
    # List select

    def selectFromList(self, selectList: list[str], menuStr: str, i = 0) -> str:

        self.logger.info(f"{menuStr} Selection Menu")
        listLen = len(selectList)

        while True:

            menuChoice = []

            print(f"\n\n * {menuStr} Selection Menu *")
            self.logger.info(f"Page {i + 1} / {listLen // 10 + 1}")

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

                self.logger.info("Selected none.")
                return ""
            
            elif resU in menuChoice:

                if resU == "N":

                    i += 1

                elif resU == "P":

                    i -= 1

                else:

                    self.logger.info(f"[{selectList[int(res) + i * 10]}] selected.")
                    return selectList[int(res) + i * 10]
                
            elif resU.startswith("SEARCH "):

                # If there is no search string after the command

                if len(resU) < 8:

                    print("Search string empty.")
                    continue

                # Get search string

                self.logger.info(resU)
                searchStr = res[7:]

                # Create list

                newSelectList = []

                for listElement in selectList:

                    if searchStr.upper() in listElement.upper():

                        newSelectList.append(listElement)

                # If there is no match element in the list

                if len(newSelectList) == 0:

                    print(f"Could not find \"{searchStr}\" in the list.")
                    self.logger.info("No match data.")
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
        self.logger.info(f"{newOrEdit[newData]} data.")

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
            
            if newData:

                # Create new tag

                try:

                    passwordList = self.pwfile.readOrDefault(KEY_PASSWORD_LIST, {})
                    tagList = list(passwordList.keys())
                    i = 0
                    pwTag = f"PW{i}"

                    while pwTag in tagList:

                        i += 1
                        pwTag = f"PW{i}"

                except Exception as ex:

                    self.logger.ShowError(ex)

                # Save tag

                datDicts = self.dat.get(KEY_DATAS, [])
                siteData = next((item for item in datDicts if item.get(KEY_SITE_NAME) == siteName), {})
                siteData[KEY_ACCOUNT_NAME] = accountName
                siteData[KEY_PASSWORD_KEY] = pwTag
                
                if siteData not in datDicts:

                    datDicts.append(siteData)

                else:

                    self.logger.warn(f"Site data already exists: {siteName}")

                self.dat[KEY_DATAS] = datDicts
                self.dataFileInstance.write(self.dat)

            else:

                # Get pw tag

                pwTag = self.dat.readMapleTag(accountName, self.DATA_TAG, siteName)

            # Encode and save

            self.encodePassword(newPassword, pwTag, siteName + accountName, self.password)

            # Log results

            self.logger.info(f"VV Create new data VV")
            self.logger.info(f"Site   : {siteName}")
            self.logger.info(f"Account: {accountName}")
            self.logger.info(f"PassWd : {newPassword[:4]}******{newPassword[10:]}")
            self.logger.info(f"^^ Create complete ^^")

            print(("\nPassword updated", "\nNew data created!")[newData])

        except Exception as ex:

            self.logger.error("Failed to generate new password.")
            self.logger.ShowError(ex)

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
            
            try:

                accountList = self.dat.getTags(self.DATA_TAG, siteName)

            except mpex.MapleDataNotFoundException:

                accountList = []

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
        siteList = self.dat.getHeaders(self.DATA_TAG)
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
        accList = self.dat.getTags(self.DATA_TAG, siteName)
        accList.sort()

        if len(accList) == 0:

            print("\nNo account data has been saved.")
            return ""

        return self.selectFromList(accList, "Account", pageInd)

    #
    ####################################
    # New site data

    def newSiteData(self):

        siteList = self.dat.getHeaders(self.DATA_TAG)

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

        self.logger.info("Generate Password menu loaded.")
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

                    self.logger.ShowError(ex)
                    
                continue

            elif select == "2":

                try:

                    siteName = self.selectSite()

                    if siteName != "":

                        newAccount = self.createNewAccountName(siteName)

                        if newAccount != "":

                            self.generateNewPassword(siteName, newAccount)

                except Exception as ex:

                    self.logger.ShowError(ex)

                continue

            elif select in self.EXIT_OPS:

                return
            
            else:

                print(f"\n{select} is not on the menu.\n")
        
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

                self.logger.info(f"Account selected [Site: {siteName} / Account: {accountName}]")
                return siteName, accountName
            
    #
    ##########################
    # Manage Password

    def managePassword(self) -> None:

        try:
                
            self.logger.info(f"Manage Password Menu")
            siteName, accountName = self.selectAccount()

            if siteName == "":

                return
            
        except Exception as ex:

            self.logger.error("Failed to get account informations.")
            self.logger.ShowError(ex)
            return
        
        try:
            
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

                    self.logger.info("Showing saved password.")
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

                            try:

                                # Copy password to clipboard

                                pyperclip.copy(password)
                                self.logger.info("Password copied to clipboard.")
                                print("\nPassword copied to clipboard.\n")

                            except Exception as ex:

                                self.logger.ShowError(ex)
                                print("\nCopy password to clipboard failed.")

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

                                accountTag = self.dat.readMapleTag(accountName, self.DATA_TAG, siteName)

                                # Delete password and account data

                                self.pwfile.deleteValue(accountTag, "PW")
                                self.pwfile.deleteValue(accountTag, "SALTS", save=True)
                                self.dat.deleteValue(accountName, self.DATA_TAG, siteName, save=True)
                                print("Account data deleted.")
                                self.logger.info(f"Account data has been deleted: [Site: {siteName} / Account: {accountName}]")
                                
                                self.saveData()

                            except Exception as ex:

                                self.logger.error("Failed to delete account data.")
                                self.logger.ShowError(ex)
                                break

                            # Delete site data if all accounts have been deleted

                            try:

                                if len(self.dat.getTags(self.DATA_TAG, siteName)) == 0:

                                    self.dat.removeHeader(siteName, self.DATA_TAG, save=True)
                                    print("Site data deleted.")
                                    self.logger.info(f"Site data has been deleted: {siteName}")

                            except Exception as ex:

                                self.logger.ShowError(ex)

                            return

                        elif resU == "N":

                            break

                        else:

                            print(f"\n{res} is not on the menu.")

                    continue

                elif res in self.EXIT_OPS:

                    self.logger.info("Exit Manage Password Menu.")
                    return
                
                else:

                    print(f"\n{res} is not on the menu.\n")

        except Exception as ex:

            self.logger.error("Failded to manage password.")
            self.logger.ShowError(ex)

    #
    ##########################
    # Settings Menu

    def settingsMenu(self) -> bool:

        self.logger.info("Settings menu loaded.")

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

                self.logger.info("Exit settings menu.")
                return False
            
            elif resU == "1":

                self.logger.info("Changing login password.")

                try:

                    password = self.dat.readMapleTag("PW", "SECURITY_INFO")
                    
                    for i in range(3):

                        strPassWd = getpass("\nCurrent password: ")

                        binPassWd = strPassWd.encode()
                        passSalt = self.dat.readMapleTag("SALT", "SECURITY_INFO")
                        salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
                        hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

                        isMatch = hashedPw == password

                        if isMatch:

                            self.password = binPassWd
                            self.logger.info("Authenticated.")
                            break

                        print("\n* Password incorrect.\n"
                            "* Please try again.")
                        self.logger.info(f"Authentication failed {i + 1}")

                    if not isMatch:

                        print("\n\n* Authentication failed *\n\n"
                              "And you are kicked out.")
                        self.logger.info("Failed to authenticate to change login password")
                        return True
                    
                    self.clearScreen()
                    self.changeSysPasswd()

                except Exception as ex:

                    self.logger.ShowError(ex)

            else:

                print(f"{res} is not on the menu.")
                continue
                
    #
    ##########################
    # Main menu

    def mainMenu(self) -> int:

        try:

            try:

                self.logger.info("START")
                password = self.dat.get(KEY_SECURITY_INFO, {}).get(KEY_PASSWORD, "")

                # If the first time to use

                if password == "":

                    self.logger.info("First time to login.")

                    # Create a new empty password file
                    self.pwfile = maplex.MapleJson(self.PASS_LIST)
                    self.pwfile.write({})

                    password = self.changeSysPasswd()

                    if password == "":

                        return -1

                # Login to the system
                    
                for i in range(3):

                    strPassWd = getpass("\nPassword: ")

                    binPassWd = strPassWd.encode()
                    passSalt = self.dat.get(KEY_SECURITY_INFO, {}).get(KEY_SALT, "")
                    salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
                    hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

                    isMatch = hashedPw == password

                    if isMatch:

                        self.logger.info("Password match.")
                        self.password = binPassWd
                        break

                    print("\n* Password incorrect.\n"
                        "* Please try again.")
                    self.logger.info(f"Login failed {i + 1}")

                if not isMatch:

                    print("\n* Authentication failed *")
                    return -9

                try:

                    # Load password file

                    fileHashSalt = self.dat.get(KEY_SECURITY_INFO, {}).get(KEY_KEY, "").encode()
                    key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, fileHashSalt, self.ITERATIONS))
                    self.pwfile = maplex.MapleJson(PASS_LIST, encrypt=True, key=key)

                except maplex.MapleException as mex:

                    self.logger.ShowError(mex, "Failed to load password file.", True)
                    return -97

                self.logger.info("System login.")
                print("Password correct!")
                
            except Exception as ex:

                self.logger.ShowError(ex, "Failed to startup.", True)
                return -98

            try:

                self.clearScreen()
                print("""
 Welcome to...

*--------------------------------------------------------------------*

  PPPPPPP                                                      D
  P      P                                                     D
  P      P                                                     D
  PPPPPPP   AAAAAA    SSSSS    SSSSS           W      W        D
  P               A  S        S                W      W  DDDDDDD
  P         AAAAAAA   SSSSS    SSSSS           W  WW  W D      D
  P        A      A        S        S          W  WW  W D      D
  P         AAAAAAA SSSSSSS  SSSSSSS  ########  WW  WW   DDDDDDD

  M      M
  MM    MM
  M M  M M
  M  MM  M  AAAAAA  N NNNNN   AAAAAA   GGGGGGG  EEEEEE  R RRRRR
  M      M        A NN     N        A G      G E      E RR     R
  M      M  AAAAAAA N      N  AAAAAAA G      G EEEEEEEE R
  M      M A      A N      N A      A  GGGGGGG E        R
  M      M  AAAAAAA N      N  AAAAAAA        G  EEEEEEE R
                                             G
                                       GGGGGG

*--------------------------------------------------------------------*

""")
                
                while True:

                    self.logger.info("Main menu loaded.")

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

                        self.logger.info("System logout.")
                        return 0

                    else:

                        print(f"\n{select} is not on the menu.")

            except Exception as ex:

                self.logger.ShowError(ex)
                self.logger.fatal("Could not handled the error.")
                self.logger.fatal("Exit the program.")
                return -99

            finally:

                self.changeKey()

        finally:

            self.logger.info("END\n- - - - - - - - - - - - - - - -")
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
