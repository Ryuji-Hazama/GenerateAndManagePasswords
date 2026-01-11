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

class GenManPw:

    def __init__(self, iterations):

        cwd = os.getcwd()
        workDir = "workDir"
        configFile = "config.mpl"

        # Check configuration directory

        if not path.isdir(path.join(cwd, workDir)):

            os.mkdir(path.join(cwd, workDir))

        # Check configuration file

        if not path.isfile(path.join(cwd, workDir, configFile)) and path.isfile(path.join(cwd, configFile)):

            shutil.copy(path.join(cwd, configFile), path.join(cwd, workDir, configFile))

        # Set const

        self.EXIT_OPS = {"Q", "E", "C", "QUIT", "EXIT", "CANCEL"}
        self.CHOICE = [True, False]
        self.DATA_TAG = "DATAS"
        self.HASH_TYPE = "sha256"
        self.ITERATIONS = iterations

        self.logger = maplex.Logger("GenManPw", os.path.join(cwd, workDir, "logs"))
        self.password = "".encode()

        # Load configuration

        self.conf = maplex.MapleTree(path.join(os.getcwd(), workDir, configFile))

        # Check the OS for clear screen

        if sys.platform.startswith("win"):

            self.clearCommand = "cls"

        else:

            self.clearCommand = "clear"

        # Get current working directory from configuration file

        cwd = self.conf.readMapleTag("CWD", "Application settings")

        if cwd == "":

            # If the directory is not configured

            self.CWD = os.getcwd()

        else:

            if not path.isdir(cwd):

                # Create if it does not exist

                self.logger.Info(f"Working directory does not exists: {cwd}")

                try:

                    os.mkdir(cwd)
                    self.CWD = cwd

                except Exception as ex:

                    self.logger.Warn("Failed to create working directory.")
                    self.logger.ShowError(ex)
                    self.CWD = os.getcwd()

            else:

                self.CWD = cwd

        self.logger.Debug(f"CWD is: {self.CWD}")

        self.DATA_FILE = path.join(self.CWD, workDir, "datas", "datas.mpl")
        self.PASS_LIST = path.join(self.CWD, workDir, "datas", "pwList.mpl")

        # Check data directoy

        if not path.isdir(path.join(self.CWD, workDir, "datas")):

            os.makedirs(path.join(self.CWD, workDir, "datas"))

        # Check temp directory

        if not path.isdir(path.join(self.CWD, "temp")):

            os.mkdir(path.join(self.CWD, "temp"))

        # Check data files

        if not path.isfile(self.DATA_FILE):

            try:

                with open(self.DATA_FILE, "w") as f:
                        
                    f.write(
"""
MAPLE
H DATAS
E
EOF
"""                 )

            except Exception as ex:

                self.logger.ShowError(ex)

        # Load data file

        self.dat = maplex.MapleTree(self.DATA_FILE)

    #
    ####################################
    # Clear screen

    def clearScreen(self):

        try:

            os.system(self.clearCommand)

        except Exception as ex:

            self.logger.Warn("Could not clear the screen.")
            self.logger.ShowError(ex)

    #
    ####################################
    # Change key

    def changeKey(self) -> bool:

        try:

            salt = os.urandom(16).hex()
            key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, salt.encode(), self.ITERATIONS))
            self.dat.saveValue("KEY", salt, "SECURITY_INFO", save=True)
            self.pwfile.changeEncryptionKey(key, True)
            self.logger.Info("Encryption key changed.")
            return True
        
        except Exception as ex:

            self.logger.ShowError(ex, "Failed to change encryption key.")
            return False

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

            self.dat.saveValue("KEY", salt, "SECURITY_INFO", save=True)
            self.logger.Info("File encrypted.")

        except Exception as ex:

            self.logger.Warn("File encryption failed.")
            self.logger.ShowError(ex)
            return False

        finally:

            if f is not None:
                f.close()

        # Delete original file

        if deleteDecodedFile:

            try:

                os.remove(self.PASS_LIST)
                self.logger.Info("Removed decoded file.")

            except Exception as ex:

                self.logger.Warn("Failed to remove decoded file.")
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

        self.logger.Warn(f"Failed to get password string. Site: {siteName} / Account: {accountName}")
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

        self.pwfile.saveValue(pwTag, token, "PW")
        self.pwfile.saveValue(pwTag, passSalt, "SALTS", save=True)

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

            for siteName in self.dat.getHeaders(self.DATA_TAG):
                for accountName in self.dat.getTags(self.DATA_TAG, siteName):

                    savedPass = self.getPassWd(siteName, accountName)
                    self.encodePassword(savedPass, self.dat.readMapleTag(accountName, self.DATA_TAG, siteName),
                                        siteName + accountName, binPassWd)

            # Save new password

            self.dat.saveValue("PW", hashedPw, "SECURITY_INFO", save=True)
            self.dat.saveValue("SALT", passSalt, "SECURITY_INFO", save=True)

            self.logger.Info("Hashed new password saved.")
            self.password = binPassWd
            self.changeKey()

            # Log

            self.logger.Info("System login password updated.")
            print("\nPassword updated!")

            return hashedPw
        
        except Exception as ex:

            self.logger.ShowError(ex)
            self.logger.Error("Failed to change password.")

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

            self.logger.Debug("Symbol list loaded")

            f = open(path.join(self.CWD, "NameList.txt"))
            nameList = f.readlines()
            f.close()

            self.logger.Debug("Names list loaded")

            f = open(path.join(self.CWD, "WordList.txt"))
            wordList = f.readlines()
            f.close()

            self.logger.Debug("Word list loaded")

            f = open(path.join(self.CWD, "VerbList.txt"))
            verbList = f.readlines()
            f.close()

            self.logger.Debug("Verbs list loaded")

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

        self.logger.Info("Auto generate password.")

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
                            self.logger.Info("Password copied to clipboard.")
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

            self.logger.Error("Failed to generate password.")
            self.logger.ShowError(ex)

        return ""

    #
    ##########################
    # Manually input password

    def manualPassword(self) -> str:

        self.logger.Info("Manually create password.")

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
                            self.logger.Info("Password copied to clipboard.")
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

        self.logger.Info(f"{menuStr} Selection Menu")
        listLen = len(selectList)

        while True:

            menuChoice = []

            print(f"\n\n * {menuStr} Selection Menu *")
            self.logger.Info(f"Page {i + 1} / {listLen // 10 + 1}")

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

                self.logger.Info("Selected none.")
                return ""
            
            elif resU in menuChoice:

                if resU == "N":

                    i += 1

                elif resU == "P":

                    i -= 1

                else:

                    self.logger.Info(f"[{selectList[int(res) + i * 10]}] selected.")
                    return selectList[int(res) + i * 10]
                
            elif resU.startswith("SEARCH "):

                # If there is no search string after the command

                if len(resU) < 8:

                    print("Search string empty.")
                    continue

                # Get search string

                self.logger.Info(resU)
                searchStr = res[7:]

                # Create list

                newSelectList = []

                for listElement in selectList:

                    if searchStr.upper() in listElement.upper():

                        newSelectList.append(listElement)

                # If there is no match element in the list

                if len(newSelectList) == 0:

                    print(f"Could not find \"{searchStr}\" in the list.")
                    self.logger.Info("No match data.")
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
        self.logger.Info(f"{newOrEdit[newData]} data.")

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

                    tagList = self.pwfile.getTags("PW")
                    i = 0
                    pwTag = f"PW{i}"

                    while pwTag in tagList:

                        i += 1
                        pwTag = f"PW{i}"

                except Exception as ex:

                    self.logger.ShowError(ex)

                # Save tag

                self.dat.saveValue(accountName, pwTag, self.DATA_TAG, siteName, save=True)

            else:

                # Get pw tag

                pwTag = self.dat.readMapleTag(accountName, self.DATA_TAG, siteName)

            # Encode and save

            self.encodePassword(newPassword, pwTag, siteName + accountName, self.password)

            # Log results

            self.logger.Info(f"VV Create new data VV")
            self.logger.Info(f"Site   : {siteName}")
            self.logger.Info(f"Account: {accountName}")
            self.logger.Info(f"PassWd : {newPassword[:4]}******{newPassword[10:]}")
            self.logger.Info(f"^^ Create complete ^^")

            print(("\nPassword updated", "\nNew data created!")[newData])

        except Exception as ex:

            self.logger.Error("Failed to generate new password.")
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

        self.logger.Info("Generate Password menu loaded.")
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

                self.logger.Info(f"Account selected [Site: {siteName} / Account: {accountName}]")
                return siteName, accountName
            
    #
    ##########################
    # Manage Password

    def managePassword(self) -> None:

        try:
                
            self.logger.Info(f"Manage Password Menu")
            siteName, accountName = self.selectAccount()

            if siteName == "":

                return
            
        except Exception as ex:

            self.logger.Error("Failed to get account informations.")
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

                    self.logger.Info("Showing saved password.")
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
                                self.logger.Info("Password copied to clipboard.")
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
                                self.logger.Info(f"Account data has been deleted: [Site: {siteName} / Account: {accountName}]")
                                
                                self.saveData()

                            except Exception as ex:

                                self.logger.Error("Failed to delete account data.")
                                self.logger.ShowError(ex)
                                break

                            # Delete site data if all accounts have been deleted

                            try:

                                if len(self.dat.getTags(self.DATA_TAG, siteName)) == 0:

                                    self.dat.removeHeader(siteName, self.DATA_TAG, save=True)
                                    print("Site data deleted.")
                                    self.logger.Info(f"Site data has been deleted: {siteName}")

                            except Exception as ex:

                                self.logger.ShowError(ex)

                            return

                        elif resU == "N":

                            break

                        else:

                            print(f"\n{res} is not on the menu.")

                    continue

                elif res in self.EXIT_OPS:

                    self.logger.Info("Exit Manage Password Menu.")
                    return
                
                else:

                    print(f"\n{res} is not on the menu.\n")

        except Exception as ex:

            self.logger.Error("Failded to manage password.")
            self.logger.ShowError(ex)

    #
    ##########################
    # Settings Menu

    def settingsMenu(self) -> bool:

        self.logger.Info("Settings menu loaded.")

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

                self.logger.Info("Exit settings menu.")
                return False
            
            elif resU == "1":

                self.logger.Info("Changing login password.")

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
                            self.logger.Info("Authenticated.")
                            break

                        print("\n* Password incorrect.\n"
                            "* Please try again.")
                        self.logger.Info(f"Authentication failed {i + 1}")

                    if not isMatch:

                        print("\n\n* Authentication failed *\n\n"
                              "And you are kicked out.")
                        self.logger.Info("Failed to authenticate to change login password")
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

                self.logger.Info("START")
                password = self.dat.readMapleTag("PW", "SECURITY_INFO")

                # If the first time to use

                if password == "":

                    self.logger.Info("First time to login.")

                    password = self.changeSysPasswd()

                    if password == "":

                        return -1

                # Login to the system
                    
                for i in range(3):

                    strPassWd = getpass("\nPassword: ")

                    binPassWd = strPassWd.encode()
                    passSalt = self.dat.readMapleTag("SALT", "SECURITY_INFO")
                    salt = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, passSalt.encode(), self.ITERATIONS)
                    hashedPw = hashlib.pbkdf2_hmac(self.HASH_TYPE, binPassWd, salt, self.ITERATIONS).hex()

                    isMatch = hashedPw == password

                    if isMatch:

                        self.logger.Info("Password match.")
                        self.password = binPassWd
                        break

                    print("\n* Password incorrect.\n"
                        "* Please try again.")
                    self.logger.Info(f"Login failed {i + 1}")

                if not isMatch:

                    print("\n* Authentication failed *")
                    return -9

                try:

                    # Check password file exists

                    if not path.exists(self.PASS_LIST):

                        newFile = True

                    else:

                        newFile = False

                    # Load password file

                    fileHashSalt = self.dat.readMapleTag("KEY", "SECURITY_INFO").encode()
                    key = base64.b64encode(hashlib.pbkdf2_hmac(self.HASH_TYPE, self.password, fileHashSalt, self.ITERATIONS))
                    self.pwfile = maplex.MapleTree(self.PASS_LIST, encrypt=True, key=key, createBaseFile=newFile)

                except maplex.MapleException as mex:

                    self.logger(self.logLevel.FATAL, "Failed to load password file.")
                    self.logger.ShowError(mex)
                    return -97

                self.logger.Info("System login.")
                print("Password correct!")
                
            except Exception as ex:

                self.logger(self.logLevel.FATAL, "Failed to startup.")
                self.logger.ShowError(ex)
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

                    self.logger.Info("Main menu loaded.")

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

                        self.logger.Info("System logout.")
                        return 0

                    else:

                        print(f"\n{select} is not on the menu.")

            except Exception as ex:

                self.logger.ShowError(ex)
                self.logger(self.logLevel.FATAL, "Could not handled the error.")
                self.logger(self.logLevel.FATAL, "Exit the program.")
                return -99

            finally:

                self.changeKey()

        finally:

            self.logger.Info("END\n- - - - - - - - - - - - - - - -")
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
