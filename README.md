# GenerateAndManagePasswords :asterisk::asterisk::asterisk:

&nbsp;&nbsp;&nbsp;&nbsp;This system generates the password strings randomly and stores them on your computer in a safe way, powered by Python.

&nbsp;&nbsp;&nbsp;&nbsp;:warning: **The current version is UNSTABLE because it is still in progress.**

## Requirement

&nbsp;&nbsp;&nbsp;&nbsp;You will need the following external packages to use this system if they haven't been installed yet.

- cryptography  
`python3 -m pip install cryptography`
- pyperclip  
`python3 -m pip install pyperclip`

## The Features

&nbsp;&nbsp;&nbsp;&nbsp;The system generates the random strings for the password. But the string is not just a random combination of the symbols that only the computer can understand. It generates a silly sentence that is made with the modified words, nouns, and common English names.

&nbsp;&nbsp;&nbsp;&nbsp;For example: `+WAtchFreeZeS4SHann0n*`

&nbsp;&nbsp;&nbsp;&nbsp;Why does the watch freeze for Shannon? It does not make sense, but it still could happen in your dream. So, it is much easier to remember more than randomly generated passwords like: `WT)eRT;63AcU#kp^`  
&nbsp;&nbsp;&nbsp;&nbsp;Because it does not make sense, it is much better than using ordinary sentences &mdash;It is almost impossible to guess the sentence for most people. And also, changing some characters in the middle of the word, like '0' for the 'o' in "Shannon", is increasing the strength for rainbow and dictionary attack, and using over 16 characters with symbols, numbers, and upper and lower characters is increasing the strength for the brute-force attack.

&nbsp;&nbsp;&nbsp;&nbsp;The system stores the generated password on your computer with the site name and account ID. The data is encrypted with the password safely. You can easily search and find the saved password from the automatically organized data. It is much safer and convenient than saving the data with "Notepad" as text data.

## How To Use

1. Download all the files in this repository (except for README.md file. :sweat_smile:)
2. Open a terminal and navigate to the directory where the files are saved.
3. Run `python3 GenManPw.py`

It is the same as using a basic Python file.

### Login

- When you use the system for the first time, you need to set a password for login.
- After the second time or if the setting data file exists, you need to input your password to unlock the system.

#### :warning: Warning (Login)

- If you forget your password, there is no way to recover data.
- Your saved data will not be recovered if you delete the data file to reset your password.

### Main Menu

- Input "1" for the password generation menu.
- Input "2" for the saved password management menu.
- Input "S" for the setting menu (not available yet.)
- Input "Q" for quitting the application.

### Generate Password Menu

- Input "1" for creating a new site and account data, and generate a new password.
- Input "2" for creating new account data in the saved site data and generate a password.
- Input "E" to go back to the main menu.

### Manage Password Menu

- Select account data from the list to manage data.
- Input "1" for showing the password.
  - You can copy the saved password to the clipboard after showing the password.
- Input "2" for changing password (not available yet.)
- Input "D" for delete account data.
  - Delete saved account data, password, and if there is no account data in the site data, site data.
- Input "E" for exiting to the main menu.

### Settings Menu

- Not available yet.

### Copy generated password to clipboard

- Input "COPY" at the generated password confirmation screen, generated password will be copied to the clipboard.

## :warning: Caution :rotating_light:

- The number of hashing iterations has been set to 1 for a quick test.
  - If you use this system or the class in real life, you should set iterations 1,000+ at the initialization of the class.
- The system is still in progress.
  - The data structure can be changed in a future update.
  - The data might be broken due to an unexpected system failure.
  - You should create a backup just in case.
- Clipboard data can be accessed from other applications.
  - Be sure to clear the clipboard data if you no longer need it to prevent data from being stolen by malware.
