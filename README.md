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

:warning: ***If you forgot the password, there is no way to recover data!!*** :rotating_light:
