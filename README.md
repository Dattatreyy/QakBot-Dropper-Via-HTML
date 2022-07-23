# Analysing New Variant of QakBot Being Spread by HTML File Attached to Phishing Emails

SHA256: e8bb9a41e6beb9ebf1627c9c6f06682c782c0e63a357c337cc56a0c753c137ec

As we can see the file is HTML and it has no submission in VT.

fig

The HTML file contains a piece of javascript code that is automatically executed once it is opened in a web browser by the recipient. It decodes a base64 string held by a local variable. It then calls a built-in function, navigator.msSaveOrOpenBlob(), to save the base64 decoded data (a ZIP archive) to a local file named “TXRTN_6442480.zip”.

fig

Decoding this from base64

fig

As we can see the encoded value which is starting from "PK..". It is the Magic Byte of ZIP file. 

Saving this ZIP File.

Check for Password in JS file itself. Use that to extract ZIP file.

<br><br>
<p class="mt-1" style="font-size: 30px;">Document password: <span style="background-color: LightGray">&nbsp abc321 &nbsp</span>
</p>

Next, we’ll look at what’s inside the downloaded ZIP archive. 

calc.exe application

102755.dll

WindowsCodeCS.dll and

It’s a Windows shortcut file – “TXRTN_6442480.lnk”. As you may know, a Windows shortcut file can execute commands by putting them into the Target field. Figure 2.1 shows a screenshot of this shortcut file and its properties. 

fig f

Target: C:\Windows\System32\cmd.exe /q /c calc.exe

This "lnk" file tries to launch "cmd.exe /q /c calc.exe" and this calc.exe is present inside zip folder.

























# Sample
https://bazaar.abuse.ch/sample/e8bb9a41e6beb9ebf1627c9c6f06682c782c0e63a357c337cc56a0c753c137ec/

# Reference
https://www.fortinet.com/blog/threat-research/new-variant-of-qakbot-spread-by-phishing-emails

