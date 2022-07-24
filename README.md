# Analysing New Variant of QakBot Being Spread by HTML File Attached to Phishing Emails

SHA256: e8bb9a41e6beb9ebf1627c9c6f06682c782c0e63a357c337cc56a0c753c137ec

As we can see the file is HTML and it has no submission in VT.

<img width="491" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180635787-da0e2f9b-5814-419d-8b75-d29633650e10.PNG">


The HTML file contains a piece of javascript code that is automatically executed once it is opened in a web browser by the recipient. It decodes a base64 string held by a local variable. It then calls a built-in function, to save the base64 decoded data (a ZIP archive) to a local file named “TXRTN_6442480.zip”.

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636072-7ae7ba8c-21f3-49b2-a08f-331851176392.PNG">

Decoding this from base64

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636136-2f692c8b-347c-46f2-b9f3-6cf0326c4b3d.PNG">

As we can see the encoded value which is starting from "PK..". It is the Magic Byte of ZIP file. 

Saving this ZIP File.

Check for Password in JS file itself. Use that to extract ZIP file.
<br><br>
<p class="mt-1" style="font-size: 30px;">Document password: <span style="background-color: LightGray">&nbsp abc321 &nbsp</span>
</p>

Next, we’ll look at what’s inside the downloaded ZIP archive. 

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636334-a4b70d1d-7827-4cdd-b19f-0a857e7b6f2d.PNG">

1. calc.exe application

2. 102755.dll

3. WindowsCodeCS.dll and

4. A Windows shortcut file – “TXRTN_6442480.lnk”. As you may know, a Windows shortcut file can execute commands by putting them into the Target field. Figure 2.1 shows a screenshot of this shortcut file and its properties. 

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636371-f9842b2f-e2f4-427e-8ee8-192c042456ef.PNG">


Target: C:\Windows\System32\cmd.exe /q /c calc.exe

This "lnk" file tries to launch "cmd.exe /q /c calc.exe" and this calc.exe is present inside zip folder.

So basically lnk file will try to launch "calc.exe". And here if you see the ProcMon the calc.exe is doing DLL Side Loading of malicious "WindowsCodeCS.dll"

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636405-a8fffc07-d7a3-4e0d-b3a1-846e8e13ed38.PNG">

So lets check what this DLL is doing via DLL Side Loading

Import the DLL in Ghidra

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636441-849339af-9456-402d-b738-cdf350bc81bc.PNG">

Open Export, check for the Entry function.  We are seeing that local_24, local_20 has some hex values.

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636468-45d115b2-09d4-4f5e-8fad-3e01a4317632.PNG">

converting these hex to char, it will give you "102755.dll". This DLL was in your ZIP file...!!!!!!!

and
Here some more information about stored variables. 

If PE is x64: SysWow64

If not or x32: System32

DLL will be executed in above loaction using "regsvr32.exe"

<img width="491" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636527-12510ce3-e1a3-403b-94e7-4b23f150b6d0.PNG">

Now lets check the "WindowsCodeCS.dll" in x32Dbg.

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636785-b4d1cbec-f619-43bd-8ea1-738f963328d5.PNG">

Down we can see "CreateProcess" where process being launched. Put breakpoint over there

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636849-5793e3fe-d247-4dac-9a11-7746f0a280b7.PNG">

and do step over, keep going down we'll see "push edx" just above the "CreateProcess" it the location where the final payload "102755.dll" being launched.

<img width="691" alt="nrl5" src="https://user-images.githubusercontent.com/107531426/180636904-9ecbcdbc-b5eb-4364-9691-25a3318cbd16.PNG">


# Sample
https://bazaar.abuse.ch/sample/e8bb9a41e6beb9ebf1627c9c6f06682c782c0e63a357c337cc56a0c753c137ec/

# Reference
https://www.fortinet.com/blog/threat-research/new-variant-of-qakbot-spread-by-phishing-emails

