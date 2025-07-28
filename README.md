# Oski---Threat-intel

Scenario: 

The accountant at the company received an email titled "Urgent New Order" from a client late in the afternoon. When he attempted to access the attached invoice, he discovered it contained false order information. Subsequently, the SIEM solution generated an alert regarding downloading a potentially malicious file. Upon initial investigation, it was found that the PPT file might be responsible for this download. Could you please conduct a detailed examination of this file?

When starting this activity, the only thing we have is this md5 hash 12c1842c3ccafe7408c23ebf292ee3d9

Let's check it on Virustotal 

<img width="1678" height="860" alt="Immagine 2025-07-28 094058" src="https://github.com/user-attachments/assets/1dce8e9f-51ae-42ed-a66b-7a4b6921e835" />

From VirusTotal we have obtained the following information:

- Creation Time 2022-09-28 17:40:46 UTC

- Threat categories trojan, ransomware

-  	http://171.22.28.221/5c06c05b7b34e8e6.php this is the first URL that the malware tries to contact with C2 control

Once infected the system,the first library that the malware requests post-infection is sqlite3.dll. 

ANY. RUN is a malware sandbox service in the cloud. By using this analyzer, we can submit a suspicious file or URL to the service and get a report.

From the report, we have a major picture about how the malware act inside the system. 

It use this RC4 5329514621441247975720749009 key to decrypt its base64-encoded string

Any.run full report gives also the MITRE technique used by the malware

<img width="1337" height="522" alt="B" src="https://github.com/user-attachments/assets/8d08574e-13d5-4b00-9958-8189d1e41be8" />

The VPN.exe file is used to acquire credentials from web browsers by reading files specific to the target browser. 

After the exfiltration of data, the malware delete all the dll files.

"C:\Windows\system32\cmd.exe" /c timeout /t 5 & del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe" & del "C:\ProgramData\*.dll"" & exit

This command launches the Windows command prompt to perform a sequence of actions: it waits for 5 seconds, then forcibly and quietly deletes a file named VPN.exe from the user's temporary folder, followed by deleting all .dll files located in C:\ProgramData\. Finally, it closes the command prompt. This behavior suggests potential malicious intent, as it removes files without confirmation, particularly DLLs in a system directory, which can disrupt software or hide traces of malware activity.

Summary:

Once installed on the target device, the malware performs anti-analysis checks to ensure it is not running in a sandbox or virtual environment. After loading Windows API functions and establishing a connection with the C2 server, it begins communication via POST requests, awaiting further configuration commands. The malware then starts collecting data from browsers, extensions, and applications by executing its grabber component to exfiltrate all files to the C2 server. Once the operation is complete, it automatically deletes itself from the device to avoid detection.

Mitigation:

Regularly ensure your security software is up to date.

Avoid downloading and installing software from unofficial third-party sources.

Never open links or attachments from unknown sources

Note: Activity on CyberDefenders, all rights reserved.


