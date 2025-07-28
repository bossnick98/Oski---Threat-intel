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

Ant.run full report gives also the MITRE technique used by the malware

<img width="1337" height="522" alt="B" src="https://github.com/user-attachments/assets/8d08574e-13d5-4b00-9958-8189d1e41be8" />






