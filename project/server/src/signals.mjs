// Every signal the agent can send: its base weight, its category, and the sentence used in alerts.
// The weights are the same numbers the agent scores with (rust/src/score.rs). Alert text is always built here
// from the signal id; text written on a device is stored for the operator and never placed in an alert.
export const ADVISORY = 'FBI FLASH-20261113-001';
const S = (weight, category, phrase) => ({ weight, category, phrase });
export const SIGNALS = {
  unsigned_program: S(2, 'identity', 'has no valid publisher signature'),
  user_writable_path: S(1, 'identity', 'runs from a folder any program can write to'),
  runs_from_temp: S(3, 'identity', 'runs from a temporary folder and talks to the internet'),
  fresh_file: S(2, 'identity', 'ran minutes after its file appeared on the device'),
  system_name_elsewhere: S(3, 'identity', 'is named like a system program but runs from another folder'),
  advisory_tool_name: S(2, 'identity', 'is named like a tool reported in ' + ADVISORY),
  script_from_document: S(3, 'lineage', 'is a script started by a browser, document or mail program'),
  shell_from_web_server: S(3, 'lineage', 'is a shell started by a web server process'),
  risky_command_line: S(3, 'lineage', 'was started with a decode-and-run or download-and-run command'),
  script_from_shortcut: S(3, 'lineage', 'is a download-and-run command started from a shortcut or the Run box'),
  program_from_attachment: S(3, 'lineage', 'was started from a mail or archive program, the way an opened attachment runs'),
  remote_session_shell: S(3, 'lineage', 'was started inside a remote session from another machine'),
  helper_with_child: S(5, 'lineage', 'was started by a system helper that has no reason to start it'),
  privilege_jump: S(6, 'privilege', 'got the highest rights on the machine in a way nothing on it grants'),
  signin_key_added: S(5, 'behaviour', 'is a new SSH sign-in key added while nobody was signed in over SSH'),
  hidden_browser: S(5, 'behaviour', 'is a browser started where nobody can see it'),
  remote_control_tool: S(3, 'behaviour', 'is a remote-control tool running from outside the program folders'),
  address_lookup_host: S(1, 'destinations', 'asked an outside service for the public address of the machine'),
  boot_protection_off: S(6, 'hardware', 'had Secure Boot (or System Integrity Protection) switched off'),
  boot_entry_added: S(5, 'hardware', 'had the firmware\'s list of what to start changed'),
  firmware_downgraded: S(5, 'hardware', 'had an older firmware put back'),
  firmware_changed_unannounced: S(6, 'hardware', 'had its firmware code altered without an update'),
  kernel_module_loose: S(5, 'hardware', 'had a kernel module loaded that is not among the installed ones'),
  driver_checks_off: S(6, 'hardware', 'was restarted with driver signature checks off'),
  boot_code_changed: S(6, 'hardware', 'had the code it starts from changed without a boot loader update'),
  gateway_impersonated: S(6, 'network', 'is a machine on the network answering in place of the gateway'),
  port_scan: S(5, 'network', 'is a machine on the network that tried many ports here in one minute'),
  keyboard_injection: S(5, 'behaviour', 'is a command window opened seconds after a keyboard never seen before was plugged in'),
  system_tool_misuse: S(4, 'behaviour', 'is a Windows system tool being used the way malware loaders use one'),
  discovery_command: S(2, 'behaviour', 'ran a who-am-I command the way an intruder does on arrival'),
  threat_executed: S(3, 'behaviour', 'ran or is still active according to Windows Defender'),
  antivirus_detection: S(5, 'antivirus', 'was detected as a threat by Windows Defender'),
  tor_routing: S(3, 'destinations', 'is using Tor'),
  learned_attack_shape: S(2, 'learned', 'matches a combination your confirmed attacks share'),
  fleet_indicator: S(3, 'destinations', 'connected to an address another of your machines was attacked through'),
  metadata_access_from_web: S(2, 'behaviour', 'is a web server process that reached for the cloud metadata service'),
  advisory_indicator: S(5, 'destinations', 'connected to an address listed in ' + ADVISORY),
  drop_or_tunnel_host: S(2, 'destinations', 'connected to a paste, file-drop or tunnel host'),
  llm_api_host: S(1, 'destinations', 'calls an AI model API from outside the system folders'),
  unusual_port: S(1, 'destinations', 'connects out on an unusual port'),
  beaconing: S(3, 'pattern', 'contacts one address at a regular interval'),
  fan_out: S(2, 'pattern', 'contacted many different addresses in one minute'),
  agent_command_stream: S(3, 'agent', 'is one of a stream of different commands started at machine pace'),
  agent_retry_variation: S(2, 'agent', 'belongs to a run of near-copy retries, the way an automated operator works'),
  agent_parallel_duplicates: S(2, 'agent', 'was started more than once at the same moment, the way parallel sub-agents repeat each other'),
  web_fuzzing: S(3, 'web', 'asked the web server for dozens of pages that do not exist'),
  web_injection_attempt: S(3, 'web', 'sent injection-shaped requests to the web server'),
  web_injection_answered: S(2, 'web', 'had injection-shaped requests processed by the application'),
  web_enumeration: S(3, 'web', 'walked through record numbers on the web application'),
  web_login_burst: S(3, 'web', 'made a burst of sign-in attempts on the web application'),
  web_shell_request: S(3, 'web', 'called a server-side script the way a web shell is called'),
  web_error_burst: S(2, 'web', 'made the web application fail repeatedly with requests that carry a body'),
  web_shell_file: S(5, 'web', 'is a new server-side script that appeared in a web folder'),
  inbound_from_suspect_peer: S(4, 'inbound', 'accepted a connection from one of your own machines that has an open attack case'),
  inbound_tor_exit: S(2, 'inbound', 'accepted connections from Tor exit nodes'),
  cloud_credential_added: S(5, 'cloud', 'added a sign-in credential to an application, service principal or another user'),
  cloud_privilege_grant: S(4, 'cloud', 'granted ownership, roles, consent or an administrator policy'),
  cloud_policy_weakened: S(4, 'cloud', 'changed or removed a Conditional Access policy or federation settings'),
  cloud_permission_probe: S(3, 'cloud', 'mapped its own permissions with dry-run and validation calls'),
  cloud_resource_staging: S(3, 'cloud', 'created key pairs, public addresses, large volumes or role-bearing instances'),
  cloud_secret_access: S(3, 'cloud', 'read keys, publishing credentials or secrets'),
  cloud_advisory_indicator: S(5, 'cloud', 'acted from an address listed in ' + ADVISORY),
  inbound_advisory_indicator: S(5, 'inbound', 'accepted a connection from an address listed in ' + ADVISORY),
  remote_access_burst: S(5, 'inbound', 'received remote-access connections from many addresses in one minute'),
  credential_theft_tool: S(6, 'directory', 'is running a credential theft command'),
  directory_recon: S(2, 'directory', 'is listing the accounts and computers of the Windows domain'),
  kerberoast_pattern: S(5, 'directory', 'requested weakly encrypted Kerberos tickets for many services (Kerberoasting)'),
  dcsync_pattern: S(7, 'directory', 'asked a domain controller to replicate directory secrets (DCSync)'),
  logon_failure_burst: S(5, 'directory', 'had a burst of failed sign-ins'),
  audit_log_cleared: S(5, 'directory', 'cleared the Security event log'),
  privileged_group_change: S(5, 'directory', 'was added to a privileged group')
};
// Hosts whose current addresses the service looks up and hands to agents, so a connection to one is recognised
// on machines that keep no DNS cache. The lookups leave from the service, never from your machines.
export const WATCH_HOSTS = ['webhook.site', 'pastebin.com', 'paste.ee', 'rentry.co', 'transfer.sh', 'file.io', 'gofile.io', 'catbox.moe', '0x0.st', 'temp.sh',
  'api.telegram.org', 'api.anthropic.com', 'api.deepseek.com', 'open.bigmodel.cn', 'api.x.ai', 'xcai.pro'];
// Which signals this service knows, said to agents with the shared state: an agent newer than the service keeps
// back the signals a lower number does not cover. Raise it whenever a signal is added.
export const SIGNAL_SET = 5;
export const TRUST = new Set(['installed_program', 'owner_trusted', 'known_baseline']);
// Never learned up or down: published indicators, the antivirus's own verdict, attacks on a service, and
// directory attacks.
export const LOCKED = new Set(['learned_attack_shape', 'fleet_indicator', 'inbound_from_suspect_peer', 'cloud_credential_added', 'cloud_advisory_indicator', 'web_shell_file', 'advisory_indicator', 'inbound_advisory_indicator', 'antivirus_detection', 'threat_executed', 'remote_access_burst', 'credential_theft_tool', 'kerberoast_pattern', 'dcsync_pattern', 'logon_failure_burst', 'audit_log_cleared', 'privileged_group_change']);
// Attack shapes that must stay reported whatever an organisation's Sentinel learns.
export const REFERENCE_ATTACKS = [
  ['shell_from_web_server', 'risky_command_line'], ['shell_from_web_server', 'discovery_command'], ['shell_from_web_server', 'agent_command_stream'],
  ['script_from_document', 'risky_command_line'], ['script_from_shortcut', 'risky_command_line'],
  ['program_from_attachment', 'fresh_file'], ['program_from_attachment', 'unsigned_program'],
  ['system_tool_misuse', 'unusual_port'], ['runs_from_temp', 'unusual_port', 'beaconing'], ['runs_from_temp', 'fan_out'],
  ['runs_from_temp', 'advisory_tool_name'], ['unsigned_program', 'user_writable_path', 'beaconing'],
  ['remote_session_shell', 'directory_recon'], ['remote_session_shell', 'risky_command_line'],
  ['fleet_indicator', 'runs_from_temp'], ['fleet_indicator', 'unsigned_program'], ['inbound_from_suspect_peer', 'remote_session_shell'],
  ['cloud_credential_added'], ['cloud_advisory_indicator'], ['cloud_privilege_grant', 'cloud_permission_probe'], ['cloud_policy_weakened', 'cloud_privilege_grant'], ['cloud_resource_staging', 'cloud_permission_probe'],
  ['web_shell_file'], ['web_fuzzing', 'web_injection_attempt'], ['web_injection_attempt', 'web_injection_answered'], ['web_login_burst', 'web_enumeration'],
  ['advisory_indicator'], ['inbound_advisory_indicator'], ['remote_access_burst'], ['antivirus_detection'], ['credential_theft_tool'],
  ['kerberoast_pattern'], ['dcsync_pattern'], ['logon_failure_burst'], ['audit_log_cleared'], ['privileged_group_change'],
  ['helper_with_child'], ['privilege_jump']
];
export const levelFor = (score, categories) => score <= 2 ? 'CLEAR' : score <= 4 ? 'WATCH' : score <= 6 ? 'SUSPECT' : categories >= 3 ? 'HOSTILE' : 'SUSPECT';
export const reported = level => level === 'SUSPECT' || level === 'HOSTILE';
