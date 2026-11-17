import { ADVISORY } from './signals.mjs';

// Cloud control planes: what an intruder does in Microsoft Entra, Azure and AWS leaves nothing on a machine.
// It is all in the audit logs. You forward those records here (POST /v1/cloud-events) and these rules read
// them. Nothing here calls a cloud API or holds a cloud credential.
//
// The field and activity names are the ones the vendors publish:
//   Microsoft Entra audit log activity reference (activityDisplayName values, Core Directory and Conditional Access)
//   AWS CloudTrail record contents (eventName, errorCode, sourceIPAddress, userIdentity, requestParameters)
//   Azure activity log schema (operationName, caller, callerIpAddress)
// The rules have been run against records written from those references, not against a live tenant.
export const CLOUD_SOURCES = ['entra-audit', 'entra-signin', 'aws-cloudtrail', 'azure-activity'];
const ADVISORY_ADDRESSES = new Set(['38.244.50.120', '144.172.64.60', '144.172.64.99', '144.172.64.128', '187.15.88.186', '187.15.90.217', '187.15.89.186',
  '101.53.80.20', '205.214.59.31', '124.155.252.63', '154.201.79.246', '23.248.249.90', '23.158.220.98', '103.248.148.84', '203.160.133.172', '209.209.85.38',
  '199.19.95.66', '199.19.95.67', '199.19.95.68', '91.92.240.238', '85.11.168.45', '178.16.54.129', '31.77.229.35', '85.11.167.52']);
const clean = (value, max = 120) => typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f<>]/g, ' ').slice(0, max) : '';
// Entra writes the long dash in some exports and a hyphen in others.
const activity = value => clean(value, 200).replace(/[–—]/g, '-').replace(/\s+/g, ' ').trim().toLowerCase();
const ENTRA = {
  'add service principal credentials': 'cloud_credential_added',
  'update application - certificates and secrets management': 'cloud_credential_added',
  'add owner to application': 'cloud_privilege_grant',
  'add owner to service principal': 'cloud_privilege_grant',
  'add app role assignment to service principal': 'cloud_privilege_grant',
  'add delegated permission grant': 'cloud_privilege_grant',
  'consent to application': 'cloud_privilege_grant',
  'add member to role': 'cloud_privilege_grant',
  'add member to role outside of pim (permanent)': 'cloud_privilege_grant',
  'update conditional access policy': 'cloud_policy_weakened',
  'delete conditional access policy': 'cloud_policy_weakened',
  'set federation settings on domain': 'cloud_policy_weakened'
};
const AWS_STAGING = new Set(['CreateKeyPair', 'ImportKeyPair', 'AllocateAddress']);
const AWS_GRANTS = new Set(['AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'PutUserPolicy', 'PutRolePolicy']);
const AZURE = [
  [/^microsoft\.resources\/deployments\/validate\/action$/, 'probe'],
  [/^microsoft\.web\/sites\/(publishxml|config\/list)\/action$/, 'cloud_secret_access'],
  [/^microsoft\.storage\/storageaccounts\/listkeys\/action$/, 'cloud_secret_access'],
  [/^microsoft\.authorization\/roleassignments\/write$/, 'cloud_privilege_grant']
];

// One pass over a batch. Returns [{ actor, address, signals: { id: count }, probes }] per identity.
export function evaluateCloud(source, records) {
  const actors = new Map();
  const note = (actor, address, id) => {
    const key = clean(actor || 'unknown identity', 120);
    if (!actors.has(key)) actors.set(key, { actor: key, addresses: new Set(), signals: {}, probes: new Set(), secrets: new Set() });
    const entry = actors.get(key);
    if (address) entry.addresses.add(clean(address, 60));
    if (id) entry.signals[id] = (entry.signals[id] || 0) + 1;
    return entry;
  };
  for (const raw of records) {
    if (!raw || typeof raw !== 'object') continue;
    if (source === 'entra-audit') {
      const record = raw.properties && typeof raw.properties === 'object' ? { ...raw, ...raw.properties } : raw;
      if (String(record.result || 'success').toLowerCase() !== 'success') continue;
      const who = record.initiatedBy?.user?.userPrincipalName || record.initiatedBy?.app?.displayName || record.initiatedBy?.user?.id || record.initiatedBy?.app?.servicePrincipalId;
      const address = record.initiatedBy?.user?.ipAddress || raw.callerIpAddress || '';
      const entry = note(who, address, ENTRA[activity(record.activityDisplayName)] || null);
      if (ADVISORY_ADDRESSES.has(address)) entry.signals.cloud_advisory_indicator = (entry.signals.cloud_advisory_indicator || 0) + 1;
    } else if (source === 'entra-signin') {
      const record = raw.properties && typeof raw.properties === 'object' ? { ...raw, ...raw.properties } : raw;
      const address = record.ipAddress || raw.callerIpAddress || '';
      if (ADVISORY_ADDRESSES.has(address) && Number(record.status?.errorCode || 0) === 0)
        note(record.servicePrincipalName || record.appDisplayName || record.userPrincipalName || record.servicePrincipalId, address, 'cloud_advisory_indicator');
    } else if (source === 'aws-cloudtrail') {
      const identity = raw.userIdentity || {}, name = clean(raw.eventName, 80), address = clean(raw.sourceIPAddress, 60), params = raw.requestParameters || {};
      const who = identity.arn || identity.userName || identity.principalId;
      const entry = note(who, /^[0-9a-fA-F:.]+$/.test(address) ? address : '', null);
      if (ADVISORY_ADDRESSES.has(address)) entry.signals.cloud_advisory_indicator = (entry.signals.cloud_advisory_indicator || 0) + 1;
      if (/DryRunOperation/.test(String(raw.errorCode || ''))) { entry.probes.add(name); continue; }
      if (raw.errorCode) continue;
      if (name === 'CreateAccessKey' && params.userName && params.userName !== identity.userName) note(who, '', 'cloud_credential_added');
      else if (name === 'CreateLoginProfile' || name === 'UpdateLoginProfile') note(who, '', 'cloud_credential_added');
      else if (AWS_GRANTS.has(name) && (name.startsWith('Put') || /AdministratorAccess|IAMFullAccess|PowerUserAccess/.test(String(params.policyArn || '')))) note(who, '', 'cloud_privilege_grant');
      else if (AWS_STAGING.has(name)) note(who, '', 'cloud_resource_staging');
      else if (name === 'RunInstances' && params.iamInstanceProfile) note(who, '', 'cloud_resource_staging');
      else if (name === 'CreateVolume' && Number(params.size) >= 100) note(who, '', 'cloud_resource_staging');
      else if (name === 'GetSecretValue') entry.secrets.add(clean(String(params.secretId || ''), 200));
    } else if (source === 'azure-activity') {
      const record = raw.properties && typeof raw.properties === 'object' ? { ...raw.properties, ...raw } : raw;
      const operation = clean(typeof record.operationName === 'object' ? record.operationName?.value : record.operationName, 200).toLowerCase();
      const status = clean(typeof record.status === 'object' ? record.status?.value : record.status || record.resultType, 40).toLowerCase();
      if (status && !['succeeded', 'success', 'started', 'accepted', 'start'].includes(status)) continue;
      const address = clean(record.callerIpAddress, 60), entry = note(record.caller || record.identity?.claims?.appid, address, null);
      if (ADVISORY_ADDRESSES.has(address)) entry.signals.cloud_advisory_indicator = (entry.signals.cloud_advisory_indicator || 0) + 1;
      const rule = AZURE.find(([pattern]) => pattern.test(operation));
      if (rule?.[1] === 'probe') entry.probes.add(clean(record.resourceId || operation, 200));
      else if (rule) entry.signals[rule[1]] = (entry.signals[rule[1]] || 0) + 1;
    }
  }
  const found = [];
  for (const entry of actors.values()) {
    // Asking "would this be allowed?" for many different actions at once is permission mapping.
    if (entry.probes.size >= 5) entry.signals.cloud_permission_probe = entry.probes.size;
    if (entry.secrets.size >= 10) entry.signals.cloud_secret_access = (entry.signals.cloud_secret_access || 0) + entry.secrets.size;
    if (Object.keys(entry.signals).length) found.push({ actor: entry.actor, address: [...entry.addresses].find(address => /^[0-9a-fA-F:.]+$/.test(address)) || '', signals: entry.signals });
  }
  return found;
}
export const CLOUD_EVIDENCE = {
  cloud_credential_added: count => 'This identity added a sign-in credential to an application, service principal or another user ' + count + ' time(s).',
  cloud_privilege_grant: count => 'This identity granted ownership, roles, consent or an administrator policy ' + count + ' time(s).',
  cloud_policy_weakened: count => 'This identity changed or removed a Conditional Access policy or federation settings ' + count + ' time(s).',
  cloud_permission_probe: count => 'This identity asked whether ' + count + ' different actions would be allowed without doing them, the way permissions are mapped.',
  cloud_resource_staging: count => 'This identity created key pairs, public addresses, large volumes or role-bearing instances ' + count + ' time(s).',
  cloud_secret_access: count => 'This identity read keys, publishing credentials or secrets ' + count + ' time(s).',
  cloud_advisory_indicator: count => 'This identity acted from an address listed in ' + ADVISORY + ' (' + count + ' record(s)). The address may have been reassigned since; review before acting.'
};
