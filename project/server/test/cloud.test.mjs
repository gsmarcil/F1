import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { PROTOCOL, refreshExits } from '../src/service.mjs';
import { evaluateCloud } from '../src/cloud.mjs';
import { environment } from './d1.mjs';

const ADMIN = 'a'.repeat(40), KEY = 'e'.repeat(40), INGEST = 'i'.repeat(40), LISTED = '199.19.95.66';
function service(changes) {
  const env = environment({ INGEST_TOKEN: INGEST, TOR_EXITS: 'off', WATCHLIST: 'off', ...changes }), waiting = [], ctx = { waitUntil: promise => waiting.push(promise) };
  const call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
  return { env, call, settle: () => Promise.all(waiting.splice(0)) };
}
// Records in the shapes the vendors document.
const entra = (activityDisplayName, who = 'svc-backup@corp.example', changes = {}) => ({ activityDateTime: '2026-11-14T10:00:00Z', category: 'ApplicationManagement', result: 'success', activityDisplayName,
  initiatedBy: { user: { userPrincipalName: who, id: 'u-1', ipAddress: '203.0.113.20' } }, targetResources: [{ displayName: 'Backup Connector', type: 'ServicePrincipal', id: 'sp-1' }], ...changes });
const trail = (eventName, changes = {}) => ({ eventVersion: '1.11', eventTime: '2026-11-14T10:00:00Z', eventSource: 'ec2.amazonaws.com', eventName, awsRegion: 'us-east-1', sourceIPAddress: '203.0.113.20',
  userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::111122223333:user/deploy', userName: 'deploy', accountId: '111122223333' }, requestParameters: {}, responseElements: null, eventType: 'AwsApiCall', ...changes });
const arm = (operationName, changes = {}) => ({ time: '2026-11-14T10:00:00Z', operationName, caller: 'app-7@corp.example', callerIpAddress: '203.0.113.20', resourceId: '/subscriptions/s/resourceGroups/g/providers/x/' + Math.random(), status: { value: 'Succeeded' }, ...changes });
const signalsOf = (source, records) => Object.fromEntries(evaluateCloud(source, records).map(found => [found.actor, found.signals]));

test('Entra audit records: added credentials, grants and weakened policies, by the activity names Microsoft publishes', () => {
  const found = signalsOf('entra-audit', [
    entra('Add service principal credentials'), entra('Update application – Certificates and secrets management'), entra('Add owner to service principal'),
    entra('Add app role assignment to service principal'), entra('Delete Conditional Access policy'), entra('Add member to role'),
    entra('Add service principal credentials', 'other@corp.example', { result: 'failure' }), entra('Update user', 'helpdesk@corp.example'),
    { operationName: 'x', callerIpAddress: LISTED, properties: entra('Consent to application', 'app-admin@corp.example', { initiatedBy: { app: { displayName: 'Deploy Pipeline' } } }) }
  ]);
  assert.deepEqual(found['svc-backup@corp.example'], { cloud_credential_added: 2, cloud_privilege_grant: 3, cloud_policy_weakened: 1 });
  assert.deepEqual(found['Deploy Pipeline'], { cloud_privilege_grant: 1, cloud_advisory_indicator: 1 });
  assert.equal(found['other@corp.example'], undefined);    // a failed attempt changed nothing
  assert.equal(found['helpdesk@corp.example'], undefined); // ordinary directory work
});

test('CloudTrail records: permission mapping, staging, credentials for someone else, and listed addresses', () => {
  const dry = name => trail(name, { errorCode: 'Client.DryRunOperation', errorMessage: 'Request would have succeeded, but DryRun flag is set.' });
  const found = signalsOf('aws-cloudtrail', [
    dry('RunInstances'), dry('CreateVolume'), dry('CreateKeyPair'), dry('AllocateAddress'), dry('CreateSnapshot'), dry('RunInstances'),
    trail('CreateKeyPair'), trail('AllocateAddress'), trail('RunInstances', { requestParameters: { iamInstanceProfile: { name: 'admin-role' } } }), trail('CreateVolume', { requestParameters: { size: '100' } }),
    trail('CreateVolume', { requestParameters: { size: '8' } }), trail('RunInstances'),
    trail('CreateAccessKey', { eventSource: 'iam.amazonaws.com', requestParameters: { userName: 'finance-admin' } }),
    trail('AttachUserPolicy', { eventSource: 'iam.amazonaws.com', requestParameters: { userName: 'deploy', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' } }),
    trail('AttachUserPolicy', { eventSource: 'iam.amazonaws.com', requestParameters: { userName: 'deploy', policyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' } }),
    trail('CreateKeyPair', { errorCode: 'UnauthorizedOperation' }),
    trail('CreateAccessKey', { requestParameters: { userName: 'ci' }, userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::111122223333:user/ci', userName: 'ci' } }),
    trail('DescribeInstances', { sourceIPAddress: LISTED, userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::111122223333:assumed-role/partner/x' } })
  ]);
  assert.deepEqual(found['arn:aws:iam::111122223333:user/deploy'], { cloud_resource_staging: 4, cloud_credential_added: 1, cloud_privilege_grant: 1, cloud_permission_probe: 5 });
  assert.equal(found['arn:aws:iam::111122223333:user/ci'], undefined);  // rotating your own key is not a case
  assert.deepEqual(found['arn:aws:sts::111122223333:assumed-role/partner/x'], { cloud_advisory_indicator: 1 });
});

test('Azure activity records: validation dry-runs across resources, publishing credentials and storage keys', () => {
  const found = signalsOf('azure-activity', [
    ...Array.from({ length: 6 }, () => arm('Microsoft.Resources/deployments/validate/action')), arm('MICROSOFT.WEB/SITES/PUBLISHXML/ACTION'), arm({ value: 'Microsoft.Storage/storageAccounts/listKeys/action' }),
    arm('Microsoft.Resources/deployments/validate/action', { caller: 'pipeline@corp.example' }), arm('Microsoft.Storage/storageAccounts/listKeys/action', { caller: 'blocked@corp.example', status: { value: 'Failed' } })
  ]);
  assert.deepEqual(found['app-7@corp.example'], { cloud_secret_access: 2, cloud_permission_probe: 6 });
  assert.equal(found['pipeline@corp.example'], undefined);  // one validation is a deployment, not mapping
  assert.equal(found['blocked@corp.example'], undefined);
});

test('forwarded records become cases, need a token, and an operator can mark an identity as theirs', async () => {
  const s = service();
  const body = { source: 'entra-audit', records: [entra('Add service principal credentials'), entra('Add owner to service principal'), entra('Add app role assignment to service principal', 'intern@corp.example')] };
  assert.equal((await s.call('POST', '/v1/cloud-events', body)).status, 401);
  assert.equal((await s.call('POST', '/v1/cloud-events', { source: 'gcp', records: [] }, INGEST)).status, 400);
  assert.deepEqual((await s.call('POST', '/v1/cloud-events', body, INGEST)).body, { accepted: true, records: 3, saved: 1 });
  const found = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  assert.deepEqual({ title: found.title, level: found.level, severity: found.severity, device: found.device, platform: found.platform }, { title: 'Cloud: svc-backup@corp.example', level: 'SUSPECT', severity: 'high', device: 'Cloud audit (entra-audit)', platform: 'cloud' });
  const full = (await s.call('GET', '/v1/cases/' + found.id, null, ADMIN)).body;
  assert.deepEqual(full.detail.signals.map(signal => [signal.id, signal.points]), [['cloud_credential_added', 5], ['cloud_privilege_grant', 4]]);
  // The ingest token cannot read cases or decide them.
  assert.equal((await s.call('GET', '/v1/cases', null, INGEST)).status, 401);
  // Marked as ours: the same identity does not raise the case again; the operator token may also ingest.
  await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'trust' }, ADMIN);
  assert.equal((await s.call('POST', '/v1/cloud-events', body, ADMIN)).body.saved, 0);
  // A stopped/paused decision makes no sense for a cloud identity.
  assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'stop' }, ADMIN)).status, 409);
  assert.equal((await s.call('POST', '/v1/cloud-events', { source: 'aws-cloudtrail', records: [trail('DescribeInstances', { sourceIPAddress: LISTED })] }, INGEST)).body.saved, 1);
});

test('the Tor exit list is fetched by the service and sent to an agent only when it changed', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async url => { assert.equal(url, 'https://check.torproject.org/torbulkexitlist'); return new Response('185.220.101.4\n185.220.101.5\nnot an address\n185.220.101.4\n'); };
  try {
    const s = service({ TOR_EXITS: '' });
    const device = (await s.call('POST', '/v1/enroll', { protocol: PROTOCOL, key: KEY, platform: 'linux', version: '0.1.0', label: 'web-01' })).body;
    const cache = await refreshExits(s.env);
    assert.deepEqual(cache.addresses, ['185.220.101.4', '185.220.101.5']);
    const report = have => ({ protocol: PROTOCOL, version: '0.1.0', platform: 'linux', cases: [], watching: {}, exits_have: have });
    const first = (await s.call('POST', '/v1/report', report(''), device.token)).body;
    assert.deepEqual(first.exits, { revision: cache.revision, addresses: ['185.220.101.4', '185.220.101.5'] });
    assert.equal((await s.call('POST', '/v1/report', report(cache.revision), device.token)).body.exits, undefined);
    const inbound = { key: 'a'.repeat(32), name: 'sshd', path: '/usr/sbin/sshd', parent: '', signals: [{ id: 'remote_access_burst', points: 5, evidence: 'x' }, { id: 'inbound_tor_exit', points: 2, evidence: 'x' }], remotes: [] };
    assert.equal((await s.call('POST', '/v1/report', { ...report(cache.revision), cases: [inbound] }, device.token)).body.saved, 1);
    assert.equal((await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0].title, 'Connection attempts against sshd');
  } finally { globalThis.fetch = real; }
});
