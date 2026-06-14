'use client';

import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import { FormEvent, ReactNode, useEffect, useMemo, useState } from 'react';

type View = 'dashboard' | 'nodes' | 'clients' | 'profiles' | 'deployments' | 'tasks' | 'logs' | 'settings';

type JsonValue = Record<string, unknown> | unknown[] | string | number | boolean | null;

type ConsoleEvent = {
  id: number;
  label: string;
  status: 'ok' | 'error' | 'info';
  detail: string;
};

type DeploymentState = {
  deploymentId: string;
  artifactId: string;
  artifactSha: string;
  status?: string;
  health?: JsonValue;
  readiness?: JsonValue;
  snapshot?: JsonValue;
  rollbackPointer?: JsonValue;
  artifactPreview?: string;
};

type TopologyData = {
  kicker: string;
  title: string;
  status: string;
  detail: string;
  tone: 'ok' | 'warn' | 'info' | 'idle';
};

type TopologyNode = Node<TopologyData, 'proxyNode'>;

const defaultNodeId = 'node-a';
const defaultProfileId = 'profile-a';
const defaultClientId = 'client-a';
const defaultUuid = '2f4f6f8a-1111-4c4c-9999-111111111111';
const nodeTypes = { proxyNode: TopologyNodeCard };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/control-plane${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { 'content-type': 'application/json' } : {}),
      ...(init?.headers || {}),
    },
    cache: 'no-store',
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(text || `${response.status} ${response.statusText}`);
  }
  if (!text) return undefined as T;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return JSON.parse(text) as T;
  return text as T;
}

function pretty(value: unknown) {
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

function readString(value: unknown, key: string) {
  if (!value || typeof value !== 'object') return '';
  const record = value as Record<string, unknown>;
  return typeof record[key] === 'string' ? record[key] : '';
}

function decodeBase64(value: string) {
  try {
    return atob(value);
  } catch {
    return '';
  }
}

export function P0Console({ initialView = 'dashboard' }: { initialView?: View }) {
  const [view, setView] = useState<View>(initialView);
  const [nodeId, setNodeId] = useState(defaultNodeId);
  const [xrayVersion, setXrayVersion] = useState('26.3.27');
  const [profileId, setProfileId] = useState(defaultProfileId);
  const [serverName, setServerName] = useState('example.com');
  const [clientId, setClientId] = useState(defaultClientId);
  const [displayName, setDisplayName] = useState('Alice');
  const [uuid, setUuid] = useState(defaultUuid);
  const [quotaBytes, setQuotaBytes] = useState('1000000000');
  const [expiresAt, setExpiresAt] = useState('2026-12-31T00:00:00Z');
  const [deployment, setDeployment] = useState<DeploymentState | null>(null);
  const [health, setHealth] = useState<string>('checking');
  const [store, setStore] = useState<'empty' | 'ready' | 'deployed'>('empty');
  const [busy, setBusy] = useState<string | null>(null);
  const [events, setEvents] = useState<ConsoleEvent[]>([]);
  const [subscription, setSubscription] = useState('');
  const [subscriptionToken, setSubscriptionToken] = useState('');
  const [latestUsage, setLatestUsage] = useState<JsonValue | null>(null);
  const [latestHeartbeat, setLatestHeartbeat] = useState<JsonValue | null>(null);
  const [runnerCommandEnvelope, setRunnerCommandEnvelope] = useState<JsonValue | null>(null);
  const [runnerResultCount, setRunnerResultCount] = useState<JsonValue | null>(null);
  const [quotaDecision, setQuotaDecision] = useState<JsonValue | null>(null);
  const [expiryDecision, setExpiryDecision] = useState<JsonValue | null>(null);
  const [usageRollups, setUsageRollups] = useState<Record<string, JsonValue>>({});
  const [rolloutAction, setRolloutAction] = useState<JsonValue | null>(null);

  const runnerCommand = useMemo(
    () =>
      [
        'CONTROL_PLANE_BASE_URL=http://127.0.0.1:18080 \\',
        `RUNNER_NODE_ID=${nodeId} \\`,
        'RUNNER_API_TOKEN=dev-runner-token \\',
        'RUNNER_WORK_DIR=.data/runner \\',
        'RUNNER_XRAY_BIN=/root/xray-bin/xray \\',
        'RUNNER_ONCE=1 \\',
        './target/debug/runner',
      ].join('\n'),
    [nodeId],
  );

  const deploymentStatus = deployment?.status || 'none';
  const artifactShort = deployment?.artifactSha ? deployment.artifactSha.slice(0, 12) : 'none';

  useEffect(() => {
    let cancelled = false;

    async function probe() {
      try {
        const result = await api<string>('/healthz');
        if (!cancelled) setHealth(result);
      } catch {
        if (!cancelled) setHealth('offline');
      }
    }

    void probe();
    const timer = window.setInterval(probe, 10000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  function push(label: string, status: ConsoleEvent['status'], detail: unknown) {
    setEvents((current) => [
      {
        id: Date.now() + Math.random(),
        label,
        status,
        detail: pretty(detail),
      },
      ...current.slice(0, 13),
    ]);
  }

  async function run<T>(label: string, action: () => Promise<T>): Promise<T> {
    setBusy(label);
    try {
      const result = await action();
      push(label, 'ok', result ?? 'ok');
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      push(label, 'error', message);
      throw error;
    } finally {
      setBusy(null);
    }
  }

  async function checkHealth() {
    setHealth('checking');
    try {
      await run('Control-plane health', async () => {
        const result = await api<string>('/healthz');
        setHealth(result);
        return result;
      });
    } catch (error) {
      setHealth('offline');
      throw error;
    }
  }

  async function registerNode(event?: FormEvent) {
    event?.preventDefault();
    const result = await run('Register node', () =>
      api<JsonValue>('/nodes/register', {
        method: 'POST',
        body: JSON.stringify({
          registration_token: 'dev-registration-token',
          node_id: nodeId,
          xray_version: xrayVersion,
        }),
      }),
    );
    setStore('ready');
    return result;
  }

  async function createProfile(event?: FormEvent) {
    event?.preventDefault();
    return run('Create VLESS REALITY profile', () =>
      api<JsonValue>('/profiles/vless-reality', {
        method: 'POST',
        body: JSON.stringify({ profile_id: profileId, server_name: serverName }),
      }),
    );
  }

  async function createClient(event?: FormEvent) {
    event?.preventDefault();
    return run('Create client credential', () =>
      api<JsonValue>('/clients', {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          profile_id: profileId,
          display_name: displayName,
          uuid,
          quota_bytes: Number(quotaBytes),
          expires_at: expiresAt,
        }),
      }),
    );
  }

  async function compileDeployment(event?: FormEvent) {
    event?.preventDefault();
    const result = await run('Compile deployment', () =>
      api<Record<string, unknown>>('/deployments/compile', {
        method: 'POST',
        headers: { 'idempotency-key': `compile-${profileId}-${nodeId}-${Date.now()}` },
        body: JSON.stringify({ profile_id: profileId, node_id: nodeId }),
      }),
    );
    const artifact = result.artifact as Record<string, unknown>;
    const plan = result.deployment_plan as Record<string, unknown>;
    const artifactId = readString(artifact, 'id');
    const artifactSha = readString(artifact, 'sha256');
    setDeployment({
      deploymentId: `dep-${artifactSha.slice(0, 12)}`,
      artifactId,
      artifactSha,
      status: 'compiled',
    });
    setStore('ready');
    push('DeploymentPlan', 'info', plan);
    return result;
  }

  async function refreshDeployment() {
    if (!deployment) return;
    const [status, healthResult, readiness, snapshot, rollbackPointer, artifactText] = await run(
      'Refresh deployment evidence',
      async () =>
        Promise.all([
          api<JsonValue>(`/deployments/${deployment.deploymentId}`),
          api<JsonValue>(`/deployments/${deployment.deploymentId}/health`).catch((error) => ({
            error: error instanceof Error ? error.message : String(error),
          })),
          api<JsonValue>(`/deployments/${deployment.deploymentId}/readiness`).catch((error) => ({
            error: error instanceof Error ? error.message : String(error),
          })),
          api<JsonValue>(`/deployments/${deployment.deploymentId}/snapshot`).catch((error) => ({
            error: error instanceof Error ? error.message : String(error),
          })),
          api<JsonValue>(`/deployments/${deployment.deploymentId}/rollback-pointer`).catch((error) => ({
            error: error instanceof Error ? error.message : String(error),
          })),
          api<string>(`/artifacts/${deployment.artifactId}/bytes`).catch((error) =>
            error instanceof Error ? error.message : String(error),
          ),
        ]),
    );
    const statusText = readString(status, 'status') || deployment.status;
    setDeployment({
      ...deployment,
      status: statusText,
      health: healthResult,
      readiness,
      snapshot,
      rollbackPointer,
      artifactPreview: typeof artifactText === 'string' ? artifactText : pretty(artifactText),
    });
    if (statusText === 'Succeeded') setStore('deployed');
  }

  async function sendHeartbeat() {
    const result = await run('Send runner heartbeat', () =>
      api<JsonValue>(`/runner/nodes/${nodeId}/heartbeat`, {
        method: 'POST',
        headers: { 'x-runner-token': 'dev-runner-token' },
        body: JSON.stringify({
          capability_snapshot: {
            core: 'xray',
            core_version: xrayVersion,
            node_id: nodeId,
            protocols: ['vless-reality'],
            work_dir: '.data/runner',
          },
        }),
      }),
    );
    return result;
  }

  async function fetchHeartbeat() {
    const result = await run('Fetch runner heartbeat', () => api<JsonValue>(`/nodes/${nodeId}/heartbeat`));
    setLatestHeartbeat(result);
    return result;
  }

  async function fetchRunnerCommand() {
    const result = await run('Fetch next runner command', async () => {
      const command = await api<JsonValue | undefined>(`/runner/nodes/${nodeId}/commands/next?last_sequence=0`, {
        headers: { 'x-runner-token': 'dev-runner-token' },
      });
      return command || { status: 'no queued command' };
    });
    setRunnerCommandEnvelope(result);
    return result;
  }

  async function fetchRunnerResultCount() {
    const result = await run('Fetch runner result count', () => api<JsonValue>('/runner/results/count'));
    setRunnerResultCount(result);
    return result;
  }

  async function recordDeploymentHealth(status: 'healthy' | 'unhealthy') {
    if (!deployment) return;
    await run(`Record ${status} deployment health`, () =>
      api<JsonValue | undefined>(`/runner/nodes/${nodeId}/deployments/${deployment.deploymentId}/health`, {
        method: 'POST',
        headers: { 'x-runner-token': 'dev-runner-token' },
        body: JSON.stringify({
          status,
          payload_json: {
            source: 'web-console',
            profile_id: profileId,
            artifact_sha: deployment.artifactSha,
          },
        }),
      }),
    );
    await refreshDeployment();
  }

  async function advanceDeployment() {
    if (!deployment) return;
    const result = await run('Advance deployment rollout', () =>
      api<JsonValue>(`/deployments/${deployment.deploymentId}/advance`, { method: 'POST' }),
    );
    setRolloutAction(result);
    return result;
  }

  async function rollbackDeployment() {
    if (!deployment) return;
    const result = await run('Queue deployment rollback', () =>
      api<JsonValue>(`/deployments/${deployment.deploymentId}/rollback`, { method: 'POST' }),
    );
    setRolloutAction(result);
    return result;
  }

  async function fetchSubscription() {
    const result = await run('Fetch subscription', () =>
      api<{ body_base64: string }>(
        `/subscriptions/${profileId}${subscriptionToken ? `?token=${encodeURIComponent(subscriptionToken)}` : ''}`,
      ),
    );
    setSubscription(decodeBase64(result.body_base64));
  }

  async function issueToken() {
    const result = await run('Issue subscription token', () =>
      api<Record<string, unknown>>(`/subscriptions/${profileId}/tokens`, { method: 'POST' }),
    );
    const token = readString(result, 'token');
    if (token) setSubscriptionToken(token);
  }

  async function recordUsage() {
    const result = await run('Record usage sample', () =>
      api<JsonValue>(`/runner/nodes/${nodeId}/usage`, {
        method: 'POST',
        headers: { 'x-runner-token': 'dev-runner-token' },
        body: JSON.stringify({
          credential_id: clientId,
          uplink_bytes: 1234,
          downlink_bytes: 5678,
        }),
      }),
    );
    return result;
  }

  async function fetchUsage() {
    const result = await run('Fetch latest node usage', () => api<JsonValue>(`/usage/nodes/${nodeId}/latest`));
    setLatestUsage(result);
  }

  async function fetchClientGuards() {
    const [quota, expiry, hour, day, month] = await run('Fetch client guardrails', async () =>
      Promise.all([
        api<JsonValue>(`/clients/${clientId}/quota`).catch((error) => ({
          error: error instanceof Error ? error.message : String(error),
        })),
        api<JsonValue>(`/clients/${clientId}/expiry`).catch((error) => ({
          error: error instanceof Error ? error.message : String(error),
        })),
        api<JsonValue>(`/usage/credentials/${clientId}/rollups/latest?bucket=hour`).catch((error) => ({
          error: error instanceof Error ? error.message : String(error),
        })),
        api<JsonValue>(`/usage/credentials/${clientId}/rollups/latest?bucket=day`).catch((error) => ({
          error: error instanceof Error ? error.message : String(error),
        })),
        api<JsonValue>(`/usage/credentials/${clientId}/rollups/latest?bucket=month`).catch((error) => ({
          error: error instanceof Error ? error.message : String(error),
        })),
      ]),
    );
    setQuotaDecision(quota);
    setExpiryDecision(expiry);
    setUsageRollups({ hour, day, month });
  }

  async function bootstrap() {
    await checkHealth();
    try {
      await registerNode();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes('registration token already consumed')) {
        throw error;
      }
      setStore('ready');
      push('Use existing node registration', 'info', message);
      await fetchHeartbeat().catch(() => undefined);
    }
    await createProfile();
    await createClient();
    await compileDeployment();
    await sendHeartbeat();
    await fetchRunnerCommand();
    setView('deployments');
  }

  return (
    <div className="workbench-shell">
      <header className="workbench-header">
        <div className="title-group">
          <p className="eyebrow">P0 operator workbench</p>
        </div>
        <div className="header-actions">
          <StatusPill label="API" value={health} tone={health === 'ok' ? 'ok' : 'warn'} />
          <StatusPill label="Store" value={store} tone={store === 'deployed' ? 'ok' : store === 'ready' ? 'info' : 'warn'} />
          <StatusPill label="Deploy" value={deploymentStatus} tone={deploymentStatus === 'Succeeded' ? 'ok' : 'idle'} />
          <StatusProbe value={health} onClick={checkHealth} />
        </div>
      </header>

      {view === 'dashboard' ? (
        <section className="dashboard-workspace">
          <section className="metric-strip" aria-label="P0 runtime summary">
            <MetricCard label="Control-plane" value={health === 'ok' ? 'Online' : 'Unchecked'} detail="Rust Axum API via same-origin proxy" />
            <MetricCard label="Target core" value="Xray 26.3.27" detail="/root/xray-bin/xray" />
            <MetricCard label="Artifact" value={artifactShort} detail="content addressed deployment output" />
            <MetricCard label="Client" value={clientId} detail={`${profileId} / ${serverName}`} />
          </section>

          <section className="dashboard-main">
            <div className="dashboard-left-stack">
              <section className="canvas-panel">
                <PanelHeader eyebrow="Topology" title="Deployment path" action={<button onClick={checkHealth} type="button">Check API</button>} />
                <TopologyCanvas
                  artifactSha={artifactShort}
                  deploymentStatus={deploymentStatus}
                  health={health}
                  nodeId={nodeId}
                  profileId={profileId}
                  storeState={store}
                />
              </section>

              <section className="artifact-panel">
                <PanelHeader eyebrow="Artifact" title={deployment?.deploymentId || 'No deployment compiled'} />
                <div className="artifact-split">
                  <JsonBlock title="Status" value={deployment ? { status: deployment.status, artifact: deployment.artifactId } : { status: 'empty' }} />
                  <JsonBlock title="Latest usage" value={latestUsage || { status: 'no usage sample loaded' }} />
                  <JsonBlock title="Runner command" value={runnerCommandEnvelope || { status: 'not fetched' }} />
                  <JsonBlock title="Rollout action" value={rolloutAction || { status: 'no rollout action' }} />
                </div>
              </section>
            </div>

            <aside className="operator-panel">
              <PanelHeader
                eyebrow="Operator"
                title="Run P0 flow"
                action={
                  <button className="primary" disabled={Boolean(busy)} onClick={bootstrap} type="button">
                    {busy || 'Run browser bootstrap'}
                  </button>
                }
              />
              <RunbookSteps
                artifactShort={artifactShort}
                clientId={clientId}
                deploymentStatus={deploymentStatus}
                health={health}
                nodeId={nodeId}
                profileId={profileId}
                store={store}
              />
              <div className="operator-command">
                <span>runner once</span>
                <pre>{runnerCommand}</pre>
              </div>
            </aside>
          </section>
        </section>
      ) : null}

      {view === 'nodes' ? (
        <section className="detail-workspace">
          <FormPanel title="Runner node" eyebrow="Node registration" onSubmit={registerNode} busy={busy}>
            <Field label="Node ID" value={nodeId} onChange={setNodeId} />
            <Field label="Xray version" value={xrayVersion} onChange={setXrayVersion} />
          </FormPanel>
          <section className="data-panel span-2">
            <PanelHeader
              eyebrow="Runner evidence"
              title="Heartbeat and command queue"
              action={
                <div className="button-row compact-row">
                  <button onClick={sendHeartbeat} type="button">Send heartbeat</button>
                  <button onClick={fetchHeartbeat} type="button">Read heartbeat</button>
                  <button onClick={fetchRunnerCommand} type="button">Next command</button>
                </div>
              }
            />
            <ResourceTable
              rows={[
                ['Node ID', nodeId, store === 'empty' ? 'unregistered in browser state' : 'registered'],
                ['Core', `xray ${xrayVersion}`, 'P0 runner target'],
                ['Command source', `/runner/nodes/${nodeId}/commands/next`, runnerCommandEnvelope ? 'loaded' : 'not fetched'],
              ]}
            />
            <div className="artifact-split offset-top">
              <JsonBlock title="Latest heartbeat" value={latestHeartbeat || { status: 'not loaded' }} />
              <JsonBlock title="Next command envelope" value={runnerCommandEnvelope || { status: 'not loaded' }} />
            </div>
          </section>
          <section className="data-panel span-3">
            <PanelHeader eyebrow="Runner command" title="Apply queued deployment" />
            <p className="muted">Run this on the remote machine after compile. The browser controls the API; it does not spawn server processes.</p>
            <pre className="codeblock">{runnerCommand}</pre>
          </section>
        </section>
      ) : null}

      {view === 'profiles' ? (
        <section className="detail-workspace">
          <FormPanel title="VLESS REALITY profile" eyebrow="Profile IR" onSubmit={createProfile} busy={busy}>
            <Field label="Profile ID" value={profileId} onChange={setProfileId} />
            <Field label="Server name / SNI" value={serverName} onChange={setServerName} />
          </FormPanel>
          <section className="data-panel span-2">
            <PanelHeader eyebrow="Compiler target" title="Xray adapter first" />
            <ResourceTable
              rows={[
                ['Protocol', 'VLESS + REALITY', 'P0 supported'],
                ['Core', 'xray-core', 'verified locally'],
                ['Later adapter', 'sing-box', 'kept behind compiler boundary'],
              ]}
            />
          </section>
        </section>
      ) : null}

      {view === 'clients' ? (
        <section className="detail-workspace">
          <FormPanel title="Client credential" eyebrow="VLESS UUID" onSubmit={createClient} busy={busy}>
            <Field label="Client ID" value={clientId} onChange={setClientId} />
            <Field label="Profile ID" value={profileId} onChange={setProfileId} />
            <Field label="Display name" value={displayName} onChange={setDisplayName} />
            <Field label="UUID" value={uuid} onChange={setUuid} />
            <Field label="Quota bytes" value={quotaBytes} onChange={setQuotaBytes} />
            <Field label="Expires at" value={expiresAt} onChange={setExpiresAt} />
          </FormPanel>
          <section className="data-panel span-2">
            <PanelHeader
              eyebrow="Usage"
              title="Quota evidence"
              action={
                <div className="button-row compact-row">
                  <button onClick={recordUsage} type="button">Record sample</button>
                  <button onClick={fetchUsage} type="button">Read latest</button>
                  <button onClick={fetchClientGuards} type="button">Read guardrails</button>
                </div>
              }
            />
            <ResourceTable
              rows={[
                ['Client ID', clientId, 'credential'],
                ['Quota bytes', quotaBytes, quotaDecision ? 'decision loaded' : 'not loaded'],
                ['Expires at', expiresAt, expiryDecision ? 'decision loaded' : 'not loaded'],
              ]}
            />
            <div className="artifact-split offset-top">
              <JsonBlock title="Latest usage" value={latestUsage || { status: 'no usage sample loaded' }} />
              <JsonBlock title="Quota decision" value={quotaDecision || { status: 'not loaded' }} />
              <JsonBlock title="Expiry decision" value={expiryDecision || { status: 'not loaded' }} />
              <JsonBlock title="Usage rollups" value={Object.keys(usageRollups).length ? usageRollups : { status: 'not loaded' }} />
            </div>
          </section>
        </section>
      ) : null}

      {view === 'deployments' ? (
        <section className="detail-workspace">
          <FormPanel title="Compile deployment" eyebrow="DeploymentPlan" onSubmit={compileDeployment} busy={busy}>
            <Field label="Profile ID" value={profileId} onChange={setProfileId} />
            <Field label="Node ID" value={nodeId} onChange={setNodeId} />
          </FormPanel>
          <section className="artifact-panel span-2">
            <PanelHeader
              eyebrow="Evidence"
              title={deployment?.deploymentId || 'No deployment compiled'}
              action={
                <div className="button-row compact-row">
                  <button disabled={!deployment || Boolean(busy)} onClick={refreshDeployment} type="button">Refresh evidence</button>
                  <button disabled={!deployment || Boolean(busy)} onClick={() => recordDeploymentHealth('healthy')} type="button">Healthy sample</button>
                  <button disabled={!deployment || Boolean(busy)} onClick={() => recordDeploymentHealth('unhealthy')} type="button">Unhealthy sample</button>
                  <button disabled={!deployment || Boolean(busy)} onClick={advanceDeployment} type="button">Advance</button>
                  <button disabled={!deployment || Boolean(busy)} onClick={rollbackDeployment} type="button">Rollback</button>
                </div>
              }
            />
            <ResourceTable
              rows={[
                ['Deployment ID', deployment?.deploymentId || 'none', deploymentStatus],
                ['Artifact SHA', artifactShort, deployment?.artifactId || 'none'],
                ['Rollout action', readString(rolloutAction, 'action') || 'none', rolloutAction ? 'loaded' : 'not loaded'],
              ]}
            />
            <div className="artifact-split">
              <JsonBlock title="Status" value={deployment ? { status: deployment.status, artifact: deployment.artifactId } : { status: 'empty' }} />
              <JsonBlock title="Health" value={deployment?.health || { status: 'not loaded' }} />
              <JsonBlock title="Readiness" value={deployment?.readiness || { status: 'not loaded' }} />
              <JsonBlock title="Rollback pointer" value={deployment?.rollbackPointer || { status: 'not loaded' }} />
              <JsonBlock title="Rollout action" value={rolloutAction || { status: 'not loaded' }} />
              <JsonBlock title="Runner result count" value={runnerResultCount || { status: 'not loaded' }} />
            </div>
            {deployment?.artifactPreview ? <pre className="artifact-preview">{deployment.artifactPreview}</pre> : null}
          </section>
        </section>
      ) : null}

      {view === 'tasks' ? (
        <section className="detail-workspace">
          <section className="data-panel span-3">
            <PanelHeader
              eyebrow="Task lane"
              title="Runner queue and browser journal"
              action={
                <div className="button-row compact-row">
                  <button onClick={fetchRunnerCommand} type="button">Next command</button>
                  <button onClick={fetchRunnerResultCount} type="button">Result count</button>
                </div>
              }
            />
            <div className="artifact-split">
              <JsonBlock title="Next runner command" value={runnerCommandEnvelope || { status: 'not loaded' }} />
              <JsonBlock title="Runner result count" value={runnerResultCount || { status: 'not loaded' }} />
            </div>
            <EventList events={events} />
          </section>
        </section>
      ) : null}

      {view === 'logs' ? (
        <section className="detail-workspace">
          <section className="artifact-panel span-3">
            <PanelHeader
              eyebrow="Artifacts"
              title="Deployment evidence"
              action={
                <div className="button-row compact-row">
                  <button disabled={!deployment || Boolean(busy)} onClick={refreshDeployment} type="button">Refresh evidence</button>
                  <button disabled={!deployment || Boolean(busy)} onClick={advanceDeployment} type="button">Advance rollout</button>
                </div>
              }
            />
            <div className="artifact-split">
              <JsonBlock title="Snapshot" value={deployment?.snapshot || { status: 'not loaded' }} />
              <JsonBlock title="Last event" value={events[0] || { status: 'no events yet' }} />
              <JsonBlock title="Rollout action" value={rolloutAction || { status: 'not loaded' }} />
              <JsonBlock title="Artifact preview" value={deployment?.artifactPreview || { status: 'not loaded' }} />
            </div>
          </section>
        </section>
      ) : null}

      {view === 'settings' ? (
        <section className="detail-workspace">
          <section className="data-panel">
            <PanelHeader
              eyebrow="Subscription"
              title="Token and output"
              action={
                <div className="button-row compact-row">
                  <button type="button" onClick={issueToken}>Issue token</button>
                  <button type="button" onClick={fetchSubscription}>Fetch subscription</button>
                </div>
              }
            />
            <Field label="Subscription token" value={subscriptionToken} onChange={setSubscriptionToken} />
            <pre className="codeblock">{subscription || 'No subscription loaded'}</pre>
          </section>
          <section className="data-panel span-2">
            <PanelHeader eyebrow="Runtime" title="Remote dev binding" />
            <ResourceTable
              rows={[
                ['Web', '0.0.0.0:3000', 'dev only'],
                ['Control-plane', '0.0.0.0:18080', 'dev only'],
                ['Xray', '/root/xray-bin/xray', 'local core'],
              ]}
            />
          </section>
        </section>
      ) : null}

      <aside className="activity-dock">
        <PanelHeader eyebrow="Activity" title="Recent API calls" action={<button onClick={checkHealth} type="button">Ping</button>} />
        <EventList events={events} />
      </aside>
    </div>
  );
}

function TopologyCanvas({
  artifactSha,
  deploymentStatus,
  health,
  nodeId,
  profileId,
  storeState,
}: {
  artifactSha: string;
  deploymentStatus: string;
  health: string;
  nodeId: string;
  profileId: string;
  storeState: string;
}) {
  const baseNodes = useMemo<TopologyNode[]>(
    () => [
      {
        id: 'web',
        type: 'proxyNode',
        position: { x: 20, y: 170 },
        sourcePosition: Position.Right,
        data: { kicker: 'Console', title: 'Next.js Web', status: 'Browser actions', detail: 'same-origin API proxy', tone: 'info' },
      },
      {
        id: 'api',
        type: 'proxyNode',
        position: { x: 230, y: 170 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { kicker: 'Control', title: 'Rust API', status: health, detail: 'Axum control-plane', tone: health === 'ok' ? 'ok' : 'warn' },
      },
      {
        id: 'ir',
        type: 'proxyNode',
        position: { x: 440, y: 60 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { kicker: 'Profile IR', title: profileId, status: 'VLESS REALITY', detail: 'validated declarative input', tone: 'info' },
      },
      {
        id: 'store',
        type: 'proxyNode',
        position: { x: 230, y: 310 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { kicker: 'State', title: 'Store', status: storeState, detail: 'memory now, Postgres later', tone: storeState === 'deployed' ? 'ok' : 'idle' },
      },
      {
        id: 'compiler',
        type: 'proxyNode',
        position: { x: 440, y: 170 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { kicker: 'Adapter', title: 'compiler-xray', status: artifactSha, detail: 'IR to xray JSON artifact', tone: artifactSha === 'none' ? 'idle' : 'ok' },
      },
      {
        id: 'runner',
        type: 'proxyNode',
        position: { x: 650, y: 170 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { kicker: 'Runner', title: nodeId, status: deploymentStatus, detail: 'test, switch, health evidence', tone: deploymentStatus === 'Succeeded' ? 'ok' : 'warn' },
      },
      {
        id: 'xray',
        type: 'proxyNode',
        position: { x: 860, y: 170 },
        targetPosition: Position.Left,
        data: { kicker: 'Runtime', title: 'xray-core', status: '26.3.27', detail: 'REALITY inbound on VPS', tone: 'ok' },
      },
    ],
    [artifactSha, deploymentStatus, health, nodeId, profileId, storeState],
  );

  const baseEdges = useMemo<Edge[]>(
    () => [
      edge('web-api', 'web', 'api'),
      edge('api-ir', 'api', 'ir'),
      edge('api-store', 'api', 'store', 'down'),
      edge('ir-compiler', 'ir', 'compiler', 'down'),
      edge('store-compiler', 'store', 'compiler'),
      edge('compiler-runner', 'compiler', 'runner'),
      edge('runner-xray', 'runner', 'xray'),
    ],
    [],
  );
  const [nodes, setNodes, onNodesChange] = useNodesState<TopologyNode>(baseNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(baseEdges);

  useEffect(() => {
    setNodes((current) => {
      const currentById = new Map(current.map((node) => [node.id, node]));
      const savedPositions = readSavedTopologyPositions();
      return baseNodes.map((node) => {
        const existing = currentById.get(node.id);
        return {
          ...node,
          position: existing?.position || savedPositions[node.id] || node.position,
        };
      });
    });
  }, [baseNodes, setNodes]);

  useEffect(() => {
    setEdges(baseEdges);
  }, [baseEdges, setEdges]);

  function saveCurrentPositions(changedNode: TopologyNode) {
    const positions = Object.fromEntries(
      nodes.map((node) => [
        node.id,
        node.id === changedNode.id ? changedNode.position : node.position,
      ]),
    );
    window.localStorage.setItem('proxy-control-topology-positions', JSON.stringify(positions));
  }

  return (
    <div className="topology-canvas" aria-label="proxy control topology canvas">
      <ReactFlow
        colorMode="light"
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.1 }}
        maxZoom={1.15}
        minZoom={0.72}
        nodes={nodes}
        nodesDraggable
        nodeTypes={nodeTypes}
        onEdgesChange={onEdgesChange}
        onNodeDragStop={(_, node) => saveCurrentPositions(node as TopologyNode)}
        onNodesChange={onNodesChange}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#d8d8d8" gap={28} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function edge(id: string, source: string, target: string, path: 'straight' | 'down' = 'straight'): Edge {
  return {
    id,
    source,
    target,
    sourceHandle: path === 'down' ? 'bottom-source' : 'right-source',
    targetHandle: path === 'down' ? 'top-target' : 'left-target',
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    type: 'straight',
  };
}

function readSavedTopologyPositions(): Record<string, { x: number; y: number }> {
  try {
    const raw = window.localStorage.getItem('proxy-control-topology-positions');
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, { x: number; y: number }>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function TopologyNodeCard({ data }: NodeProps<TopologyNode>) {
  return (
    <div className={`topology-node ${data.tone}`}>
      <Handle className="topology-handle" id="left-target" type="target" position={Position.Left} />
      <Handle className="topology-handle" id="top-target" type="target" position={Position.Top} />
      <span>{data.kicker}</span>
      <strong>{data.title}</strong>
      <em>{data.status}</em>
      <p>{data.detail}</p>
      <Handle className="topology-handle" id="bottom-target" type="target" position={Position.Bottom} />
      <Handle className="topology-handle" id="top-source" type="source" position={Position.Top} />
      <Handle className="topology-handle" id="right-source" type="source" position={Position.Right} />
      <Handle className="topology-handle" id="bottom-source" type="source" position={Position.Bottom} />
    </div>
  );
}

function RunbookSteps({
  artifactShort,
  clientId,
  deploymentStatus,
  health,
  nodeId,
  profileId,
  store,
}: {
  artifactShort: string;
  clientId: string;
  deploymentStatus: string;
  health: string;
  nodeId: string;
  profileId: string;
  store: string;
}) {
  const steps = [
    ['01', 'Health', health === 'ok' ? 'API reachable' : 'Not checked'],
    ['02', 'Register', store === 'empty' ? 'Node pending' : nodeId],
    ['03', 'Profile', profileId],
    ['04', 'Credential', clientId],
    ['05', 'Compile', artifactShort],
    ['06', 'Runner', deploymentStatus === 'Succeeded' ? 'Applied' : 'Manual once-run'],
  ];
  return (
    <div className="runbook-steps">
      {steps.map(([index, label, value]) => (
        <div className="runbook-step" key={label}>
          <span>{index}</span>
          <strong>{label}</strong>
          <em>{value}</em>
        </div>
      ))}
    </div>
  );
}

function PanelHeader({ eyebrow, title, action }: { eyebrow: string; title: string; action?: ReactNode }) {
  return (
    <div className="panel-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h3>{title}</h3>
      </div>
      {action ? <div>{action}</div> : null}
    </div>
  );
}

function StatusPill({ label, value, tone }: { label: string; value: string; tone: 'ok' | 'warn' | 'info' | 'idle' }) {
  return (
    <div className={`status-pill ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatusProbe({ value, onClick }: { value: string; onClick: () => void }) {
  const tone = value === 'ok' ? 'ok' : value === 'checking' ? 'checking' : 'error';
  const label = value === 'ok' ? 'Live' : value === 'checking' ? 'Connecting' : 'Failed';
  return (
    <button className={`status-probe ${tone}`} onClick={onClick} title="Refresh API health" type="button">
      <span aria-hidden="true" />
      <strong>{label}</strong>
    </button>
  );
}

function MetricCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <section className="metric-card">
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{detail}</span>
    </section>
  );
}

function FormPanel({
  title,
  eyebrow,
  children,
  onSubmit,
  busy,
}: {
  title: string;
  eyebrow: string;
  children: ReactNode;
  onSubmit: (event: FormEvent) => void;
  busy: string | null;
}) {
  return (
    <form className="data-panel form-panel" onSubmit={onSubmit}>
      <PanelHeader eyebrow={eyebrow} title={title} />
      <div className="form-grid">{children}</div>
      <button className="primary" disabled={Boolean(busy)} type="submit">
        {busy || 'Apply'}
      </button>
    </form>
  );
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function JsonBlock({ title, value }: { title?: string; value: unknown }) {
  return (
    <div className="json-block">
      {title ? <p>{title}</p> : null}
      <pre>{pretty(value)}</pre>
    </div>
  );
}

function ResourceTable({ rows }: { rows: Array<[string, string, string]> }) {
  return (
    <table className="resource-table">
      <thead>
        <tr>
          <th>Resource</th>
          <th>Value</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([resource, value, status]) => (
          <tr key={resource}>
            <td>{resource}</td>
            <td>{value}</td>
            <td>{status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EventList({ events }: { events: ConsoleEvent[] }) {
  if (!events.length) return <p className="muted">No API activity yet.</p>;
  return (
    <div className="event-list">
      {events.map((event) => (
        <article className={`event-item ${event.status}`} key={event.id}>
          <div>
            <strong>{event.label}</strong>
            <span>{event.status}</span>
          </div>
          <pre>{event.detail}</pre>
        </article>
      ))}
    </div>
  );
}
