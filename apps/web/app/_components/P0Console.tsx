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

type NodeInventoryItem = {
  node_id: string;
  host: string;
  xray_version: string;
  runner_result_public_key_hex: string;
  last_heartbeat_at: string;
};

type NodeInventoryResponse = {
  nodes: NodeInventoryItem[];
};

type RegistrationTokenItem = {
  token_id: string;
  token: string;
  status: string;
  used_by_node_id?: string | null;
};

type RegistrationTokenResponse = {
  tokens: RegistrationTokenItem[];
};

type ProfileInventoryItem = {
  profile_id: string;
  protocol: string;
  core: string;
  inbound_count: number;
  credential_count: number;
  created_at: string;
};

type ProfileInventoryResponse = {
  profiles: ProfileInventoryItem[];
};

type ClientInventoryItem = {
  client_id: string;
  profile_id: string;
  display_name: string;
  kind: string;
  status: string;
};

type ClientInventoryResponse = {
  clients: ClientInventoryItem[];
};

type DeploymentInventoryItem = {
  deployment_id: string;
  node_id: string;
  profile_id: string;
  compiled_config_artifact_id: string;
  status: string;
  created_at: string;
};

type DeploymentInventoryResponse = {
  deployments: DeploymentInventoryItem[];
};

class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly statusText: string,
    readonly body: string,
  ) {
    super(body || `${status} ${statusText}`);
  }
}

type TopologyData = {
  kicker: string;
  title: string;
  status: string;
  detail: string;
  tone: 'ok' | 'warn' | 'info' | 'idle';
};

type TopologyNode = Node<TopologyData, 'proxyNode'>;
type ControlState = 'unregistered' | 'registered' | 'deployed';
type ProxyProtocol = 'vless' | 'shadowsocks' | 'trojan';

const defaultNodeId = 'node-a';
const defaultProfileId = 'profile-a';
const defaultClientId = 'client-a';
const defaultUuid = '2f4f6f8a-1111-4c4c-9999-111111111111';
const defaultRunnerResultPublicKeyHex = '511c34a1a2cb521df16bb246b8de8e7997ce235c7e76b22a3d7503a24819dd8a';
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
    throw new ApiError(response.status, response.statusText, text);
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
  const [registrationToken, setRegistrationToken] = useState('dev-registration-token');
  const [runnerApiToken, setRunnerApiToken] = useState('dev-runner-token');
  const [runnerResultPublicKeyHex, setRunnerResultPublicKeyHex] = useState(defaultRunnerResultPublicKeyHex);
  const [profileId, setProfileId] = useState(defaultProfileId);
  const [profileProtocol, setProfileProtocol] = useState<ProxyProtocol>('vless');
  const [serverName, setServerName] = useState('example.com');
  const [inboundPort, setInboundPort] = useState('443');
  const [clientId, setClientId] = useState(defaultClientId);
  const [displayName, setDisplayName] = useState('Alice');
  const [uuid, setUuid] = useState(defaultUuid);
  const [credentialPassword, setCredentialPassword] = useState('MDEyMzQ1Njc4OWFiY2RlZg==');
  const [shadowsocksMethod, setShadowsocksMethod] = useState('2022-blake3-aes-128-gcm');
  const [quotaBytes, setQuotaBytes] = useState('1000000000');
  const [expiresAt, setExpiresAt] = useState('2026-12-31T00:00:00Z');
  const [deployment, setDeployment] = useState<DeploymentState | null>(null);
  const [health, setHealth] = useState<string>('checking');
  const [store, setStore] = useState<ControlState>('unregistered');
  const [nodes, setNodes] = useState<NodeInventoryItem[]>([]);
  const [registrationTokens, setRegistrationTokens] = useState<RegistrationTokenItem[]>([]);
  const [profiles, setProfiles] = useState<ProfileInventoryItem[]>([]);
  const [clients, setClients] = useState<ClientInventoryItem[]>([]);
  const [deployments, setDeployments] = useState<DeploymentInventoryItem[]>([]);
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
  const [architectureStatus, setArchitectureStatus] = useState<JsonValue | null>(null);

  const deploymentStatus = deployment?.status || 'none';
  const artifactShort = deployment?.artifactSha ? deployment.artifactSha.slice(0, 12) : 'none';
  const selectedNode = nodes.find((node) => node.node_id === nodeId);
  const selectedNodeRegistered = Boolean(selectedNode);
  const selectedRunnerResultKey = selectedNode?.runner_result_public_key_hex || runnerResultPublicKeyHex;
  const activeRegistrationToken = registrationTokens.find((token) => token.status === 'active');
  const controlStateLabel = stateLabel(store);
  const runnerCommand = useMemo(() => {
    const lines = [
      'CONTROL_PLANE_BASE_URL=http://127.0.0.1:18080 \\',
      `RUNNER_NODE_ID=${nodeId} \\`,
      `RUNNER_API_TOKEN=${runnerApiToken} \\`,
    ];
    if (!selectedNodeRegistered) {
      lines.push(`NODE_REGISTRATION_TOKEN=${registrationToken} \\`);
      lines.push(`RUNNER_XRAY_VERSION=${xrayVersion} \\`);
    }
    lines.push('RUNNER_WORK_DIR=.data/runner \\');
    lines.push('RUNNER_XRAY_BIN=/root/xray-bin/xray \\');
    lines.push('RUNNER_ONCE=1 \\');
    lines.push('./target/debug/runner');
    return lines.join('\n');
  }, [nodeId, registrationToken, runnerApiToken, selectedNodeRegistered, xrayVersion]);

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

  useEffect(() => {
    void refreshNodes(false);
    void refreshRegistrationTokens(false);
    void refreshProfiles(false);
    void refreshClients(false);
    void refreshDeployments(false);
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
      push(label, 'error', errorDetail(error));
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
          registration_token: registrationToken,
          node_id: nodeId,
          xray_version: xrayVersion,
        }),
      }),
    );
    setStore('registered');
    await refreshNodes(false);
    await refreshRegistrationTokens(false);
    return result;
  }

  async function refreshNodes(logActivity = true) {
    const load = async () => {
      const result = await api<NodeInventoryResponse>('/nodes');
      setNodes(result.nodes);
      if (result.nodes.some((node) => node.node_id === nodeId)) {
        setStore((current) => (current === 'deployed' ? current : 'registered'));
      } else {
        setStore('unregistered');
      }
      return result;
    };
    return logActivity ? run('Refresh node inventory', load) : load().catch(() => undefined);
  }

  async function refreshRegistrationTokens(logActivity = true) {
    const load = async () => {
      const result = await api<RegistrationTokenResponse>('/nodes/registration-tokens');
      setRegistrationTokens(result.tokens);
      const activeToken = result.tokens.find((token) => token.status === 'active');
      if (activeToken && !result.tokens.some((token) => token.token === registrationToken && token.status === 'active')) {
        setRegistrationToken(activeToken.token);
      }
      return result;
    };
    return logActivity ? run('Refresh registration tokens', load) : load().catch(() => undefined);
  }

  async function issueRegistrationToken() {
    const result = await run('Issue node registration token', () =>
      api<RegistrationTokenItem>('/nodes/registration-tokens', {
        method: 'POST',
        body: JSON.stringify({}),
      }),
    );
    setRegistrationToken(result.token);
    await refreshRegistrationTokens(false);
    return result;
  }

  async function rotateRunnerResultKey() {
    const result = await run('Rotate runner result key', () =>
      api<JsonValue>(`/nodes/${nodeId}/runner-result-key/rotate`, {
        method: 'POST',
        body: JSON.stringify({ runner_result_public_key_hex: runnerResultPublicKeyHex }),
      }),
    );
    await refreshNodes(false);
    return result;
  }

  async function createProfile(event?: FormEvent) {
    event?.preventDefault();
    const profileRequest =
      profileProtocol === 'shadowsocks'
        ? { path: '/profiles/shadowsocks', body: { profile_id: profileId, port: Number(inboundPort || 8388) } }
        : profileProtocol === 'trojan'
          ? {
              path: '/profiles/trojan',
              body: { profile_id: profileId, server_name: serverName, port: Number(inboundPort || 443) },
            }
          : { path: '/profiles/vless-reality', body: { profile_id: profileId, server_name: serverName } };
    const result = await run(`Create ${protocolLabel(profileProtocol)} profile`, () =>
      api<JsonValue>(profileRequest.path, {
        method: 'POST',
        body: JSON.stringify(profileRequest.body),
      }),
    );
    await refreshProfiles(false);
    return result;
  }

  async function refreshProfiles(logActivity = true) {
    const load = async () => {
      const result = await api<ProfileInventoryResponse>('/profiles');
      setProfiles(result.profiles);
      return result;
    };
    return logActivity ? run('Refresh profile inventory', load) : load().catch(() => undefined);
  }

  async function createClient(event?: FormEvent) {
    event?.preventDefault();
    const credentialMaterial =
      profileProtocol === 'shadowsocks'
        ? { kind: 'shadowsocks', method: shadowsocksMethod, password: credentialPassword }
        : profileProtocol === 'trojan'
          ? { kind: 'trojan', password: credentialPassword }
          : { kind: 'vless', uuid };
    const result = await run('Create client credential', () =>
      api<JsonValue>('/clients', {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          profile_id: profileId,
          display_name: displayName,
          ...credentialMaterial,
          quota_bytes: Number(quotaBytes),
          expires_at: expiresAt,
        }),
      }),
    );
    await refreshClients(false);
    await refreshProfiles(false);
    return result;
  }

  async function refreshClients(logActivity = true) {
    const load = async () => {
      const result = await api<ClientInventoryResponse>('/clients');
      setClients(result.clients);
      return result;
    };
    return logActivity ? run('Refresh client inventory', load) : load().catch(() => undefined);
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
    setStore('registered');
    push('DeploymentPlan', 'info', plan);
    await refreshDeployments(false);
    return result;
  }

  async function refreshDeployments(logActivity = true) {
    const load = async () => {
      const result = await api<DeploymentInventoryResponse>('/deployments');
      setDeployments(result.deployments);
      return result;
    };
    return logActivity ? run('Refresh deployment inventory', load) : load().catch(() => undefined);
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
        headers: { 'x-runner-token': runnerApiToken },
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
    await refreshNodes(false);
    return result;
  }

  async function fetchHeartbeat() {
    const result = await run('Fetch runner heartbeat', () => api<JsonValue>(`/nodes/${nodeId}/heartbeat`));
    setLatestHeartbeat(result);
    await refreshNodes(false);
    return result;
  }

  async function fetchRunnerCommand() {
    const result = await run('Fetch next runner command', async () => {
      try {
        const command = await api<JsonValue | undefined>(`/runner/nodes/${nodeId}/commands/next?last_sequence=0`, {
          headers: { 'x-runner-token': runnerApiToken },
        });
        return command || { status: 'no queued command', next_step: 'Compile a deployment, then run the runner once command.' };
      } catch (error) {
        if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
          return runnerCommandBoundary(error, nodeId);
        }
        throw error;
      }
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
        headers: { 'x-runner-token': runnerApiToken },
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
        headers: { 'x-runner-token': runnerApiToken },
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

  async function fetchArchitectureStatus() {
    const result = await run('Fetch architecture capabilities', () => api<JsonValue>('/system/capabilities'));
    setArchitectureStatus(result);
    return result;
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
      setStore('registered');
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
          <StatusPill label="Node" value={controlStateLabel} tone={store === 'deployed' ? 'ok' : store === 'registered' ? 'info' : 'warn'} />
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
                  <JsonBlock title="Status" value={deployment ? { status: deployment.status, artifact: deployment.artifactId } : { status: 'not compiled' }} />
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
                    {busy || 'Create dev deployment'}
                  </button>
                }
              />
              <p className="muted">
                One-click dev bootstrap: health check, node registration, profile, credential, deployment compile, then runner queue check. It creates sample control-plane records; it does not start xray-core by itself.
              </p>
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
          <FormPanel title="Register runner node" eyebrow="Node inventory" onSubmit={registerNode} busy={busy} submitLabel="Register node">
            <Field label="Node ID" value={nodeId} onChange={setNodeId} />
            <Field label="Xray version" value={xrayVersion} onChange={setXrayVersion} />
            <Field label="Registration token" value={registrationToken} onChange={setRegistrationToken} wide />
          </FormPanel>
          <section className="data-panel">
            <PanelHeader
              eyebrow="Runner trust"
              title="Result signature key"
              action={<button disabled={!selectedNode || Boolean(busy)} onClick={rotateRunnerResultKey} type="button">Rotate key</button>}
            />
            <Field label="Runner result public key" value={runnerResultPublicKeyHex} onChange={setRunnerResultPublicKeyHex} wide />
            <Field label="Runner API token" value={runnerApiToken} onChange={setRunnerApiToken} wide />
            <ResourceTable
              rows={[
                ['Registered key', shortHex(selectedRunnerResultKey), selectedNode ? 'loaded from node identity' : 'default dev key'],
                ['Runner API token', runnerApiToken ? 'configured in console' : 'missing', runnerApiToken ? 'sent as x-runner-token' : 'command polling will be unauthorized'],
                ['Rotate endpoint', `/nodes/${nodeId}/runner-result-key/rotate`, selectedNode ? 'ready' : 'register node first'],
              ]}
            />
          </section>
          <section className="data-panel">
            <PanelHeader eyebrow="Add path" title="How nodes join" />
            <ResourceTable
              rows={[
                ['Browser registration', 'Register node', selectedNode ? 'already registered' : 'uses /nodes/register'],
                [
                  'Runner self-registration',
                  'NODE_REGISTRATION_TOKEN',
                  selectedNode ? 'omit after registration' : activeRegistrationToken ? 'active token available' : 'issue a token first',
                ],
                ['One-time token', activeRegistrationToken?.token || registrationToken, tokenStatus(registrationTokens, activeRegistrationToken?.token || registrationToken)],
              ]}
            />
            <p className="muted offset-top">
              Nodes are runner identities, not proxy clients. The browser can register a dev node for testing; in the real flow the runner starts with a one-time token, registers itself, then polls signed deployment commands.
            </p>
          </section>
          <section className="data-panel span-2">
            <PanelHeader
              eyebrow="Runner evidence"
              title="Node heartbeat and command queue"
              action={
                <div className="button-row compact-row">
                  <button onClick={() => refreshNodes()} type="button">Refresh nodes</button>
                  <button onClick={issueRegistrationToken} type="button">Issue token</button>
                  <button onClick={sendHeartbeat} type="button">Send heartbeat</button>
                  <button onClick={fetchHeartbeat} type="button">Read heartbeat</button>
                  <button onClick={fetchRunnerCommand} type="button">Fetch next command</button>
                </div>
              }
            />
            <ResourceTable
              rows={[
                ['Node ID', nodeId, selectedNode ? 'registered in control-plane' : 'not registered in control-plane'],
                ['Host', selectedNode?.host || `${nodeId}.example`, selectedNode ? 'loaded from backend' : 'derived preview'],
                ['Core', selectedNode?.xray_version || `xray ${xrayVersion}`, 'P0 runner target'],
                ['Result key', shortHex(selectedRunnerResultKey), 'runner result signature verification'],
                ['Runner token', runnerApiToken ? 'configured' : 'missing', runnerApiToken ? 'matches dev default unless changed' : 'set RUNNER_API_TOKEN first'],
                ['Command source', `/runner/nodes/${nodeId}/commands/next`, runnerCommandStatus(runnerCommandEnvelope, selectedNodeRegistered)],
                ['Registration token', registrationToken, tokenStatus(registrationTokens, registrationToken)],
              ]}
            />
            <p className="muted offset-top">
              A node is a VPS-side runner identity. Registering it creates the control-plane record; the runner process then sends heartbeat, polls the next command, applies the xray-core config, and reports evidence.
            </p>
            <div className="artifact-split offset-top">
              <JsonBlock title="Node inventory" value={nodes.length ? nodes : { status: 'no nodes registered' }} />
              <JsonBlock title="Registration tokens" value={registrationTokens.length ? registrationTokens : { status: 'no registration tokens loaded' }} />
              <JsonBlock title="Latest heartbeat" value={latestHeartbeat || { status: 'not loaded yet' }} />
              <JsonBlock title="Next command envelope" value={runnerCommandEnvelope || { status: 'no pending command loaded' }} />
            </div>
          </section>
          <section className="data-panel span-3">
            <PanelHeader eyebrow="Runner command" title="Apply queued deployment" />
            <p className="muted">
              Run this on the remote machine after compile. When the node is not registered, the command includes the one-time registration token; after registration it only polls, tests, switches, and reports evidence.
            </p>
            <pre className="codeblock">{runnerCommand}</pre>
          </section>
        </section>
      ) : null}

      {view === 'profiles' ? (
        <section className="detail-workspace">
          <FormPanel title={`${protocolLabel(profileProtocol)} profile`} eyebrow="Profile IR" onSubmit={createProfile} busy={busy}>
            <SelectField
              label="Protocol"
              value={profileProtocol}
              onChange={(value) => setProfileProtocol(value as ProxyProtocol)}
              options={[
                ['vless', 'VLESS REALITY'],
                ['shadowsocks', 'Shadowsocks'],
                ['trojan', 'Trojan TLS'],
              ]}
            />
            <Field label="Profile ID" value={profileId} onChange={setProfileId} />
            {profileProtocol !== 'shadowsocks' ? <Field label="Server name / SNI" value={serverName} onChange={setServerName} /> : null}
            {profileProtocol !== 'vless' ? <Field label="Inbound port" value={inboundPort} onChange={setInboundPort} /> : null}
          </FormPanel>
          <section className="data-panel span-2">
            <PanelHeader
              eyebrow="Compiler target"
              title="Xray adapter coverage"
              action={<button onClick={() => refreshProfiles()} type="button">Refresh profiles</button>}
            />
            <ResourceTable
              rows={[
                ['Selected protocol', protocolLabel(profileProtocol), 'wired to backend endpoint'],
                ['VLESS REALITY', '/profiles/vless-reality', 'browser operation'],
                ['Shadowsocks', '/profiles/shadowsocks', 'browser operation'],
                ['Trojan', '/profiles/trojan', 'browser operation'],
                ['Profile inventory', '/profiles', inventoryStatus(profiles.length, 'profile')],
                ['Core', 'xray-core', 'verified locally'],
                ['Later adapter', 'sing-box', 'kept behind compiler boundary'],
              ]}
            />
            <div className="offset-top">
              <JsonBlock title="Profile inventory" value={profiles.length ? profiles : { status: 'No profiles yet', next_step: 'Create a profile before compiling a deployment.' }} />
            </div>
          </section>
        </section>
      ) : null}

      {view === 'clients' ? (
        <section className="detail-workspace">
          <FormPanel title="Client credential" eyebrow={protocolLabel(profileProtocol)} onSubmit={createClient} busy={busy}>
            <SelectField
              label="Credential kind"
              value={profileProtocol}
              onChange={(value) => setProfileProtocol(value as ProxyProtocol)}
              options={[
                ['vless', 'VLESS UUID'],
                ['shadowsocks', 'Shadowsocks password'],
                ['trojan', 'Trojan password'],
              ]}
            />
            <Field label="Client ID" value={clientId} onChange={setClientId} />
            <Field label="Profile ID" value={profileId} onChange={setProfileId} />
            <Field label="Display name" value={displayName} onChange={setDisplayName} />
            {profileProtocol === 'vless' ? <Field label="UUID" value={uuid} onChange={setUuid} /> : null}
            {profileProtocol === 'shadowsocks' ? <Field label="Method" value={shadowsocksMethod} onChange={setShadowsocksMethod} wide /> : null}
            {profileProtocol !== 'vless' ? <Field label="Password" value={credentialPassword} onChange={setCredentialPassword} wide /> : null}
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
                  <button onClick={() => refreshClients()} type="button">Refresh clients</button>
                </div>
              }
            />
            <ResourceTable
              rows={[
                ['Client ID', clientId, 'credential'],
                ['Credential kind', protocolLabel(profileProtocol), 'wired to /clients kind'],
                ['Client inventory', '/clients', inventoryStatus(clients.length, 'client')],
                ['Quota bytes', quotaBytes, quotaDecision ? 'decision loaded' : 'not loaded'],
                ['Expires at', expiresAt, expiryDecision ? 'decision loaded' : 'not loaded'],
              ]}
            />
            <div className="artifact-split offset-top">
              <JsonBlock title="Latest usage" value={latestUsage || { status: 'no usage sample loaded' }} />
              <JsonBlock title="Quota decision" value={quotaDecision || { status: 'not loaded' }} />
              <JsonBlock title="Expiry decision" value={expiryDecision || { status: 'not loaded' }} />
              <JsonBlock title="Usage rollups" value={Object.keys(usageRollups).length ? usageRollups : { status: 'not loaded' }} />
              <JsonBlock title="Client inventory" value={clients.length ? clients : { status: 'No clients yet', next_step: 'Create a client credential for the selected profile.' }} />
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
                  <button onClick={() => refreshDeployments()} type="button">Refresh deployments</button>
                </div>
              }
            />
            <ResourceTable
              rows={[
                ['Deployment ID', deployment?.deploymentId || 'none', deploymentStatus],
                ['Artifact SHA', artifactShort, deployment?.artifactId || 'none'],
                ['Deployment inventory', '/deployments', inventoryStatus(deployments.length, 'deployment')],
                ['Rollout action', readString(rolloutAction, 'action') || 'none', rolloutAction ? 'loaded' : 'not loaded'],
              ]}
            />
            <div className="artifact-split">
              <JsonBlock title="Status" value={deployment ? { status: deployment.status, artifact: deployment.artifactId } : { status: 'not compiled' }} />
              <JsonBlock title="Health" value={deployment?.health || { status: 'not loaded yet' }} />
              <JsonBlock title="Readiness" value={deployment?.readiness || { status: 'not loaded yet' }} />
              <JsonBlock title="Rollback pointer" value={deployment?.rollbackPointer || { status: 'not loaded yet' }} />
              <JsonBlock title="Rollout action" value={rolloutAction || { status: 'not loaded yet' }} />
              <JsonBlock title="Runner result count" value={runnerResultCount || { status: 'not loaded yet' }} />
              <JsonBlock title="Deployment inventory" value={deployments.length ? deployments : { status: 'No deployments yet', next_step: 'Compile a deployment after node, profile, and client exist.' }} />
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
                  <button onClick={fetchRunnerCommand} type="button">Fetch next command</button>
                  <button onClick={fetchRunnerResultCount} type="button">Result count</button>
                </div>
              }
            />
            <div className="artifact-split">
              <JsonBlock title="Next runner command" value={runnerCommandEnvelope || { status: 'No runner command loaded', next_step: 'Register a node and compile a deployment, then fetch the next command.' }} />
              <JsonBlock title="Runner result count" value={runnerResultCount || { status: 'not loaded yet' }} />
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
              <JsonBlock title="Snapshot" value={deployment?.snapshot || { status: 'not loaded yet' }} />
              <JsonBlock title="Last event" value={events[0] || { status: 'no events yet' }} />
              <JsonBlock title="Rollout action" value={rolloutAction || { status: 'not loaded yet' }} />
              <JsonBlock title="Artifact preview" value={deployment?.artifactPreview || { status: 'not loaded yet' }} />
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
            <PanelHeader
              eyebrow="Runtime"
              title="Architecture status"
              action={<button type="button" onClick={fetchArchitectureStatus}>Read capabilities</button>}
            />
            <ResourceTable
              rows={[
                ['Web', '0.0.0.0:3000', 'dev only'],
                ['Control-plane', '0.0.0.0:18080', 'dev only'],
                ['Xray', '/root/xray-bin/xray', 'local core'],
                ['Backend wheels', '/system/capabilities', architectureStatus ? 'loaded' : 'not loaded'],
              ]}
            />
            <div className="offset-top">
              <JsonBlock title="Capability matrix" value={architectureStatus || { status: 'not loaded yet' }} />
            </div>
          </section>
        </section>
      ) : null}

      <aside className="activity-dock">
        <PanelHeader eyebrow="Activity" title="Recent API calls" action={<StatusProbe value={health} onClick={checkHealth} />} />
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
  storeState: ControlState;
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
        data: { kicker: 'Control state', title: 'Memory store', status: stateLabel(storeState), detail: 'in-memory now, Postgres later', tone: storeState === 'deployed' ? 'ok' : 'idle' },
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
  store: ControlState;
}) {
  const steps = [
    ['01', 'Health', health === 'ok' ? 'API reachable' : 'Not checked'],
    ['02', 'Register', store === 'unregistered' ? 'Node not registered' : nodeId],
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

function stateLabel(state: ControlState) {
  if (state === 'deployed') return 'Deployed';
  if (state === 'registered') return 'Registered';
  return 'Not registered';
}

function protocolLabel(protocol: ProxyProtocol) {
  if (protocol === 'shadowsocks') return 'Shadowsocks';
  if (protocol === 'trojan') return 'Trojan TLS';
  return 'VLESS REALITY';
}

function inventoryStatus(count: number, itemName: string) {
  return count > 0 ? `${count} loaded` : `No ${itemName}s yet`;
}

function runnerCommandStatus(envelope: JsonValue | null, nodeRegistered: boolean) {
  const status = readString(envelope, 'status');
  if (status) return status;
  return nodeRegistered ? 'ready to poll with runner token' : 'register node first';
}

function runnerCommandBoundary(error: ApiError, nodeId: string): Record<string, unknown> {
  if (error.status === 404) {
    return {
      status: 'Node not registered',
      http_status: error.status,
      node_id: nodeId,
      next_step: 'Create or register the node before polling the runner command queue.',
    };
  }
  return {
    status: 'Runner command not authorized',
    http_status: error.status,
    node_id: nodeId,
    reason: 'Runner command polling is a runner-only API and requires a valid x-runner-token for this node.',
    next_step: 'Keep RUNNER_API_TOKEN aligned with the control-plane token, then run the runner once command on the VPS.',
  };
}

function errorDetail(error: unknown): Record<string, unknown> | string {
  if (error instanceof ApiError) {
    return {
      status: error.status,
      status_text: error.statusText,
      body: error.body || 'No response body',
    };
  }
  return error instanceof Error ? error.message : String(error);
}

function shortHex(value: string) {
  if (!value) return 'not set';
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-8)}` : value;
}

function tokenStatus(tokens: RegistrationTokenItem[], tokenValue: string) {
  const token = tokens.find((item) => item.token === tokenValue);
  if (!token) return 'not loaded';
  if (token.status === 'active') return 'active one-time token';
  return token.used_by_node_id ? `used by ${token.used_by_node_id}` : token.status;
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
  submitLabel = 'Apply',
}: {
  title: string;
  eyebrow: string;
  children: ReactNode;
  onSubmit: (event: FormEvent) => void;
  busy: string | null;
  submitLabel?: string;
}) {
  return (
    <form className="data-panel form-panel" onSubmit={onSubmit}>
      <PanelHeader eyebrow={eyebrow} title={title} />
      <div className="form-grid">{children}</div>
      <button className="primary" disabled={Boolean(busy)} type="submit">
        {busy || submitLabel}
      </button>
    </form>
  );
}

function Field({
  label,
  value,
  onChange,
  wide = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  wide?: boolean;
}) {
  return (
    <label className={`field ${wide ? 'wide-field' : ''}`}>
      <span>{label}</span>
      <input value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<[string, string]>;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map(([optionValue, label]) => (
          <option key={optionValue} value={optionValue}>
            {label}
          </option>
        ))}
      </select>
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
