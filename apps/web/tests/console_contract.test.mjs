import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const appDir = new URL('../app/', import.meta.url);
const read = (path) => readFileSync(new URL(path, appDir), 'utf8');

test('route pages render the interactive P0 console instead of runbook cards', () => {
  const pages = ['dashboard', 'nodes', 'clients', 'profiles', 'deployments', 'tasks', 'logs', 'settings'];
  for (const page of pages) {
    const source = read(`${page}/page.tsx`);
    assert(source.includes('P0Console'), `${page} does not render P0Console`);
    assert(!source.includes('CommandBlock'), `${page} still renders command-only runbook blocks`);
    assert(!source.includes('ConsoleCard'), `${page} still renders static cards`);
    assert(!source.includes('curl -sS'), `${page} still contains curl instructions`);
  }
});

test('P0 console contains real browser operations for the control-plane flow', () => {
  const source = read('_components/P0Console.tsx');
  for (const snippet of [
    '/nodes/register',
    '/profiles/vless-reality',
    '/clients',
    '/deployments/compile',
    '/deployments/${deployment.deploymentId}/health',
    '/artifacts/${deployment.artifactId}/bytes',
    '/subscriptions/${profileId}',
    '/runner/nodes/${nodeId}/usage',
    '/runner/nodes/${nodeId}/heartbeat',
    '/nodes/${nodeId}/heartbeat',
    '/runner/nodes/${nodeId}/commands/next',
    '/runner/nodes/${nodeId}/deployments/${deployment.deploymentId}/health',
    '/deployments/${deployment.deploymentId}/advance',
    '/deployments/${deployment.deploymentId}/rollback',
    '/runner/results/count',
    '/clients/${clientId}/quota',
    '/clients/${clientId}/expiry',
    '/usage/credentials/${clientId}/rollups/latest?bucket=hour',
    'Run browser bootstrap',
    'Refresh evidence',
    'Fetch subscription',
  ]) {
    assert(source.includes(snippet), `P0Console missing ${snippet}`);
  }
});

test('dashboard uses a Vercel-style workbench with a Claude-style operator artifact rail', () => {
  const source = read('_components/P0Console.tsx');
  for (const snippet of [
    '@xyflow/react',
    'TopologyCanvas',
    'TopologyNodeCard',
    'nodesDraggable',
    'onNodeDragStop',
    'proxy-control-topology-positions',
    'Next.js Web',
    'Rust API',
    'DeploymentPlan',
    'operator-panel',
    'artifact-panel',
    'Run browser bootstrap',
    'Runner queue and browser journal',
    'Quota evidence',
    'Heartbeat and command queue',
    'xray-core',
  ]) {
    assert(source.includes(snippet), `P0Console missing workbench item ${snippet}`);
  }
});

test('Next route handler proxies same-origin browser calls to the Rust control-plane', () => {
  const source = read('api/control-plane/[...path]/route.ts');
  assert(source.includes('WEB_API_BASE_URL'));
  assert(source.includes('DEFAULT_CONTROL_PLANE'));
  assert(source.includes('idempotency-key'));
  assert(source.includes('x-runner-token'));
  assert(source.includes('export async function GET'));
  assert(source.includes('export async function POST'));
});

test('layout and styles express a dense operational console', () => {
  const layout = read('layout.tsx');
  const styles = read('styles.css');
  assert(layout.includes('app-sidebar'));
  assert(layout.includes('GeistSans'));
  assert(layout.includes('@xyflow/react/dist/style.css'));
  assert(layout.includes('RelayX'));
  assert(layout.includes('Agent 原生代理基础设施控制平面'));
  for (const className of [
    'workbench-shell',
    'dashboard-workspace',
    'dashboard-main',
    'dashboard-left-stack',
    'metric-strip',
    'status-probe',
    'topology-canvas',
    'operator-panel',
    'artifact-panel',
    'detail-workspace',
    'form-panel',
    'activity-dock',
    'artifact-preview',
    'runbook-step',
    'resource-table',
    'offset-top',
  ]) {
    assert(styles.includes(className), `styles missing ${className}`);
  }
  assert(styles.includes('--page: #fbf8ff'), 'styles should use a restrained light-purple page surface');
  assert(styles.includes('--accent: #7c3aed'), 'styles should expose the light-purple accent token');
  assert(styles.includes('.status-probe.checking'), 'styles should define the yellow connecting state');
  assert(styles.includes('.status-probe.error'), 'styles should define the red failed state');
  assert(styles.includes('var(--font-geist-sans)'), 'styles should use Geist Sans');
  assert(styles.includes('var(--font-geist-mono)'), 'styles should use Geist Mono');
});
