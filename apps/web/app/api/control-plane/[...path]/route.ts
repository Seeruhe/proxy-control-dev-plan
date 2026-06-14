import { NextRequest, NextResponse } from 'next/server';

const DEFAULT_CONTROL_PLANE = 'http://127.0.0.1:18080';

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

function controlPlaneBaseUrl() {
  return (process.env.WEB_API_BASE_URL || DEFAULT_CONTROL_PLANE).replace(/\/$/, '');
}

async function proxy(request: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const upstream = new URL(`${controlPlaneBaseUrl()}/${path.join('/')}`);
  upstream.search = request.nextUrl.search;

  const headers = new Headers();
  for (const name of ['content-type', 'idempotency-key', 'x-runner-token']) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }

  const response = await fetch(upstream, {
    method: request.method,
    headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text(),
    cache: 'no-store',
  });

  const body = await response.arrayBuffer();
  return new NextResponse(body, {
    status: response.status,
    headers: {
      'content-type': response.headers.get('content-type') || 'application/octet-stream',
    },
  });
}

export async function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}
