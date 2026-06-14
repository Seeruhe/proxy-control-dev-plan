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

  const requestHeaders = new Headers();
  for (const name of ['content-type', 'idempotency-key', 'x-runner-token']) {
    const value = request.headers.get(name);
    if (value) requestHeaders.set(name, value);
  }

  const response = await fetch(upstream, {
    method: request.method,
    headers: requestHeaders,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text(),
    cache: 'no-store',
  });

  const responseHeaders = new Headers();
  const contentType = response.headers.get('content-type');
  if (contentType) responseHeaders.set('content-type', contentType);

  if (response.status === 204 || response.status === 304 || request.method === 'HEAD') {
    return new NextResponse(null, {
      status: response.status,
      headers: responseHeaders,
    });
  }

  const body = await response.arrayBuffer();
  return new NextResponse(body, {
    status: response.status,
    headers: responseHeaders,
  });
}

export async function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}
