import './styles.css';
import '@xyflow/react/dist/style.css';
import { GeistMono } from 'geist/font/mono';
import { GeistSans } from 'geist/font/sans';
import type { ReactNode } from 'react';

const nav = [
  ['dashboard', 'Dashboard'],
  ['nodes', 'Nodes'],
  ['profiles', 'Profiles'],
  ['clients', 'Clients'],
  ['deployments', 'Deployments'],
  ['tasks', 'Tasks'],
  ['logs', 'Logs'],
  ['settings', 'Settings'],
];

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <aside className="app-sidebar">
          <div className="brand">
            <span />
            <div>
              <h1>RelayX</h1>
              <p>Agent 原生代理基础设施控制平面</p>
            </div>
          </div>
          <nav>
            {nav.map(([href, label]) => (
              <a key={href} href={`/${href}`}>{label}</a>
            ))}
          </nav>
        </aside>
        <main>{children}</main>
      </body>
    </html>
  );
}
