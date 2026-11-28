import { useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

type SetupStatus = { setup_required: boolean };
type AuthResponse = { authenticated: boolean; username: string | null };
type Health = { ok: boolean; version: string; runtime: string };
type RuntimeStatus = { mode: string; available: boolean; engine: string; message: string; can_manage_vpn: boolean; wireguard_master_key_configured: boolean };
type AwgSettings = {
  version: string; jc?: number; jmin?: number; jmax?: number; s1?: number; s2?: number;
  s3?: number; s4?: number; h1?: string; h2?: string; h3?: string; h4?: string;
  i1?: string; i2?: string; i3?: string; i4?: string; i5?: string;
  content_padding_addition?: number | string; random_trailers?: boolean; disable_cookies?: boolean;
};
type Container = {
  id: string; name: string; protocol: string; status: string; runtime_operation?: string | null; endpoint: string;
  listen_port: number; transport: string; subnet: string; dns: string; mtu: number;
  revision: number; awg_settings_json: string; wireguard_server_public_key?: string | null;
  awg_header_protection_key_configured: boolean;
};
type Client = {
  id: string; container_id: string; name: string; note: string; assigned_ip: string;
  enabled: boolean; traffic_limit_bytes: number; traffic_used_bytes: number; expires_at: string | null;
  wireguard_public_key?: string | null;
};
type PeerStatsItem = {
  client_id: string; name: string; assigned_ip: string; enabled: boolean; expired: boolean;
  active_on_server: boolean; latest_handshake_unix: number | null;
  rx_bytes: number | null; tx_bytes: number | null;
  traffic_used_bytes: number; traffic_limit_bytes: number;
};
type PeerStatsResponse = {
  container_id: string; interface_name: string; peer_count: number; unmatched_peer_count: number;
  items: PeerStatsItem[];
};
type ListResponse<T> = { items: T[] };
type CreatedClient = { item: Client; subscription_token: string; notice: string };
type Section = 'overview' | 'protocols' | 'clients';

const emptyAwg = {
  version: '2.0', jc: '5', jmin: '8', jmax: '80', s1: '32', s2: '64',
  s3: '16', s4: '8', h1: '', h2: '', h3: '', h4: '',
  i1: '', i2: '', i3: '', i4: '', i5: '',
  content_padding_addition: '', random_trailers: false, disable_cookies: false,
};
const protocolNames: Record<string, string> = {
  'amnezia-awg': 'AmneziaWG', wireguard: 'WireGuard', openvpn: 'OpenVPN', 'openvpn-cloak': 'OpenVPN + Cloak',
};

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, credentials: 'include', headers });
  if (!response.ok) {
    const body = await response.text();
    let message = body || `HTTP ${response.status}`;
    try { const parsed = JSON.parse(body); message = parsed.error ?? parsed.message ?? message; } catch {}
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function formatBytes(value: number | null | undefined): string {
  if (value == null) return '—';
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = value / 1024;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(amount >= 100 ? 0 : 1)} ${units[unit]}`;
}

function formatHandshake(value: number | null | undefined): string {
  if (!value) return 'Нет handshake';
  return new Date(value * 1000).toLocaleString();
}

function App() {
  const [loading, setLoading] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const [user, setUser] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [containers, setContainers] = useState<Container[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [peerStats, setPeerStats] = useState<Record<string, PeerStatsResponse>>({});
  const [section, setSection] = useState<Section>('overview');
  const [showContainerForm, setShowContainerForm] = useState(false);
  const [editingAwgId, setEditingAwgId] = useState<string | null>(null);
  const [clientFormFor, setClientFormFor] = useState<string | null>(null);
  const [issuedToken, setIssuedToken] = useState('');
  const [clientSearch, setClientSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [containerDraft, setContainerDraft] = useState({
    name: '', protocol: 'amnezia-awg', endpoint: '', listen_port: '443',
    transport: 'udp', subnet: '10.66.0.0/24', dns: '1.1.1.1', mtu: '1280',
  });
  const [awgDraft, setAwgDraft] = useState(emptyAwg);
  const [clientName, setClientName] = useState('');
  const [clientNote, setClientNote] = useState('');
  const [clientExpiresAt, setClientExpiresAt] = useState('');
  const [clientTrafficLimitGb, setClientTrafficLimitGb] = useState('0');
  const [actionBusy, setActionBusy] = useState(false);

  async function loadWorkspace() {
    const [containerData, clientData, runtimeData] = await Promise.all([
      api<ListResponse<Container>>('/api/containers'),
      api<ListResponse<Client>>('/api/clients'),
      api<RuntimeStatus>('/api/runtime/status'),
    ]);
    setContainers(containerData.items);
    setClients(clientData.items);
    setRuntimeStatus(runtimeData);
  }

  async function refresh() {
    try {
      const [setup, service] = await Promise.all([
        api<SetupStatus>('/api/setup/status'), api<Health>('/api/health'),
      ]);
      setSetupRequired(setup.setup_required);
      setHealth(service);
      if (!setup.setup_required) {
        try {
          const session = await api<AuthResponse>('/api/auth/me');
          setUser(session.username);
          await loadWorkspace();
        } catch { setUser(null); }
      } else setUser(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Не удалось подключиться к API');
    } finally { setLoading(false); }
  }

  useEffect(() => { void refresh(); }, []);

  // Read-only peer counters are refreshed only for running Linux-host profiles.
  useEffect(() => {
    const active = containers.filter(container =>
      container.status === 'running' && !container.runtime_operation &&
      (container.protocol === 'wireguard' || container.protocol === 'amnezia-awg')
    );
    if (!user || runtimeStatus?.mode !== 'host' || active.length === 0) {
      setPeerStats({});
      return;
    }

    let disposed = false;
    let polling = false;
    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const results = await Promise.all(active.map(async container => {
          try {
            const result = await api<PeerStatsResponse>(`/api/containers/${container.id}/peer-stats`);
            return [container.id, result] as const;
          } catch {
            return [container.id, null] as const;
          }
        }));
        if (!disposed) {
          setPeerStats(current => {
            const next: Record<string, PeerStatsResponse> = {};
            for (const container of active) {
              const result = results.find(([id]) => id === container.id)?.[1];
              if (result) next[container.id] = result;
              else if (current[container.id]) next[container.id] = current[container.id];
            }
            return next;
          });
        }
      } finally {
        polling = false;
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), 15000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [containers, user, runtimeStatus?.mode]);

  async function submitAuth(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const result = await api<AuthResponse>(setupRequired ? '/api/setup/initialize' : '/api/auth/login', {
        method: 'POST', body: JSON.stringify({ username, password }),
      });
      setUser(result.username); setPassword(''); setSetupRequired(false); await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось выполнить запрос'); }
    finally { setBusy(false); }
  }

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); }
    finally { setUser(null); setContainers([]); setClients([]); }
  }

  function awgPayload() {
    const numeric = (value: string) => value.trim() === '' ? undefined : Number(value);
    const text = (value: string) => value.trim() === '' ? undefined : value.trim();
    return {
      version: awgDraft.version,
      jc: numeric(awgDraft.jc), jmin: numeric(awgDraft.jmin), jmax: numeric(awgDraft.jmax),
      s1: numeric(awgDraft.s1), s2: numeric(awgDraft.s2), s3: numeric(awgDraft.s3), s4: numeric(awgDraft.s4),
      h1: text(awgDraft.h1), h2: text(awgDraft.h2), h3: text(awgDraft.h3), h4: text(awgDraft.h4),
      i1: text(awgDraft.i1), i2: text(awgDraft.i2), i3: text(awgDraft.i3), i4: text(awgDraft.i4), i5: text(awgDraft.i5),
      content_padding_addition: awgDraft.version === '3.1'
        ? (awgDraft.content_padding_addition.trim() === '' ? undefined
          : (/^\d+$/.test(awgDraft.content_padding_addition.trim())
            ? Number(awgDraft.content_padding_addition.trim())
            : awgDraft.content_padding_addition.trim()))
        : undefined,
      random_trailers: awgDraft.version === '3.1' && awgDraft.random_trailers,
      disable_cookies: awgDraft.version === '3.1' && awgDraft.disable_cookies,
    };
  }

  async function createContainer(event: FormEvent) {
    event.preventDefault(); setActionBusy(true); setError('');
    try {
      if (editingAwgId) {
        const target = containers.find(item => item.id === editingAwgId);
        if (!target) throw new Error('Профиль больше не найден. Обнови список.');
        await api('/api/containers/' + editingAwgId + '/awg-profile', { method: 'PUT', body: JSON.stringify({ expected_revision: target.revision, settings: awgPayload() }) });
        setEditingAwgId(null);
      } else {
        const body: Record<string, unknown> = { ...containerDraft, listen_port: Number(containerDraft.listen_port), mtu: Number(containerDraft.mtu) };
        if (containerDraft.protocol === 'amnezia-awg') body.awg_settings = awgPayload();
        await api('/api/containers', { method: 'POST', body: JSON.stringify(body) });
      }
      setShowContainerForm(false);
      setContainerDraft({ name: '', protocol: 'amnezia-awg', endpoint: '', listen_port: '443', transport: 'udp', subnet: '10.66.0.0/24', dns: '1.1.1.1', mtu: '1280' });
      setAwgDraft(emptyAwg);
      await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать конфигурацию'); }
    finally { setActionBusy(false); }
  }

  async function operateInterface(containerId: string, action: 'start' | 'stop') {
    setActionBusy(true); setError('');
    try {
      await api('/api/containers/' + containerId + '/' + action, { method: 'POST', body: '{}' });
      await loadWorkspace();
    } catch (e) {
      setError(e instanceof Error ? e.message : (action === 'start' ? 'Не удалось запустить VPN-интерфейс' : 'Не удалось остановить VPN-интерфейс'));
      await loadWorkspace().catch(() => undefined);
    } finally { setActionBusy(false); }
  }

  async function provisionServerKey(containerId: string) {
    setActionBusy(true); setError('');
    try {
      await api('/api/containers/' + containerId + '/wireguard-server-key', { method: 'POST', body: '{}' });
      await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать ключ сервера'); }
    finally { setActionBusy(false); }
  }

  async function provisionAwgHeaderProtectionKey(containerId: string) {
    setActionBusy(true); setError('');
    try {
      await api('/api/containers/' + containerId + '/awg-header-protection-key', { method: 'POST', body: '{}' });
      await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать HeaderProtectionKey'); }
    finally { setActionBusy(false); }
  }

  async function createClient(event: FormEvent, containerId: string) {
    event.preventDefault(); setActionBusy(true); setError(''); setIssuedToken('');
    try {
      const trafficLimitGb = Number(clientTrafficLimitGb || '0');
      const trafficLimitBytes = Math.round(trafficLimitGb * 1024 ** 3);
      if (!Number.isFinite(trafficLimitGb) || trafficLimitGb < 0 || !Number.isSafeInteger(trafficLimitBytes)) {
        throw new Error('Укажи корректный лимит трафика в ГиБ');
      }
      const result = await api<CreatedClient>(`/api/containers/${containerId}/clients`, {
        method: 'POST', body: JSON.stringify({
          name: clientName,
          note: clientNote,
          traffic_limit_bytes: trafficLimitBytes,
          ...(clientExpiresAt ? { expires_at: new Date(clientExpiresAt).toISOString() } : {}),
        }),
      });
      setIssuedToken(result.subscription_token); setClientName(''); setClientNote(''); setClientExpiresAt(''); setClientTrafficLimitGb('0');
      setClientFormFor(null); await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать клиента'); }
    finally { setActionBusy(false); }
  }

  async function downloadSubscriptionConfig() {
    if (!issuedToken) return;
    setActionBusy(true); setError('');
    try {
      const response = await fetch('/api/subscriptions/config', {
        method: 'GET',
        credentials: 'omit',
        headers: { Authorization: `Bearer ${issuedToken}` },
      });
      if (!response.ok) {
        const body = await response.text();
        let message = body || `HTTP ${response.status}`;
        try { const parsed = JSON.parse(body); message = parsed.error ?? parsed.message ?? message; } catch {}
        throw new Error(message);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'client.conf';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Не удалось скачать клиентский конфиг по токену');
    } finally {
      setActionBusy(false);
    }
  }

  async function disableClient(clientId: string) {
    setActionBusy(true); setError('');
    try { await api(`/api/clients/${clientId}/disable`, { method: 'POST', body: '{}' }); await loadWorkspace(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось отключить клиента'); }
    finally { setActionBusy(false); }
  }

  const enabledCount = clients.filter(client => client.enabled).length;
  const liveTraffic = useMemo(() => {
    let rxBytes = 0;
    let txBytes = 0;
    let livePeers = 0;
    for (const result of Object.values(peerStats)) {
      for (const peer of result.items) {
        if (!peer.active_on_server) continue;
        rxBytes += peer.rx_bytes ?? 0;
        txBytes += peer.tx_bytes ?? 0;
        livePeers += 1;
      }
    }
    return { rxBytes, txBytes, livePeers };
  }, [peerStats]);
  const filteredClients = useMemo(() => clients.filter(client => {
    const term = clientSearch.toLowerCase();
    const matchesText = !term || [client.name, client.note, client.assigned_ip].some(value => value.toLowerCase().includes(term));
    const owner = containers.find(container => container.id === client.container_id);
    const matchesProtocol = protocolFilter === 'all' || owner?.protocol === protocolFilter;
    return matchesText && matchesProtocol;
  }), [clients, containers, clientSearch, protocolFilter]);

  function beginAwgEdit(container: Container) {
    let saved: Partial<AwgSettings> = {};
    try { saved = JSON.parse(container.awg_settings_json || '{}') as Partial<AwgSettings>; } catch {}
    const str = (value: unknown) => value === undefined || value === null ? '' : String(value);
    setAwgDraft({ version: saved.version ?? '2.0', jc: str(saved.jc), jmin: str(saved.jmin), jmax: str(saved.jmax), s1: str(saved.s1), s2: str(saved.s2), s3: str(saved.s3), s4: str(saved.s4), h1: str(saved.h1), h2: str(saved.h2), h3: str(saved.h3), h4: str(saved.h4), i1: str(saved.i1), i2: str(saved.i2), i3: str(saved.i3), i4: str(saved.i4), i5: str(saved.i5), content_padding_addition: str(saved.content_padding_addition), random_trailers: saved.random_trailers ?? false, disable_cookies: saved.disable_cookies ?? false });
    setContainerDraft({ name: container.name, protocol: container.protocol, endpoint: container.endpoint, listen_port: String(container.listen_port), transport: container.transport, subnet: container.subnet, dns: container.dns, mtu: String(container.mtu) });
    setEditingAwgId(container.id); setShowContainerForm(true); setSection('protocols');
  }

  function renderContainerCard(container: Container) {
    return <div key={container.id}>
      <ContainerCard container={container} clients={clients} runtimeCanManage={!!runtimeStatus?.can_manage_vpn} onStart={() => void operateInterface(container.id, 'start')} onStop={() => void operateInterface(container.id, 'stop')} onEdit={() => beginAwgEdit(container)} onProvisionKey={() => void provisionServerKey(container.id)} onProvisionHeaderKey={() => void provisionAwgHeaderProtectionKey(container.id)} onAdd={() => {
        setClientFormFor(clientFormFor === container.id ? null : container.id);
        setClientName(''); setClientNote(''); setClientExpiresAt(''); setClientTrafficLimitGb('0');
      }} />
      {clientFormFor === container.id && <form className="client-form" onSubmit={event => void createClient(event, container.id)}>
        <label>Имя устройства<input required maxLength={48} value={clientName} onChange={event => setClientName(event.target.value)} placeholder="Ноутбук, телефон…" /></label>
        <label>Заметка<input maxLength={200} value={clientNote} onChange={event => setClientNote(event.target.value)} placeholder="Необязательно" /></label>
        <label>Лимит трафика, ГиБ<input type="number" min="0" step="0.1" value={clientTrafficLimitGb} onChange={event => setClientTrafficLimitGb(event.target.value)} /></label>
        <label>Срок доступа<input type="datetime-local" value={clientExpiresAt} onChange={event => setClientExpiresAt(event.target.value)} /></label>
        <small className="muted">0 — без лимита. Учёт RX + TX; проверка и отключение выполняются сервером примерно раз в 30 секунд.</small>
        <button className="primary compact" disabled={actionBusy}>{actionBusy ? 'Создание…' : 'Создать доступ'}</button>
      </form>}
    </div>;
  }

  if (loading) return <div className="loading">Загрузка панели…</div>;
  if (error && !health) return <div className="loading error-screen"><b>Не удалось подключиться к backend</b><p>{error}</p><button className="secondary" onClick={() => { setLoading(true); setError(''); void refresh(); }}>Повторить</button></div>;

  if (setupRequired || !user) return (
    <div className="auth-shell"><div className="auth-card">
      <div className="brand auth-brand"><span className="brand-mark">A</span><div>AMNEZIA<span>PANEL</span></div></div>
      <small className="eyebrow">{setupRequired ? 'ПЕРВОНАЧАЛЬНАЯ НАСТРОЙКА' : 'ЗАЩИЩЁННЫЙ ДОСТУП'}</small>
      <h1>{setupRequired ? 'Создайте администратора' : 'Вход в панель'}</h1>
      <p className="auth-description">{setupRequired ? 'Это единственная учётная запись администратора. После создания первичная настройка будет закрыта.' : 'Войдите под учётной записью администратора.'}</p>
      <form onSubmit={submitAuth}>
        <label>Имя пользователя<input value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={32} autoComplete="username" required /></label>
        <label>Пароль<input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} maxLength={256} autoComplete={setupRequired ? 'new-password' : 'current-password'} required /></label>
        {setupRequired && <span className="field-hint">Минимум 12 символов. Используйте уникальный пароль.</span>}
        {error && <div className="form-error">{error}</div>}
        <button className="primary submit" disabled={busy}>{busy ? 'Подождите…' : setupRequired ? 'Создать администратора' : 'Войти'}</button>
      </form>
      <div className="auth-foot">ARGON2ID · SESSION COOKIE HTTPONLY · SQLITE</div>
    </div></div>
  );

  const nav = (id: Section, label: string, icon: string) => (
    <button className={section === id ? 'nav-item active' : 'nav-item'} onClick={() => setSection(id)}>
      <span className="nav-icon">{icon}</span>{label}
      {id === 'clients' && <span className="nav-count">{clients.length}</span>}
    </button>
  );

  return (
    <div className="shell">
      <aside>
        <div className="brand"><span className="brand-mark">A</span><div>AMNEZIA<span>PANEL</span></div></div>
        <div className="side-caption">WORKSPACE</div>
        <nav>
          {nav('overview', 'Обзор', '⌂')}
          {nav('protocols', 'Протоколы', '⌁')}
          {nav('clients', 'Клиенты', '◉')}
        </nav>
        <div className="side-runtime">
          <span className={runtimeStatus?.available ? 'runtime-dot online' : 'runtime-dot'} />
          <div><b>{runtimeStatus?.engine ?? 'Runtime'}</b><small>{runtimeStatus?.available ? 'Сервис доступен' : 'Нет соединения'}</small></div>
        </div>
        <div className="side-foot">CONTROL PLANE <span>v0.4.0 · {runtimeStatus?.mode?.toUpperCase() ?? 'PREVIEW'}</span></div>
      </aside>
      <main>
        <header>
          <div><small>AMNEZIA PANEL / {section.toUpperCase()}</small><h1>{section === 'overview' ? 'Центр управления' : section === 'protocols' ? 'Протоколы и профили' : 'Управление клиентами'}</h1></div>
          <div className="header-actions"><span className="user-pill">{user}</span><button className="secondary" onClick={() => void refresh()}>↻ Обновить</button><button className="secondary" onClick={logout}>Выйти</button></div>
        </header>
        {error && <div className="form-error global-error">{error}<button onClick={() => setError('')}>Закрыть</button></div>}
        {issuedToken && <section className="token-notice"><b>Токен доступа создан</b><p>Токен показывается один раз. Получить актуальный client.conf можно через GET /api/subscriptions/config, передав токен заголовком Authorization: Bearer. Токен не помещается в URL и не хранится в открытом виде на сервере.</p><code>{issuedToken}</code><div className="card-actions"><button className="primary compact" disabled={actionBusy} onClick={() => void downloadSubscriptionConfig()}>{actionBusy ? 'Подготовка…' : 'Скачать client.conf'}</button><button className="secondary compact" onClick={() => setIssuedToken('')}>Скрыть</button></div></section>}

        {section === 'overview' && <>
          <section className="hero-panel">
            <div><span className="hero-kicker">NETWORK OPERATIONS</span><h2>Вся VPN-инфраструктура — в одном месте.</h2><p>Состояние сервисов, конфигурации и доступы клиентов. Без фиктивной телеметрии.</p></div>
            <div className="hero-mark">AWG<span>CONTROL</span></div>
          </section>
          <section className="stats">
            <article><label>КОНФИГУРАЦИИ</label><strong>{containers.length.toString().padStart(2, '0')}</strong><span>Профилей в локальной БД</span></article>
            <article><label>КЛИЕНТЫ</label><strong>{clients.length.toString().padStart(2, '0')}</strong><span>{enabledCount} включено · {clients.length - enabledCount} отключено</span></article>
            <article><label>ТРАФИК RX / TX</label><strong>{runtimeStatus?.mode === 'host' && Object.keys(peerStats).length ? formatBytes(liveTraffic.rxBytes + liveTraffic.txBytes) : '—'}</strong><span>{runtimeStatus?.mode === 'host' && Object.keys(peerStats).length ? `RX ${formatBytes(liveTraffic.rxBytes)} · TX ${formatBytes(liveTraffic.txBytes)} · ${liveTraffic.livePeers} активных пиров` : 'Доступно для запущенных host-интерфейсов'}</span></article>
            <article><label>API / RUNTIME</label><strong className={health?.ok ? 'ok' : 'warn'}>{health?.ok ? 'ONLINE' : '—'}</strong><span>{runtimeStatus?.engine ?? '—'} · {runtimeStatus?.available ? 'доступен' : 'недоступен'}</span></article>
          </section>
          <section className="runtime-banner">
            <div className="runtime-symbol">!</div><div><b>{runtimeStatus?.mode === 'preview' ? 'Рабочий режим: Preview' : 'Состояние runtime'}</b><p>{runtimeStatus?.message ?? 'Статус runtime пока недоступен.'}</p><p>Шифрование ключей WireGuard: {runtimeStatus?.wireguard_master_key_configured ? 'мастер-ключ настроен' : 'мастер-ключ не задан — создание WG/AWG-клиентов недоступно'}</p></div>
            <span className="mode-chip">{runtimeStatus?.can_manage_vpn ? 'VPN CONTROL' : 'METADATA ONLY'}</span>
          </section>
          <section className="panel">
            <div className="panel-head"><div><small>INFRASTRUCTURE</small><h2>VPN-конфигурации</h2></div><button className="primary compact" onClick={() => {setSection('protocols');setShowContainerForm(true);}}>＋ Добавить сервер</button></div>
            {containers.length === 0 ? <div className="empty"><div className="empty-icon">⌁</div><b>Пока нет VPN-серверов</b><p>Создай первую конфигурацию и настрой параметры протокола. Пока она хранится в Preview и не запускает VPN.</p><button className="primary compact" onClick={() => {setSection('protocols');setShowContainerForm(true);}}>Создать конфигурацию</button></div> :
              <div className="container-list">{containers.slice(0, 4).map(container => renderContainerCard(container))}</div>}
          </section>
        </>}

        {section === 'protocols' && <section className="panel">
          <div className="panel-head"><div><small>PROTOCOL LAB</small><h2>Серверные профили</h2></div><button className="primary compact" onClick={() => { setShowContainerForm(v => !v); setEditingAwgId(null); }}>{showContainerForm ? 'Закрыть редактор' : '＋ Новый профиль'}</button></div>
          <p className="section-lead">Параметры сохраняются в базе и проходят серверную валидацию. Запуск и остановка доступны только в Linux host runtime при явно включённом HOST_RUNTIME_ALLOW_MUTATIONS.</p>
          {showContainerForm && <form className="editor-form" onSubmit={createContainer}>
            <div className="form-section-title">{editingAwgId ? 'РЕДАКТИРОВАНИЕ AWG · БАЗОВЫЕ ПАРАМЕТРЫ НЕ ИЗМЕНЯЮТСЯ' : '01 / БАЗОВЫЕ ПАРАМЕТРЫ'}</div>
            <label>Название<input required minLength={2} maxLength={48} disabled={!!editingAwgId} value={containerDraft.name} onChange={e => setContainerDraft({...containerDraft,name:e.target.value})} placeholder="Например, Finland AWG" /></label>
            <label>Протокол<select disabled={!!editingAwgId} value={containerDraft.protocol} onChange={e => { const protocol = e.target.value; setContainerDraft({...containerDraft,protocol,transport: protocol === 'openvpn-cloak' ? 'tcp' : 'udp'}); }}><option value="amnezia-awg">AmneziaWG</option><option value="wireguard">WireGuard</option><option value="openvpn">OpenVPN</option><option value="openvpn-cloak">OpenVPN + Cloak</option></select></label>
            <label>Домен / IP сервера<input required disabled={!!editingAwgId} value={containerDraft.endpoint} onChange={e => setContainerDraft({...containerDraft,endpoint:e.target.value})} placeholder="vpn.example.com" /></label>
            <label>Порт<input type="number" min="1" max="65535" required disabled={!!editingAwgId} value={containerDraft.listen_port} onChange={e => setContainerDraft({...containerDraft,listen_port:e.target.value})} /></label>
            <label>Транспорт<select disabled={!!editingAwgId} value={containerDraft.transport} onChange={e => setContainerDraft({...containerDraft,transport:e.target.value})}><option value="udp" disabled={containerDraft.protocol === 'openvpn-cloak'}>UDP</option><option value="tcp" disabled={containerDraft.protocol === 'amnezia-awg' || containerDraft.protocol === 'wireguard'}>TCP</option></select></label>
            <label>Подсеть IPv4<input required disabled={!!editingAwgId} value={containerDraft.subnet} onChange={e => setContainerDraft({...containerDraft,subnet:e.target.value})} /></label>
            <label>DNS-сервер<input required disabled={!!editingAwgId} value={containerDraft.dns} onChange={e => setContainerDraft({...containerDraft,dns:e.target.value})} /></label>
            <label>MTU<input type="number" min="576" max="9000" required disabled={!!editingAwgId} value={containerDraft.mtu} onChange={e => setContainerDraft({...containerDraft,mtu:e.target.value})} /></label>
            {containerDraft.protocol === 'amnezia-awg' && <>
              <div className="form-section-title awg-title">02 / AMNEZIAWG OBFUSCATION STUDIO <span>ADVANCED</span></div>
              <div className="awg-intro">Junk packets, padding и magic headers меняют сигнатуру трафика. Клиентские и серверные значения должны быть согласованы. Это профиль настроек, не гарантия обхода DPI.</div>
              <label>Версия AWG<select value={awgDraft.version} onChange={e => setAwgDraft({...awgDraft,version:e.target.value})}><option value="1.5">Legacy 1.5</option><option value="2.0">AmneziaWG 2.0</option><option value="3.1">AmneziaWG 3.1</option></select></label>
              <label>Jc · количество junk-пакетов<input type="number" min="1" max="128" value={awgDraft.jc} onChange={e => setAwgDraft({...awgDraft,jc:e.target.value})} /></label>
              <label>Jmin · минимум байт<input type="number" min="1" max="1279" value={awgDraft.jmin} onChange={e => setAwgDraft({...awgDraft,jmin:e.target.value})} /></label>
              <label>Jmax · максимум байт<input type="number" min="2" max="1280" value={awgDraft.jmax} onChange={e => setAwgDraft({...awgDraft,jmax:e.target.value})} /></label>
              <label>S1 · initiation padding<input type="number" min="0" max="1132" value={awgDraft.s1} onChange={e => setAwgDraft({...awgDraft,s1:e.target.value})} /></label>
              <label>S2 · response padding<input type="number" min="0" max="1188" value={awgDraft.s2} onChange={e => setAwgDraft({...awgDraft,s2:e.target.value})} /></label>
              {awgDraft.version !== '1.5' && <>
                <label>S3 · cookie padding<input type="number" min="0" max="1280" value={awgDraft.s3} onChange={e => setAwgDraft({...awgDraft,s3:e.target.value})} /></label>
                <label>S4 · data padding<input type="number" min="0" max="1280" value={awgDraft.s4} onChange={e => setAwgDraft({...awgDraft,s4:e.target.value})} /></label>
              </>}
              <div className="form-section-title">03 / MAGIC HEADERS</div>
              {(['h1','h2','h3','h4'] as const).map((key, index) => <label key={key}>H{index + 1} · {['init','response','cookie','data'][index]}<input value={awgDraft[key]} onChange={e => setAwgDraft({...awgDraft,[key]:e.target.value})} placeholder="Например, 100000-200000" /></label>)}
              <div className="form-section-title">04 / CPS SIGNATURE CHAIN</div>
              {(['i1','i2','i3','i4','i5'] as const).map((key, index) => <label key={key}>I{index + 1} · signature<input maxLength={1024} value={awgDraft[key]} onChange={e => setAwgDraft({...awgDraft,[key]:e.target.value})} placeholder="<r 128> или <b 0x...>" /></label>)}
              {awgDraft.version === '3.1' && <>
                <div className="form-section-title">05 / TRANSPORT PROTECTION · 3.1</div>
                <label>ContentPaddingAddition<input type="text" inputMode="numeric" value={awgDraft.content_padding_addition} onChange={e => setAwgDraft({...awgDraft,content_padding_addition:e.target.value})} placeholder="0–65535 или диапазон, например 16-32" /></label>
                <label className="check-label"><input type="checkbox" checked={awgDraft.random_trailers} onChange={e => setAwgDraft({...awgDraft,random_trailers:e.target.checked})} /> RandomTrailers</label>
                <label className="check-label"><input type="checkbox" checked={awgDraft.disable_cookies} onChange={e => setAwgDraft({...awgDraft,disable_cookies:e.target.checked})} /> DisableCookies</label>
              </>}
              <div className="awg-footnote">H1–H4 могут быть числами или диапазонами без пересечений. При HeaderProtectionKey официальная рекомендация — H1=1, H2=2, H3=3, H4=4. I1–I5 — CPS-цепочка; суммарно не более 3000 символов. Для AWG 3.1 здесь хранятся флаги RandomTrailers / DisableCookies и ContentPaddingAddition. HeaderProtectionKey можно создать для AWG 3.1 после установки S1–S4 не меньше 12; он хранится только в зашифрованном виде и не показывается в UI.</div>
            </>}
            <div className="form-actions"><span>СОХРАНЕНИЕ ПРОФИЛЯ · Не запускает VPN; параметры будут применены при следующем старте остановленного интерфейса.</span><button className="primary" disabled={actionBusy}>{actionBusy ? 'Сохранение…' : editingAwgId ? 'Сохранить новую ревизию AWG' : 'Создать профиль'}</button></div>
          </form>}
          {containers.length === 0 ? <div className="empty small-empty"><b>Нет профилей</b><p>Создай конфигурацию протокола, чтобы начать.</p></div> :
            <div className="container-list">{containers.map(container => renderContainerCard(container))}</div>}
        </section>}

        {section === 'clients' && <section className="panel">
          <div className="panel-head"><div><small>ACCESS MANAGEMENT</small><h2>Клиенты и устройства</h2></div><span className="muted">{enabledCount} из {clients.length} включено</span></div>
          <div className="filter-bar"><input value={clientSearch} onChange={e => setClientSearch(e.target.value)} placeholder="Поиск по имени, заметке или IP…" /><select value={protocolFilter} onChange={e => setProtocolFilter(e.target.value)}><option value="all">Все протоколы</option>{Object.entries(protocolNames).map(([key,label]) => <option key={key} value={key}>{label}</option>)}</select></div>
          {runtimeStatus?.mode === 'host' && containers.some(container => container.status === 'running') && <p className="section-lead">Активные WireGuard / AmneziaWG peers отображаются с live-статистикой. Отзыв доступа удаляет peer из работающего интерфейса без перезапуска. Добавление устройств и автоматическое применение срока действия пока требуют отдельной синхронизации.</p>}
          {filteredClients.length === 0 ? <div className="empty small-empty"><b>{clients.length ? 'Ничего не найдено' : 'Клиентов пока нет'}</b><p>{clients.length ? 'Измени поисковый запрос или фильтр.' : 'Добавь устройство в карточке серверного профиля.'}</p></div> :
            <div className="client-table"><div className="client-row client-header"><span>УСТРОЙСТВО</span><span>IP-АДРЕС</span><span>ПРОТОКОЛ</span><span>ДОСТУП</span><span>ТРАФИК / HANDSHAKE</span><span>ДЕЙСТВИЕ</span></div>
              {filteredClients.map(client => {
                const owner = containers.find(c => c.id === client.container_id);
                const canRevoke = !!owner && !owner.runtime_operation && ((owner.status === 'preview' || owner.status === 'stopped') || (owner.status === 'running' && runtimeStatus?.mode === 'host' && runtimeStatus.can_manage_vpn && (owner.protocol === 'wireguard' || owner.protocol === 'amnezia-awg')));
                const livePeer = owner ? peerStats[owner.id]?.items.find(item => item.client_id === client.id) : undefined;
                return <div className="client-row" key={client.id}>
                  <span><b>{client.name}</b><small>{client.note || owner?.name || 'Без заметки'}</small>{client.wireguard_public_key && <small className="public-key-line"><code title={client.wireguard_public_key}>{client.wireguard_public_key.slice(0, 18)}…</code><button className="text-action" onClick={() => void navigator.clipboard.writeText(client.wireguard_public_key!)}>Копировать public key</button>{client.enabled && <a className="text-action" href={`/api/clients/${client.id}/config`} download="client.conf">Скачать .conf</a>}</small>}</span>
                  <code>{client.assigned_ip}</code><span className="protocol-cell">{protocolNames[owner?.protocol ?? ''] ?? '—'}</span>
                  <span className={client.enabled ? 'status-enabled' : 'status-disabled'}>{client.enabled ? '● Включён' : '○ Отключён'}</span>
                  <span className="peer-activity">{owner?.status === 'running' && runtimeStatus?.mode === 'host' ? livePeer ? <><small>{livePeer.active_on_server ? `RX ${formatBytes(livePeer.rx_bytes)} · TX ${formatBytes(livePeer.tx_bytes)}` : 'Не найден на интерфейсе'}</small><small>{livePeer.traffic_limit_bytes > 0 ? `Лимит ${formatBytes(livePeer.traffic_used_bytes)} / ${formatBytes(livePeer.traffic_limit_bytes)}` : `Учтено ${formatBytes(livePeer.traffic_used_bytes)} · без лимита`}</small><small>{formatHandshake(livePeer.latest_handshake_unix)}{livePeer.expired ? ' · ИСТЁК' : ''}</small></> : <small>Получение статистики…</small> : <small>—</small>}</span>
                  <span>{client.enabled && <button className="danger compact" disabled={actionBusy || !canRevoke} title={canRevoke ? (owner?.status === 'running' ? 'Удалить peer из работающего интерфейса' : 'Отозвать доступ') : 'Дождись завершения операции или останови VPN-профиль'} onClick={() => void disableClient(client.id)}>Отозвать</button>}</span>
                </div>;
              })}
            </div>}
        </section>}
        <footer>AMNEZIA PANEL <span>RUST / AXUM · REACT / TYPESCRIPT · {runtimeStatus?.mode?.toUpperCase() ?? 'PREVIEW'}</span></footer>
      </main>
    </div>
  );
}

function ContainerCard({ container, clients, runtimeCanManage, onStart, onStop, onAdd, onEdit, onProvisionKey, onProvisionHeaderKey }: { container: Container; clients: Client[]; runtimeCanManage: boolean; onStart: () => void; onStop: () => void; onAdd: () => void; onEdit: () => void; onProvisionKey: () => void; onProvisionHeaderKey: () => void }) {
  const related = clients.filter(client => client.container_id === container.id);
  let awg: Partial<AwgSettings> = {};
  try { awg = JSON.parse(container.awg_settings_json || '{}') as Partial<AwgSettings>; } catch {}
  const profileStopped = (container.status === 'preview' || container.status === 'stopped') && !container.runtime_operation;
  const canAddClient = profileStopped || (
    container.status === 'running' && !container.runtime_operation && runtimeCanManage &&
    (container.protocol === 'wireguard' || container.protocol === 'amnezia-awg')
  );
  const stateLabel = container.status === 'running' && container.runtime_operation
    ? 'SYNCING'
    : container.runtime_operation === 'start' ? 'STARTING'
      : container.runtime_operation === 'stop' ? 'STOPPING'
        : container.status.toUpperCase();
  return <article className="container-card">
    <div className="container-top"><div><b>{container.name}</b><span className="protocol-tag">{protocolNames[container.protocol] ?? container.protocol}</span></div><span className={`preview-tag ${container.runtime_operation ? 'status-starting' : container.status === 'running' ? 'status-running' : container.status === 'error' ? 'status-error' : ''}`}>{stateLabel}</span></div>
    {container.status === 'running' && <p className="muted small-note">{runtimeCanManage ? 'Новые WireGuard / AmneziaWG peer добавляются сразу без перезапуска; отзыв доступа тоже применяется live. Истечение срока синхронизируется автоматически.' : 'Для live-изменения peer требуется включённый Linux Host Runtime с разрешёнными операциями.'}</p>}
    <div className="container-meta"><span>⌖ {container.endpoint}:{container.listen_port}/{container.transport}</span><span>▦ {container.subnet}</span><span>DNS {container.dns}</span><span>MTU {container.mtu}</span></div>
    {container.protocol === 'amnezia-awg' && <div className="awg-summary"><span>AWG {awg.version ?? '—'}</span><span>Jc {awg.jc ?? '—'}</span><span>Junk {awg.jmin ?? '—'}–{awg.jmax ?? '—'} B</span><span>Headers {[awg.h1,awg.h2,awg.h3,awg.h4].filter(Boolean).length}/4</span></div>}
    {container.protocol === 'amnezia-awg' && awg.version === '3.1' && <div className="server-key-row"><small>HEADER PROTECTION</small>{container.awg_header_protection_key_configured ? <span className="status-enabled">● Ключ создан · зашифрован</span> : [awg.s1,awg.s2,awg.s3,awg.s4].every(value => typeof value === 'number' && value >= 12) ? <button className="secondary compact" disabled={!profileStopped} onClick={onProvisionHeaderKey}>＋ Создать HeaderProtectionKey</button> : <span className="muted">Для ключа установи S1–S4 ≥ 12 и сохрани профиль</span>}</div>}
    {(container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && <div className="server-key-row">{container.wireguard_server_public_key ? <><small>SERVER PUBLIC KEY</small><code title={container.wireguard_server_public_key}>{container.wireguard_server_public_key.slice(0, 22)}…</code><button className="text-action" onClick={() => void navigator.clipboard.writeText(container.wireguard_server_public_key!)}>Копировать</button></> : <><small>SERVER KEY NOT PROVISIONED</small><button className="secondary compact" disabled={!profileStopped} onClick={onProvisionKey}>＋ Создать ключ сервера</button></>}</div>}
    <div className="container-bottom"><span>{related.length} устройств · ревизия {container.revision}</span><div className="card-actions">{(container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && container.wireguard_server_public_key && <a className="text-action" href={`/api/containers/${container.id}/server-config`} download="server.conf">Скачать server.conf</a>}{runtimeCanManage && (container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && container.runtime_operation ? <span className="muted">{container.status === 'running' ? 'Синхронизация…' : container.runtime_operation === 'start' ? 'Запуск…' : 'Остановка…'}</span> : runtimeCanManage && (container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && (container.status === 'running' || container.status === 'error') ? <button className="danger compact" onClick={onStop}>Остановить VPN</button> : runtimeCanManage && (container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && profileStopped ? <button className="primary compact" disabled={!container.wireguard_server_public_key} onClick={onStart}>Запустить VPN</button> : null}{container.protocol === 'amnezia-awg' && <button className="secondary compact" disabled={!profileStopped} onClick={onEdit}>Настроить AWG</button>}<button className="secondary compact" disabled={!canAddClient || ((container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && !container.wireguard_server_public_key)} title={!canAddClient ? 'Для работающего профиля требуется доступный Linux Host Runtime без выполняющейся операции' : ''} onClick={onAdd}>＋ Добавить устройство</button></div></div>
  </article>;
}

createRoot(document.getElementById('root')!).render(<App />);
