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
  content_padding_addition?: number; random_trailers?: boolean; disable_cookies?: boolean;
};
type Container = {
  id: string; name: string; protocol: string; status: string; endpoint: string;
  listen_port: number; transport: string; subnet: string; dns: string; mtu: number;
  revision: number; awg_settings_json: string; wireguard_server_public_key?: string | null;
};
type Client = {
  id: string; container_id: string; name: string; note: string; assigned_ip: string;
  enabled: boolean; traffic_limit_bytes: number; traffic_used_bytes: number; expires_at: string | null;
  wireguard_public_key?: string | null;
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
      content_padding_addition: awgDraft.version === '3.1' ? numeric(awgDraft.content_padding_addition) : undefined,
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

  async function provisionServerKey(containerId: string) {
    setActionBusy(true); setError('');
    try {
      await api('/api/containers/' + containerId + '/wireguard-server-key', { method: 'POST', body: '{}' });
      await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать ключ сервера'); }
    finally { setActionBusy(false); }
  }

  async function createClient(event: FormEvent, containerId: string) {
    event.preventDefault(); setActionBusy(true); setError(''); setIssuedToken('');
    try {
      const result = await api<CreatedClient>(`/api/containers/${containerId}/clients`, {
        method: 'POST', body: JSON.stringify({ name: clientName, note: clientNote }),
      });
      setIssuedToken(result.subscription_token); setClientName(''); setClientNote('');
      setClientFormFor(null); await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать клиента'); }
    finally { setActionBusy(false); }
  }

  async function disableClient(clientId: string) {
    setActionBusy(true); setError('');
    try { await api(`/api/clients/${clientId}/disable`, { method: 'POST', body: '{}' }); await loadWorkspace(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось отключить клиента'); }
    finally { setActionBusy(false); }
  }

  const enabledCount = clients.filter(client => client.enabled).length;
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
      <ContainerCard container={container} clients={clients} onEdit={() => beginAwgEdit(container)} onProvisionKey={() => void provisionServerKey(container.id)} onAdd={() => {
        setClientFormFor(clientFormFor === container.id ? null : container.id);
        setClientName(''); setClientNote('');
      }} />
      {clientFormFor === container.id && <form className="client-form" onSubmit={event => void createClient(event, container.id)}>
        <label>Имя устройства<input required maxLength={48} value={clientName} onChange={event => setClientName(event.target.value)} placeholder="Ноутбук, телефон…" /></label>
        <label>Заметка<input maxLength={200} value={clientNote} onChange={event => setClientNote(event.target.value)} placeholder="Необязательно" /></label>
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
        <div className="side-foot">CONTROL PLANE <span>v0.3.0 · PREVIEW</span></div>
      </aside>
      <main>
        <header>
          <div><small>AMNEZIA PANEL / {section.toUpperCase()}</small><h1>{section === 'overview' ? 'Центр управления' : section === 'protocols' ? 'Протоколы и профили' : 'Управление клиентами'}</h1></div>
          <div className="header-actions"><span className="user-pill">{user}</span><button className="secondary" onClick={() => void refresh()}>↻ Обновить</button><button className="secondary" onClick={logout}>Выйти</button></div>
        </header>
        {error && <div className="form-error global-error">{error}<button onClick={() => setError('')}>Закрыть</button></div>}
        {issuedToken && <section className="token-notice"><b>Токен доступа создан</b><p>Показывается один раз. Рабочая ссылка подписки появится после подключения VPN runtime.</p><code>{issuedToken}</code><button className="secondary compact" onClick={() => setIssuedToken('')}>Скрыть</button></section>}

        {section === 'overview' && <>
          <section className="hero-panel">
            <div><span className="hero-kicker">NETWORK OPERATIONS</span><h2>Вся VPN-инфраструктура — в одном месте.</h2><p>Состояние сервисов, конфигурации и доступы клиентов. Без фиктивной телеметрии.</p></div>
            <div className="hero-mark">AWG<span>CONTROL</span></div>
          </section>
          <section className="stats">
            <article><label>КОНФИГУРАЦИИ</label><strong>{containers.length.toString().padStart(2, '0')}</strong><span>Профилей в локальной БД</span></article>
            <article><label>КЛИЕНТЫ</label><strong>{clients.length.toString().padStart(2, '0')}</strong><span>{enabledCount} включено · {clients.length - enabledCount} отключено</span></article>
            <article><label>ТРАФИК RX / TX</label><strong>—</strong><span>Сбор статистики ещё не подключён</span></article>
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
          <p className="section-lead">Параметры сохраняются в базе и проходят серверную валидацию. Фактический запуск интерфейса VPN пока не включён.</p>
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
              {(['i1','i2','i3','i4','i5'] as const).map((key, index) => <label key={key}>I{index + 1} · signature<input value={awgDraft[key]} onChange={e => setAwgDraft({...awgDraft,[key]:e.target.value})} placeholder="<r 128> или <b 0x...>" /></label>)}
              {awgDraft.version === '3.1' && <>
                <div className="form-section-title">05 / TRANSPORT PROTECTION · 3.1</div>
                <label>ContentPaddingAddition<input type="number" min="0" value={awgDraft.content_padding_addition} onChange={e => setAwgDraft({...awgDraft,content_padding_addition:e.target.value})} placeholder="По умолчанию" /></label>
                <label className="check-label"><input type="checkbox" checked={awgDraft.random_trailers} onChange={e => setAwgDraft({...awgDraft,random_trailers:e.target.checked})} /> RandomTrailers</label>
                <label className="check-label"><input type="checkbox" checked={awgDraft.disable_cookies} onChange={e => setAwgDraft({...awgDraft,disable_cookies:e.target.checked})} /> DisableCookies</label>
              </>}
              <div className="awg-footnote">H1–H4 могут быть числами или диапазонами без пересечений. I1–I5 — CPS-цепочка; формат проверяется базово. Для AWG 3.1 здесь хранятся флаги RandomTrailers / DisableCookies и ContentPaddingAddition. HeaderProtectionKey пока не генерируется и не хранится: для него сначала нужен безопасный жизненный цикл секретов.</div>
            </>}
            <div className="form-actions"><span>PREVIEW · Сохранение не запускает VPN и не применяет настройки к серверу.</span><button className="primary" disabled={actionBusy}>{actionBusy ? 'Сохранение…' : editingAwgId ? 'Сохранить новую ревизию AWG' : 'Создать профиль'}</button></div>
          </form>}
          {containers.length === 0 ? <div className="empty small-empty"><b>Нет профилей</b><p>Создай конфигурацию протокола, чтобы начать.</p></div> :
            <div className="container-list">{containers.map(container => renderContainerCard(container))}</div>}
        </section>}

        {section === 'clients' && <section className="panel">
          <div className="panel-head"><div><small>ACCESS MANAGEMENT</small><h2>Клиенты и устройства</h2></div><span className="muted">{enabledCount} из {clients.length} включено</span></div>
          <div className="filter-bar"><input value={clientSearch} onChange={e => setClientSearch(e.target.value)} placeholder="Поиск по имени, заметке или IP…" /><select value={protocolFilter} onChange={e => setProtocolFilter(e.target.value)}><option value="all">Все протоколы</option>{Object.entries(protocolNames).map(([key,label]) => <option key={key} value={key}>{label}</option>)}</select></div>
          {filteredClients.length === 0 ? <div className="empty small-empty"><b>{clients.length ? 'Ничего не найдено' : 'Клиентов пока нет'}</b><p>{clients.length ? 'Измени поисковый запрос или фильтр.' : 'Добавь устройство в карточке серверного профиля.'}</p></div> :
            <div className="client-table"><div className="client-row client-header"><span>УСТРОЙСТВО</span><span>IP-АДРЕС</span><span>ПРОТОКОЛ</span><span>ДОСТУП</span><span>ДЕЙСТВИЕ</span></div>
              {filteredClients.map(client => {
                const owner = containers.find(c => c.id === client.container_id);
                return <div className="client-row" key={client.id}>
                  <span><b>{client.name}</b><small>{client.note || owner?.name || 'Без заметки'}</small>{client.wireguard_public_key && <small className="public-key-line"><code title={client.wireguard_public_key}>{client.wireguard_public_key.slice(0, 18)}…</code><button className="text-action" onClick={() => void navigator.clipboard.writeText(client.wireguard_public_key!)}>Копировать public key</button></small>}</span>
                  <code>{client.assigned_ip}</code><span className="protocol-cell">{protocolNames[owner?.protocol ?? ''] ?? '—'}</span>
                  <span className={client.enabled ? 'status-enabled' : 'status-disabled'}>{client.enabled ? '● Включён' : '○ Отключён'}</span>
                  <span>{client.enabled && <button className="danger compact" disabled={actionBusy} onClick={() => void disableClient(client.id)}>Отозвать</button>}</span>
                </div>;
              })}
            </div>}
        </section>}
        <footer>AMNEZIA PANEL <span>RUST / AXUM · REACT / TYPESCRIPT · {runtimeStatus?.mode?.toUpperCase() ?? 'PREVIEW'}</span></footer>
      </main>
    </div>
  );
}

function ContainerCard({ container, clients, onAdd, onEdit, onProvisionKey }: { container: Container; clients: Client[]; onAdd: () => void; onEdit: () => void; onProvisionKey: () => void }) {
  const related = clients.filter(client => client.container_id === container.id);
  let awg: Partial<AwgSettings> = {};
  try { awg = JSON.parse(container.awg_settings_json || '{}') as Partial<AwgSettings>; } catch {}
  return <article className="container-card">
    <div className="container-top"><div><b>{container.name}</b><span className="protocol-tag">{protocolNames[container.protocol] ?? container.protocol}</span></div><span className="preview-tag">PREVIEW</span></div>
    <div className="container-meta"><span>⌖ {container.endpoint}:{container.listen_port}/{container.transport}</span><span>▦ {container.subnet}</span><span>DNS {container.dns}</span><span>MTU {container.mtu}</span></div>
    {container.protocol === 'amnezia-awg' && <div className="awg-summary"><span>AWG {awg.version ?? '—'}</span><span>Jc {awg.jc ?? '—'}</span><span>Junk {awg.jmin ?? '—'}–{awg.jmax ?? '—'} B</span><span>Headers {[awg.h1,awg.h2,awg.h3,awg.h4].filter(Boolean).length}/4</span></div>}
    {(container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && <div className="server-key-row">{container.wireguard_server_public_key ? <><small>SERVER PUBLIC KEY</small><code title={container.wireguard_server_public_key}>{container.wireguard_server_public_key.slice(0, 22)}…</code><button className="text-action" onClick={() => void navigator.clipboard.writeText(container.wireguard_server_public_key!)}>Копировать</button></> : <><small>SERVER KEY NOT PROVISIONED</small><button className="secondary compact" onClick={onProvisionKey}>＋ Создать ключ сервера</button></>}</div>}
    <div className="container-bottom"><span>{related.length} устройств · ревизия {container.revision}</span><div className="card-actions">{container.protocol === 'amnezia-awg' && <button className="secondary compact" onClick={onEdit}>Настроить AWG</button>}<button className="secondary compact" disabled={(container.protocol === 'amnezia-awg' || container.protocol === 'wireguard') && !container.wireguard_server_public_key} onClick={onAdd}>＋ Добавить устройство</button></div></div>
  </article>;
}

createRoot(document.getElementById('root')!).render(<App />);
