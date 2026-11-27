import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

type SetupStatus = { setup_required: boolean };
type AuthResponse = { authenticated: boolean; username: string | null };
type Health = { ok: boolean; version: string; runtime: string };
type Container = {
  id: string; name: string; protocol: string; status: string; endpoint: string;
  listen_port: number; transport: string; subnet: string; dns: string; mtu: number; revision: number;
};
type Client = {
  id: string; container_id: string; name: string; note: string; assigned_ip: string;
  enabled: boolean; traffic_limit_bytes: number; traffic_used_bytes: number; expires_at: string | null;
};
type ListResponse<T> = { items: T[] };
type CreatedClient = { item: Client; subscription_token: string; notice: string };

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
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [containers, setContainers] = useState<Container[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [showContainerForm, setShowContainerForm] = useState(false);
  const [clientFormFor, setClientFormFor] = useState<string | null>(null);
  const [issuedToken, setIssuedToken] = useState('');
  const [containerDraft, setContainerDraft] = useState({
    name: '', protocol: 'amnezia-awg', endpoint: '', listen_port: '443',
    transport: 'udp', subnet: '10.66.0.0/24', dns: '1.1.1.1', mtu: '1280',
  });
  const [clientName, setClientName] = useState('');
  const [clientNote, setClientNote] = useState('');
  const [actionBusy, setActionBusy] = useState(false);

  async function loadWorkspace() {
    const [containerData, clientData] = await Promise.all([
      api<ListResponse<Container>>('/api/containers'),
      api<ListResponse<Client>>('/api/clients'),
    ]);
    setContainers(containerData.items);
    setClients(clientData.items);
  }

  async function refresh() {
    try {
      const [setup, service] = await Promise.all([
        api<SetupStatus>('/api/setup/status'),
        api<Health>('/api/health'),
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
      setUser(result.username);
      setPassword('');
      setSetupRequired(false);
      await loadWorkspace();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Не удалось выполнить запрос');
    } finally { setBusy(false); }
  }

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); }
    finally { setUser(null); setContainers([]); setClients([]); }
  }

  async function createContainer(event: FormEvent) {
    event.preventDefault(); setActionBusy(true); setError('');
    try {
      await api('/api/containers', {
        method: 'POST',
        body: JSON.stringify({
          ...containerDraft,
          listen_port: Number(containerDraft.listen_port),
          mtu: Number(containerDraft.mtu),
        }),
      });
      setShowContainerForm(false);
      setContainerDraft({ name: '', protocol: 'amnezia-awg', endpoint: '', listen_port: '443', transport: 'udp', subnet: '10.66.0.0/24', dns: '1.1.1.1', mtu: '1280' });
      await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать конфигурацию'); }
    finally { setActionBusy(false); }
  }

  async function createClient(event: FormEvent, containerId: string) {
    event.preventDefault(); setActionBusy(true); setError(''); setIssuedToken('');
    try {
      const result = await api<CreatedClient>(`/api/containers/${containerId}/clients`, {
        method: 'POST', body: JSON.stringify({ name: clientName, note: clientNote }),
      });
      setIssuedToken(result.subscription_token);
      setClientName(''); setClientNote('');
      setClientFormFor(null);
      await loadWorkspace();
    } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось создать клиента'); }
    finally { setActionBusy(false); }
  }

  async function disableClient(clientId: string) {
    setActionBusy(true); setError('');
    try { await api(`/api/clients/${clientId}/disable`, { method: 'POST', body: '{}' }); await loadWorkspace(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Не удалось отключить клиента'); }
    finally { setActionBusy(false); }
  }

  const clientCount = clients.length;
  const enabledCount = clients.filter(client => client.enabled).length;

  if (loading) return <div className="loading">Загрузка панели…</div>;

  if (error && !health) return (
    <div className="loading error-screen">
      <b>Не удалось подключиться к backend</b><p>{error}</p>
      <button className="secondary" onClick={() => { setLoading(true); setError(''); void refresh(); }}>Повторить</button>
    </div>
  );

  if (setupRequired || !user) return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="brand auth-brand"><span className="brand-mark">A</span><div>AMNEZIA<span>PANEL</span></div></div>
        <small className="eyebrow">{setupRequired ? 'ПЕРВОНАЧАЛЬНАЯ НАСТРОЙКА' : 'ЗАЩИЩЁННЫЙ ДОСТУП'}</small>
        <h1>{setupRequired ? 'Создайте администратора' : 'Вход в панель'}</h1>
        <p className="auth-description">{setupRequired
          ? 'Это единственная учётная запись администратора. После создания первичная настройка будет закрыта.'
          : 'Войдите под учётной записью администратора.'}</p>
        <form onSubmit={submitAuth}>
          <label>Имя пользователя<input value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={32} autoComplete="username" required /></label>
          <label>Пароль<input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} maxLength={256} autoComplete={setupRequired ? 'new-password' : 'current-password'} required /></label>
          {setupRequired && <span className="field-hint">Минимум 12 символов. Используйте уникальный пароль.</span>}
          {error && <div className="form-error">{error}</div>}
          <button className="primary submit" disabled={busy}>{busy ? 'Подождите…' : setupRequired ? 'Создать администратора' : 'Войти'}</button>
        </form>
        <div className="auth-foot">ARGON2ID · SESSION COOKIE HTTPONLY · SQLITE</div>
      </div>
    </div>
  );

  return (
    <div className="shell">
      <aside>
        <div className="brand"><span className="brand-mark">A</span><div>AMNEZIA<span>PANEL</span></div></div>
        <nav><small>УПРАВЛЕНИЕ</small><a className="active">Обзор</a><a>Клиенты</a><a>Протоколы</a><a>Автообновление</a><a>Развёртывание VPS</a></nav>
        <div className="side-foot">CONTROL PLANE <span>v0.2.0 · PREVIEW</span></div>
      </aside>
      <main>
        <header><div><small>СИСТЕМА / ОБЗОР</small><h1>Панель управления</h1></div>
          <div className="header-actions"><span className="user-pill">{user}</span><button className="secondary" onClick={logout}>Выйти</button></div>
        </header>
        {error && <div className="form-error global-error">{error}<button onClick={() => setError('')}>Закрыть</button></div>}
        {issuedToken && <section className="token-notice"><b>Токен подписки создан</b><p>Он показан только сейчас и пока не подключён к рабочему endpoint. Сохрани его для дальнейшей интеграции.</p><code>{issuedToken}</code><button className="secondary" onClick={() => setIssuedToken('')}>Скрыть</button></section>}
        <section className="notice"><b>Preview runtime</b><p>Сейчас панель сохраняет конфигурации и клиентов в SQLite. Реальные VPN-процессы и Docker-контейнеры пока не запускаются — это следующий этап.</p></section>
        <section className="stats">
          <article><label>VPN-КОНФИГУРАЦИИ</label><strong>{containers.length}</strong><span>Записей в локальной БД</span></article>
          <article><label>КЛИЕНТЫ</label><strong>{clientCount}</strong><span>{enabledCount} включено</span></article>
          <article><label>ТРАФИК RX / TX</label><strong>—</strong><span>Учёт ещё не подключён</span></article>
          <article><label>СОСТОЯНИЕ API</label><strong className="ok">{health?.runtime.toUpperCase() ?? '—'}</strong><span>Версия {health?.version ?? '—'}</span></article>
        </section>

        <section className="panel">
          <div className="panel-head"><div><small>ИНФРАСТРУКТУРА</small><h2>VPN-конфигурации</h2></div>
            <button className="primary compact" onClick={() => setShowContainerForm(v => !v)}>{showContainerForm ? 'Отмена' : '＋ Добавить конфигурацию'}</button>
          </div>
          {showContainerForm && <form className="editor-form" onSubmit={createContainer}>
            <label>Название<input required minLength={2} maxLength={48} value={containerDraft.name} onChange={e => setContainerDraft({...containerDraft,name:e.target.value})} placeholder="Например, Finland AWG" /></label>
            <label>Протокол<select value={containerDraft.protocol} onChange={e => setContainerDraft({...containerDraft,protocol:e.target.value})}>
              <option value="amnezia-awg">AmneziaWG</option><option value="wireguard">WireGuard</option><option value="openvpn">OpenVPN</option><option value="openvpn-cloak">OpenVPN + Cloak</option>
            </select></label>
            <label>Домен / IP сервера<input required value={containerDraft.endpoint} onChange={e => setContainerDraft({...containerDraft,endpoint:e.target.value})} placeholder="vpn.example.com" /></label>
            <label>Порт<input type="number" min="1" max="65535" required value={containerDraft.listen_port} onChange={e => setContainerDraft({...containerDraft,listen_port:e.target.value})} /></label>
            <label>Транспорт<select value={containerDraft.transport} onChange={e => setContainerDraft({...containerDraft,transport:e.target.value})}><option value="udp">UDP</option><option value="tcp">TCP</option></select></label>
            <label>Подсеть IPv4<input required value={containerDraft.subnet} onChange={e => setContainerDraft({...containerDraft,subnet:e.target.value})} /></label>
            <label>DNS<input required value={containerDraft.dns} onChange={e => setContainerDraft({...containerDraft,dns:e.target.value})} /></label>
            <label>MTU<input type="number" min="576" max="9000" required value={containerDraft.mtu} onChange={e => setContainerDraft({...containerDraft,mtu:e.target.value})} /></label>
            <div className="form-actions"><span>Сохраняется как Preview — без запуска VPN.</span><button className="primary" disabled={actionBusy}>{actionBusy ? 'Сохранение…' : 'Сохранить'}</button></div>
          </form>}
          {containers.length === 0 && !showContainerForm
            ? <div className="empty"><div className="empty-icon">⌁</div><b>Конфигураций пока нет</b><p>Добавь сервер AmneziaWG, WireGuard или OpenVPN. На этом этапе мы сохраним параметры и подготовим управление клиентами.</p></div>
            : <div className="container-list">{containers.map(container => {
              const related = clients.filter(client => client.container_id === container.id);
              return <article className="container-card" key={container.id}>
                <div className="container-top"><div><b>{container.name}</b><span className="protocol-tag">{container.protocol}</span></div><span className="preview-tag">PREVIEW</span></div>
                <div className="container-meta"><span>{container.endpoint}:{container.listen_port}/{container.transport}</span><span>{container.subnet}</span><span>DNS {container.dns}</span><span>MTU {container.mtu}</span></div>
                <div className="container-bottom"><span>{related.length} клиентов · ревизия {container.revision}</span><button className="secondary compact" onClick={() => {setClientFormFor(clientFormFor === container.id ? null : container.id);setClientName('');setClientNote('');}}>＋ Добавить клиента</button></div>
                {clientFormFor === container.id && <form className="client-form" onSubmit={e => createClient(e,container.id)}>
                  <label>Имя клиента<input required maxLength={48} value={clientName} onChange={e => setClientName(e.target.value)} placeholder="Ноутбук, телефон…" /></label>
                  <label>Заметка<input maxLength={200} value={clientNote} onChange={e => setClientNote(e.target.value)} placeholder="Необязательно" /></label>
                  <button className="primary" disabled={actionBusy}>{actionBusy ? 'Создание…' : 'Создать клиента'}</button>
                </form>}
              </article>;
            })}</div>}
        </section>

        <section className="panel clients-panel">
          <div className="panel-head"><div><small>УЧЁТНЫЕ ЗАПИСИ</small><h2>Клиенты</h2></div><span className="muted">{enabledCount} активно</span></div>
          {clients.length === 0 ? <div className="empty small-empty"><b>Клиентов пока нет</b><p>Добавь клиента в карточке VPN-конфигурации.</p></div> :
            <div className="client-table"><div className="client-row client-header"><span>ИМЯ</span><span>IP-АДРЕС</span><span>СОСТОЯНИЕ</span><span>ДЕЙСТВИЕ</span></div>
              {clients.map(client => <div className="client-row" key={client.id}><span><b>{client.name}</b><small>{client.note || containers.find(c => c.id === client.container_id)?.name || '—'}</small></span><code>{client.assigned_ip}</code><span className={client.enabled ? 'status-enabled' : 'status-disabled'}>{client.enabled ? 'Включён' : 'Отключён'}</span><span>{client.enabled && <button className="danger compact" disabled={actionBusy} onClick={() => void disableClient(client.id)}>Отключить</button>}</span></div>)}
            </div>}
        </section>
        <footer>AMNEZIA PANEL <span>RUST API · REACT UI</span></footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
