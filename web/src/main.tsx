import { FormEvent, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

type SetupStatus = { setup_required: boolean };
type AuthResponse = { authenticated: boolean; username: string | null };
type Health = { ok: boolean; version: string; runtime: string };

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...init.headers },
  });
  if (!response.ok) {
    const body = await response.text();
    let message = body || `HTTP ${response.status}`;
    try { message = JSON.parse(body).error ?? JSON.parse(body).message ?? message; } catch {}
    throw new Error(message);
  }
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
        } catch { setUser(null); }
      } else {
        setUser(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Не удалось подключиться к API');
    } finally { setLoading(false); }
  }

  useEffect(() => { void refresh(); }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    try {
      const result = await api<AuthResponse>(setupRequired ? '/api/setup/initialize' : '/api/auth/login', {
        method: 'POST', body: JSON.stringify({ username, password }),
      });
      setUser(result.username);
      setPassword('');
      setSetupRequired(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Не удалось выполнить запрос');
    } finally { setBusy(false); }
  }

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); }
    finally { setUser(null); }
  }

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
        <form onSubmit={submit}>
          <label>Имя пользователя<input value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={32} autoComplete="username" required /></label>
          <label>Пароль<input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} maxLength={256} autoComplete={setupRequired ? 'new-password' : 'current-password'} required /></label>
          {setupRequired && <span className="field-hint">Минимум 12 символов. Используйте уникальный пароль.</span>}
          {error && <div className="form-error">{error}</div>}
          <button className="primary submit" disabled={busy}>{busy ? 'Подождите…' : setupRequired ? 'Создать администратора' : 'Войти'}</button>
        </form>
        <div className="auth-foot">ПАРОЛЬ ХЕШИРУЕТСЯ ARGON2ID · SESSION COOKIE HTTPONLY</div>
      </div>
    </div>
  );

  return (
    <div className="shell">
      <aside>
        <div className="brand"><span className="brand-mark">A</span><div>AMNEZIA<span>PANEL</span></div></div>
        <nav><small>УПРАВЛЕНИЕ</small><a className="active">Обзор</a><a>Клиенты</a><a>Протоколы</a><a>Автообновление</a><a>Развёртывание VPS</a></nav>
        <div className="side-foot">CONTROL PLANE <span>v0.1.0 · DEV</span></div>
      </aside>
      <main>
        <header><div><small>СИСТЕМА / ОБЗОР</small><h1>Панель управления</h1></div>
          <div className="header-actions"><span className="user-pill">{user}</span><button className="secondary" onClick={logout}>Выйти</button></div>
        </header>
        <section className="notice"><b>Фундамент backend готовится</b><p>Авторизация и первичная настройка подключены к Rust API. Управление VPN-контейнерами и клиентами будет добавлено следующими этапами.</p></section>
        <section className="stats">
          <article><label>КОНТЕЙНЕРЫ</label><strong>—</strong><span>Runtime ещё не подключён</span></article>
          <article><label>КЛИЕНТЫ</label><strong>0</strong><span>Пока не создано</span></article>
          <article><label>ТРАФИК RX / TX</label><strong>—</strong><span>Телеметрия не подключена</span></article>
          <article><label>СОСТОЯНИЕ API</label><strong className="ok">{health?.runtime.toUpperCase() ?? '—'}</strong><span>Версия {health?.version ?? '—'}</span></article>
        </section>
        <section className="panel"><div className="panel-head"><div><small>ИНФРАСТРУКТУРА</small><h2>Протоколы и контейнеры</h2></div><span className="muted">0 активных</span></div>
          <div className="empty"><div className="empty-icon">⌁</div><b>Контейнеры ещё не подключены</b><p>Следующий этап — preview runtime и безопасное управление Docker без shell-интерполяции.</p></div>
        </section>
        <footer>AMNEZIA PANEL <span>RUST API · REACT UI</span></footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
