import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

function App() {
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <span className="brand-mark">A</span>
          <div>AMNEZIA<span>PANEL</span></div>
        </div>
        <nav>
          <small>УПРАВЛЕНИЕ</small>
          <a className="active">Обзор</a>
          <a>Клиенты</a>
          <a>Протоколы</a>
          <a>Автообновление</a>
          <a>Развёртывание VPS</a>
        </nav>
        <div className="side-foot">CONTROL PLANE <span>v0.1.0 · DEV</span></div>
      </aside>
      <main>
        <header>
          <div><small>СИСТЕМА / ОБЗОР</small><h1>Панель управления</h1></div>
          <div className="header-actions">
            <button className="lang">RU / EN</button>
            <button className="primary" disabled>＋ Новый клиент</button>
          </div>
        </header>
        <section className="notice">
          <b>Начальная сборка</b>
          <p>Это рабочий каркас интерфейса. Подключение Docker, управление VPN-пирами и выпуск конфигураций ещё не реализованы.</p>
        </section>
        <section className="stats">
          <article><label>КОНТЕЙНЕРЫ</label><strong>—</strong><span>Нет подключённых runtime</span></article>
          <article><label>КЛИЕНТЫ</label><strong>0</strong><span>Пока не создано</span></article>
          <article><label>ТРАФИК RX / TX</label><strong>—</strong><span>Телеметрия не подключена</span></article>
          <article><label>СОСТОЯНИЕ API</label><strong className="ok">ONLINE</strong><span>Локальный режим разработки</span></article>
        </section>
        <section className="panel">
          <div className="panel-head">
            <div><small>ИНФРАСТРУКТУРА</small><h2>Протоколы и контейнеры</h2></div>
            <span className="muted">0 активных</span>
          </div>
          <div className="empty">
            <div className="empty-icon">⌁</div>
            <b>Контейнеры ещё не подключены</b>
            <p>На следующем этапе добавим runtime-адаптеры и безопасное управление Docker.</p>
          </div>
        </section>
        <footer>AMNEZIA PANEL <span>SELF-HOSTED VPN CONTROL PLANE</span></footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode><App /></React.StrictMode>
);
