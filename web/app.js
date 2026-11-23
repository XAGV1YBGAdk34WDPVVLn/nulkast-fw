(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmtBytes = (b) => b >= 1048576 ? (b/1048576).toFixed(1) + ' MB' : b >= 1024 ? (b/1024).toFixed(1) + ' KB' : b + ' B';
  const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString() : '-';

  let toastTimer = null;
  function toast(msg) {
    const el = $('toast');
    el.textContent = msg;
    el.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), 2600);
  }

  async function api(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch('/api/v1' + path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  // Tabs
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      $('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  function renderFlowRow(f) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge badge-ok">${esc(f.proto)}</span></td>
      <td class="mono">${esc(f.src_ip)}:${esc(f.src_port)}</td>
      <td class="mono">${esc(f.dst_ip)}:${esc(f.dst_port)}</td>
      <td class="mono">${fmtBytes((f.bytes_orig || 0) + (f.bytes_reply || 0))}</td>
      <td><button class="btn btn-danger" data-block-ip="${esc(f.dst_ip)}">Block IP</button></td>`;
    return tr;
  }

  function renderDnsRow(q) {
    const tr = document.createElement('tr');
    const badge = q.action === 'sinkholed' ? 'badge-danger' : 'badge-ok';
    tr.innerHTML = `
      <td class="mono">${esc(q.client_ip)}</td>
      <td class="mono">${esc(q.domain)}</td>
      <td>${esc(q.qtype)}</td>
      <td><span class="badge ${badge}">${esc(q.action)}</span></td>
      <td><button class="btn btn-danger" data-block-domain="${esc(q.domain)}">Sinkhole</button></td>`;
    return tr;
  }

  async function loadAll() {
    try {
      const [status, rules, devices, flows, dns, hosts, alerts, ids, sqm, audit] = await Promise.all([
        api('GET', '/status'),
        api('GET', '/rules'),
        api('GET', '/devices'),
        api('GET', '/flows?limit=60'),
        api('GET', '/dns/queries?limit=60'),
        api('GET', '/dns/hosts'),
        api('GET', '/alerts?limit=60'),
        api('GET', '/ids/status'),
        api('GET', '/sqm'),
        api('GET', '/audit?limit=60'),
      ]);

      $('iface-summary').textContent = `WAN ${status.wan} · LAN ${status.lan.join(', ')}`;
      $('stat-devices').textContent = status.db.devices_count;
      $('stat-flows').textContent = status.db.flows_count;
      $('stat-dns').textContent = status.db.dns_queries_count;
      $('stat-ips').textContent = status.blocked_ips;
      $('stat-domains').textContent = status.blocked_domains;
      $('stat-db').textContent = fmtBytes(status.db.db_size_bytes);

      if (status.pending_rollback) {
        $('rollback-info').textContent = `token ${status.pending_rollback.token} (reverts at ${fmtTime(status.pending_rollback.expires_at_unix)})`;
        $('rollback-banner').classList.remove('hidden');
      } else {
        $('rollback-banner').classList.add('hidden');
      }

      const fb = $('flows-body');
      fb.innerHTML = '';
      flows.forEach((f) => fb.appendChild(renderFlowRow(f)));

      const db = $('dns-body');
      db.innerHTML = '';
      dns.forEach((q) => db.appendChild(renderDnsRow(q)));

      const devb = $('devices-body');
      devb.innerHTML = devices.map((d) => `
        <tr>
          <td class="mono">${esc(d.ip)}</td>
          <td class="mono">${esc(d.mac)}</td>
          <td>${esc(d.hostname || '-')}</td>
          <td><span class="badge ${d.paused ? 'badge-danger' : 'badge-ok'}">${d.paused ? 'paused' : 'active'}</span></td>
          <td><button class="btn ${d.paused ? 'btn-ok' : 'btn-danger'}" data-toggle-mac="${esc(d.mac)}" data-paused="${d.paused}">${d.paused ? 'Unpause' : 'Pause'}</button></td>
        </tr>`).join('');

      $('local-domain-badge').textContent = `(*.${hosts.local_domain})`;
      $('hosts-body').innerHTML = hosts.hosts.map((h) => `
        <tr>
          <td class="mono">${esc(h.domain)}</td>
          <td class="mono">${esc(h.ip)}</td>
          <td><button class="btn btn-ghost" data-del-host="${esc(h.domain)}">Delete</button></td>
        </tr>`).join('');

      $('list-ips').innerHTML = rules.blocked_ips.map((ip) =>
        `<li><span>${esc(ip)}</span><button class="btn btn-ghost" data-del-ip="${esc(ip)}">Remove</button></li>`
      ).join('');

      $('list-domains').innerHTML = rules.blocked_domains.map((d) =>
        `<li><span>${esc(d)}</span><button class="btn btn-ghost" data-del-domain="${esc(d)}">Remove</button></li>`
      ).join('');

      $('list-ports').innerHTML = rules.allowed_ports.map((p) =>
        `<li><span>${esc(p.proto)}/${esc(p.port)}</span><button class="btn btn-ghost" data-del-port="${esc(p.proto)}/${esc(p.port)}">Close</button></li>`
      ).join('');

      const isDrop = ids.mode === 'drop';
      $('ids-mode-badge').textContent = isDrop ? 'IPS: DROP' : 'IDS: ALERT';
      $('ids-mode-badge').className = 'badge ' + (isDrop ? 'badge-danger' : 'badge-warn');
      $('btn-toggle-ids').textContent = isDrop ? 'Switch to IDS (ALERT)' : 'Switch to IPS (DROP)';
      $('btn-toggle-ids').dataset.nextMode = isDrop ? 'alert' : 'drop';
      $('ids-counts').textContent = `JA4: ${ids.ja4_rules} · Suricata: ${ids.suricata_rules} · Domains: ${ids.blocked_domains}`;

      $('alerts-body').innerHTML = alerts.map((a) => `
        <tr>
          <td class="mono">${fmtTime(a.ts)}</td>
          <td><span class="badge badge-warn">${esc(a.category)}</span></td>
          <td><span class="badge ${a.action === 'dropped' ? 'badge-danger' : 'badge-ok'}">${esc(a.action)}</span></td>
          <td class="mono">${esc(a.src_ip)} → ${esc(a.dst_ip)}:${esc(a.dst_port)}</td>
          <td class="mono">${esc(a.indicator)} <span class="muted">${esc(a.detail)}</span></td>
        </tr>`).join('');

      $('sqm-enabled').checked = !!sqm.enabled;
      $('sqm-dl').value = sqm.download_mbps;
      $('sqm-ul').value = sqm.upload_mbps;
      $('sqm-overhead').value = sqm.overhead || 'docsis';
      $('sqm-stats').textContent = `Egress (${sqm.wan}):\n${sqm.egress_qdisc || '(none)'}\n\nIngress (${sqm.ifb_dev}):\n${sqm.ingress_qdisc || '(none)'}`;

      $('audit-body').innerHTML = audit.map((a) => `
        <tr>
          <td class="mono">${fmtTime(a.ts)}</td>
          <td>${esc(a.actor)}</td>
          <td><span class="badge badge-ok">${esc(a.action)}</span></td>
          <td class="mono">${esc(a.target)}</td>
          <td class="muted">${esc(a.detail)}</td>
        </tr>`).join('');
    } catch (err) {
      toast('Error: ' + err.message);
    }
  }

  // Delegated 1-click actions
  document.addEventListener('click', async (e) => {
    const t = e.target;
    try {
      if (t.dataset.blockIp) {
        await api('POST', '/rules/ips', { ip: t.dataset.blockIp });
        toast(`Blocked ${t.dataset.blockIp}`);
        loadAll();
      } else if (t.dataset.delIp) {
        await api('DELETE', '/rules/ips/' + t.dataset.delIp);
        toast(`Unblocked ${t.dataset.delIp}`);
        loadAll();
      } else if (t.dataset.blockDomain) {
        await api('POST', '/rules/domains', { domain: t.dataset.blockDomain });
        toast(`Sinkholed ${t.dataset.blockDomain}`);
        loadAll();
      } else if (t.dataset.delDomain) {
        await api('DELETE', '/rules/domains/' + encodeURIComponent(t.dataset.delDomain));
        toast(`Removed ${t.dataset.delDomain}`);
        loadAll();
      } else if (t.dataset.delPort) {
        await api('DELETE', '/rules/ports/' + t.dataset.delPort);
        toast(`Closed port ${t.dataset.delPort}`);
        loadAll();
      } else if (t.dataset.delHost) {
        await api('DELETE', '/dns/hosts/' + encodeURIComponent(t.dataset.delHost));
        toast(`Deleted DNS host ${t.dataset.delHost}`);
        loadAll();
      } else if (t.dataset.toggleMac) {
        const paused = t.dataset.paused === 'true';
        await api(paused ? 'DELETE' : 'POST', `/devices/${encodeURIComponent(t.dataset.toggleMac)}/pause`);
        toast(`${paused ? 'Unpaused' : 'Paused'} ${t.dataset.toggleMac}`);
        loadAll();
      }
    } catch (err) {
      toast('Error: ' + err.message);
    }
  });

  $('form-host').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = $('input-host-domain').value.trim();
    const ip = $('input-host-ip').value.trim();
    try {
      await api('POST', '/dns/hosts', { domain, ip });
      $('input-host-domain').value = '';
      $('input-host-ip').value = '';
      toast(`Saved ${domain} -> ${ip}`);
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('form-ip').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = $('input-ip').value.trim();
    try {
      await api('POST', '/rules/ips', { ip });
      $('input-ip').value = '';
      toast(`Blocked ${ip}`);
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('form-domain').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = $('input-domain').value.trim();
    try {
      await api('POST', '/rules/domains', { domain });
      $('input-domain').value = '';
      toast(`Sinkholed ${domain}`);
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('form-port').addEventListener('submit', async (e) => {
    e.preventDefault();
    const proto = $('input-proto').value;
    const port = parseInt($('input-port').value, 10);
    try {
      await api('POST', '/rules/ports', { proto, port });
      $('input-port').value = '';
      toast(`Opened ${proto}/${port}`);
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('btn-toggle-ids').addEventListener('click', async () => {
    const next = $('btn-toggle-ids').dataset.nextMode || 'drop';
    try {
      await api('POST', '/ids/mode', { mode: next });
      toast(`IDS/IPS mode switched to ${next.toUpperCase()}`);
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('form-feed').addEventListener('submit', async (e) => {
    e.preventDefault();
    const format = $('feed-format').value;
    const content = $('feed-content').value;
    try {
      const res = await api('POST', '/feeds/import', { format, content, apply: true });
      toast(`Imported ${res.imported} ${format} entries`);
      $('feed-content').value = '';
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('form-sqm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('POST', '/sqm', {
        enabled: $('sqm-enabled').checked,
        download_mbps: parseInt($('sqm-dl').value, 10),
        upload_mbps: parseInt($('sqm-ul').value, 10),
        overhead: $('sqm-overhead').value,
      });
      toast('SQM configuration saved & applied');
      loadAll();
    } catch (err) { toast('Error: ' + err.message); }
  });

  $('btn-refresh').addEventListener('click', loadAll);
  $('btn-confirm').addEventListener('click', async () => {
    await api('POST', '/firewall/confirm');
    toast('Rules confirmed');
    loadAll();
  });
  $('btn-rollback').addEventListener('click', async () => {
    await api('POST', '/firewall/rollback');
    toast('Rolled back to last known-good snapshot');
    loadAll();
  });

  // Live WebSocket stream with auto-reconnect
  function connectWs() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/api/v1/ws/events`);
    ws.onopen = () => {
      $('ws-badge').textContent = 'WS: live';
      $('ws-badge').className = 'badge badge-ok';
    };
    ws.onclose = () => {
      $('ws-badge').textContent = 'WS: reconnecting';
      $('ws-badge').className = 'badge badge-warn';
      setTimeout(connectWs, 2000);
    };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'flow') {
          const fb = $('flows-body');
          fb.prepend(renderFlowRow(msg.data));
          while (fb.children.length > 60) fb.lastChild.remove();
        } else if (msg.type === 'dns_query') {
          const db = $('dns-body');
          db.prepend(renderDnsRow(msg.data));
          while (db.children.length > 60) db.lastChild.remove();
        } else if (msg.type === 'rule_changed' || msg.type === 'firewall_applied') {
          loadAll();
        }
      } catch (_) {}
    };
  }

  loadAll();
  connectWs();
})();
