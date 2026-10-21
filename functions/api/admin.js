export async function onRequestPost(context) {
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}


const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

export async function onRequestPost({ request, env }) {
  const SB = env.SUPABASE_URL, SK = env.SUPABASE_SERVICE_KEY;
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  if (!token) return json({ error: 'Sin sesión' }, 401);

  // 1) Quién llama: el token debe ser de un usuario válido
  const meRes = await fetch(SB + '/auth/v1/user', { headers: { apikey: SK, Authorization: 'Bearer ' + token } });
  if (!meRes.ok) return json({ error: 'Sesión no válida' }, 401);
  const me = await meRes.json();
  const myName = ((me.user_metadata && me.user_metadata.username) || '').toLowerCase();

  // 2) Solo administradores
  const admins = (env.ADMIN_USERS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!admins.includes(myName)) return json({ error: 'Solo administradores' }, 403);

  const body = await request.json().catch(() => ({}));
  const adminHeaders = { apikey: SK, Authorization: 'Bearer ' + SK, 'Content-Type': 'application/json' };

  const listUsers = async () => {
    const r = await fetch(SB + '/auth/v1/admin/users?per_page=500', { headers: adminHeaders });
    const d = await r.json();
    return d.users || d;
  };
  const audit = async (action, target) => {
    await fetch(SB + '/rest/v1/audit_log', {
      method: 'POST',
      headers: { ...adminHeaders, Prefer: 'return=minimal' },
      body: JSON.stringify({ actor: myName, action, target })
    });
  };

  if (body.action === 'list') {
    const users = await listUsers();
    return json({ users: users.map(u => ({
      id: u.id,
      username: (u.user_metadata && u.user_metadata.username) || '',
      created: u.created_at,
      last_sign_in: u.last_sign_in_at,
      must_change: !!(u.user_metadata && u.user_metadata.must_change)
    })) });
  }

  if (body.action === 'create') {
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!/^[a-z0-9]{3,20}$/.test(username)) return json({ error: 'Usuario: solo letras y números, 3 a 20 caracteres.' }, 400);
    if (password.length < 6) return json({ error: 'La clave temporal debe tener al menos 6 caracteres.' }, 400);
    const r = await fetch(SB + '/auth/v1/admin/users', {
      method: 'POST', headers: adminHeaders,
      body: JSON.stringify({ email: username + '@inventario.internal', password, email_confirm: true,
        user_metadata: { username, must_change: true } })
    });
    if (!r.ok) return json({ error: 'No se pudo crear: ' + (await r.text()) }, 400);
    await audit('CREADO', username);
    return json({ ok: true });
  }

  if (body.action === 'reset') {
    const username = String(body.username || '').toLowerCase();
    const password = String(body.password || '');
    if (password.length < 6) return json({ error: 'La clave temporal debe tener al menos 6 caracteres.' }, 400);
    const u = (await listUsers()).find(x => ((x.user_metadata && x.user_metadata.username) || '') === username);
    if (!u) return json({ error: 'Usuario no encontrado' }, 404);
    const r = await fetch(SB + '/auth/v1/admin/users/' + u.id, {
      method: 'PUT', headers: adminHeaders,
      body: JSON.stringify({ password, user_metadata: { ...(u.user_metadata || {}), username, must_change: true } })
    });
    if (!r.ok) return json({ error: 'No se pudo resetear: ' + (await r.text()) }, 400);
    await audit('CLAVE RESETEADA', username);
    return json({ ok: true });
  }

  if (body.action === 'delete') {
    const username = String(body.username || '').toLowerCase();
    if (username === myName) return json({ error: 'No puedes borrar tu propio usuario.' }, 400);
    const u = (await listUsers()).find(x => ((x.user_metadata && x.user_metadata.username) || '') === username);
    if (!u) return json({ error: 'Usuario no encontrado' }, 404);
    const r = await fetch(SB + '/auth/v1/admin/users/' + u.id, { method: 'DELETE', headers: adminHeaders });
    if (!r.ok) return json({ error: 'No se pudo borrar: ' + (await r.text()) }, 400);
    await audit('BORRADO', username);
    return json({ ok: true });
  }

  return json({ error: 'Acción no válida' }, 400);
}
