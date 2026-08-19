async function api(url, options={}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function loadAdmin() {
  const me = await api("/api/me");
  if (!me.user || me.user.role !== "admin") return location.href="/login.html";
  document.getElementById("who").textContent = `Logged in as ${me.user.username}`;
  const data = await api("/api/admin/teams");
  document.getElementById("summary").textContent =
    `${data.teams.length} registered team(s). Maximum allowed: 32.`;

  const box = document.getElementById("teams");
  box.innerHTML = "";
  data.teams.forEach(team => {
    const div = document.createElement("div");
    div.className="team";
    div.innerHTML = `
      <strong>${escapeHtml(team.name)}</strong><br>
      Coach: ${escapeHtml(team.coach_username)}<br>
      Phone: ${escapeHtml(team.contact_phone)}<br>
      Players: ${team.player_count}<br>
      Fee: ₹${team.fee_amount || 1500}<br>
      Status: <strong>${escapeHtml(team.status)}</strong>
      <div style="margin-top:10px">
        <button class="button" onclick="setStatus(${team.id},'approved')">Approve</button>
        <button class="button secondary" onclick="setStatus(${team.id},'rejected')">Reject</button>
        <button class="button secondary" onclick="setStatus(${team.id},'pending')">Pending</button>
      </div>`;
    box.appendChild(div);
  });
}

async function setStatus(id,status) {
  try {
    await api(`/api/admin/teams/${id}/status`, {
      method:"PATCH",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({status})
    });
    await loadAdmin();
  } catch(err) { alert(err.message); }
}

document.getElementById("logout").addEventListener("click", async () => {
  await api("/api/logout",{method:"POST"});
  location.href="/login.html";
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

loadAdmin().catch(() => location.href="/login.html");
