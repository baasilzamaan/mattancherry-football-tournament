async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function loadCoach() {
  const me = await api("/api/me");
  if (!me.user || me.user.role !== "coach") return (location.href = "/login.html");
  document.getElementById("who").textContent = `Logged in as ${me.user.username}`;
  await loadTeams();
}

async function loadTeams() {
  const data = await api("/api/my-teams");
  const box = document.getElementById("teams");
  const select = document.getElementById("teamSelect");
  box.innerHTML = "";
  select.innerHTML = "";

  if (!data.teams.length) {
    box.textContent = "No teams registered yet.";
    return;
  }

  data.teams.forEach(team => {
    const div = document.createElement("div");
    div.className = "team";
    div.innerHTML = `<strong>${escapeHtml(team.name)}</strong><br>
      Status: <span class="status">${escapeHtml(team.status)}</span><br>
      Players: ${team.player_count}<br>
      Fee: ₹${Number(team.fee_amount || 1500).toLocaleString("en-IN")}`;
    box.appendChild(div);

    const option = document.createElement("option");
    option.value = team.id;
    option.textContent = team.name;
    select.appendChild(option);
  });
}

document.getElementById("teamForm").addEventListener("submit", async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  const msg = document.getElementById("teamMessage");
  msg.textContent = "Registering team...";
  try {
    await api("/api/teams", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: f.get("name"),
        contactPhone: f.get("contactPhone"),
        schoolOrClub: f.get("schoolOrClub")
      })
    });
    msg.textContent = "Team registered successfully.";
    e.target.reset();
    await loadTeams();
  } catch (err) {
    msg.textContent = err.message;
  }
});

document.getElementById("playerForm").addEventListener("submit", async e => {
  e.preventDefault();
  const form = e.target;
  const f = new FormData(form);
  const teamId = f.get("teamId");
  const msg = document.getElementById("playerMessage");
  const photo = f.get("photo");
  const aadhaar = f.get("aadhaarCard");

  if (!photo || !photo.size) return (msg.textContent = "Please select the player's photo.");
  if (!aadhaar || !aadhaar.size) return (msg.textContent = "Please select the Aadhaar Card file.");
  if (photo.size > 5 * 1024 * 1024 || aadhaar.size > 5 * 1024 * 1024) {
    return (msg.textContent = "Each uploaded file must be 5 MB or smaller.");
  }

  msg.textContent = "Uploading player securely...";
  try {
    await api(`/api/teams/${encodeURIComponent(teamId)}/players`, {
      method: "POST",
      body: f
    });
    msg.textContent = "Player added securely.";
    form.reset();
    await loadTeams();
  } catch (err) {
    msg.textContent = err.message;
  }
});

document.getElementById("logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  location.href = "/login.html";
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[c]));
}

loadCoach().catch(() => (location.href = "/login.html"));
