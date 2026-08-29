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
  const playerTeamSelect = document.getElementById("playerTeamSelect");

  box.innerHTML = "";
  select.innerHTML = "";
  playerTeamSelect.innerHTML = "";

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

    const playerOption = document.createElement("option");
    playerOption.value = team.id;
    playerOption.textContent = team.name;
    playerTeamSelect.appendChild(playerOption);
  });

  await loadPlayers(playerTeamSelect.value);
}

async function loadPlayers(teamId) {
  const box = document.getElementById("players");

  if (!teamId) {
    box.innerHTML = "<p>Select a team to view its players.</p>";
    return;
  }

  box.innerHTML = "<p>Loading players...</p>";

  try {
    const data = await api(`/api/my-teams/${encodeURIComponent(teamId)}/players`);

    if (!data.players.length) {
      box.innerHTML = "<p>No players have been added to this team yet.</p>";
      return;
    }

    box.innerHTML = data.players.map(player => {
      const dob = player.date_of_birth
        ? new Date(player.date_of_birth + "T00:00:00").toLocaleDateString("en-IN")
        : "Not provided";

      return `
        <div class="team player-card">
          <strong>${escapeHtml(player.full_name)}</strong><br>
          Date of Birth: ${escapeHtml(dob)}<br>
          Phone: ${escapeHtml(player.phone_number || "Not provided")}<br>
          Added: ${escapeHtml(new Date(player.created_at).toLocaleString("en-IN"))}
          <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
            ${player.has_photo
              ? `<button type="button" class="button secondary view-file" data-player="${player.id}" data-kind="photo">View Photo</button>`
              : "<span>No photo</span>"}
            ${player.has_aadhaar
              ? `<button type="button" class="button secondary view-file" data-player="${player.id}" data-kind="aadhaar">View Aadhaar</button>`
              : "<span>No Aadhaar file</span>"}
          </div>
        </div>`;
    }).join("");

    box.querySelectorAll(".view-file").forEach(button => {
      button.addEventListener("click", () => {
        const url = `/api/my-players/${encodeURIComponent(button.dataset.player)}/file/${encodeURIComponent(button.dataset.kind)}`;
        window.open(url, "_blank", "noopener");
      });
    });
  } catch (err) {
    box.innerHTML = `<p class="message">${escapeHtml(err.message)}</p>`;
  }
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

  if (!photo || !photo.size) {
    msg.textContent = "Please select the player's photo.";
    return;
  }

  if (!aadhaar || !aadhaar.size) {
    msg.textContent = "Please select the Aadhaar Card file.";
    return;
  }

  if (photo.size > 5 * 1024 * 1024 || aadhaar.size > 5 * 1024 * 1024) {
    msg.textContent = "Each uploaded file must be 5 MB or smaller.";
    return;
  }

  msg.textContent = "Uploading player securely...";

  try {
    await api(`/api/teams/${encodeURIComponent(teamId)}/players`, {
      method: "POST",
      body: f
    });

    msg.textContent = "Player added successfully.";
    form.reset();

    await loadTeams();
  } catch (err) {
    msg.textContent = err.message;
  }
});

document.getElementById("playerTeamSelect").addEventListener("change", e => {
  loadPlayers(e.target.value);
});

document.getElementById("refreshPlayers").addEventListener("click", () => {
  loadPlayers(document.getElementById("playerTeamSelect").value);
});

document.getElementById("logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  location.href = "/login.html";
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

loadCoach().catch(() => (location.href = "/login.html"));
