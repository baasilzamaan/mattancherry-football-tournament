async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const message = document.getElementById("message");
  try {
    const data = await postJSON("/api/login", {
      username: form.get("username"),
      password: form.get("password")
    });
    location.href = data.user.role === "admin" ? "/admin.html" : "/coach.html";
  } catch (err) {
    message.textContent = err.message;
  }
});

document.getElementById("registerForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const message = document.getElementById("registerMessage");
  try {
    const data = await postJSON("/api/register-coach", {
      username: form.get("username"),
      password: form.get("password")
    });
    message.textContent = data.message;
    e.target.reset();
  } catch (err) {
    message.textContent = err.message;
  }
});