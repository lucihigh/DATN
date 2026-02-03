import { useState } from "react";
import { api } from "@secure-wallet/shared";

function App() {
  const [email, setEmail] = useState("user@example.com");
  const [password, setPassword] = useState("password123");
  const [message, setMessage] = useState<string | null>(null);

  const handleLogin = async () => {
    const { data, error } = await api.POST("/auth/login", {
      body: { email, password }
    });
    if (error) {
      setMessage(JSON.stringify(error));
    } else {
      setMessage(JSON.stringify(data));
    }
  };

  return (
    <div style={{ fontFamily: "Inter, system-ui", padding: "2rem" }}>
      <h1>Secure E-Wallet (User)</h1>
      <p>Stubbed user login hitting the API + AI scorer.</p>
      <label>
        Email
        <input value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <br />
      <label>
        Password
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <br />
      <button onClick={handleLogin}>Login</button>
      {message && <pre>{message}</pre>}
    </div>
  );
}

export default App;
