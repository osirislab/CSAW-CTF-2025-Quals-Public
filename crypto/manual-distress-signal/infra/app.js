// app.js
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const zlib = require("zlib");

const app = express();
const PORT = 21022;

app.use(bodyParser.json());

const SERVER_SECRET = 'csawctf{why_1s_th3_4cc3ss_k3y_1n_th3_d1str3ss_s1gn4l}';

app.get("/", (req, res) => {
  res.send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>⚠️FZgnZe\x19=blmk^ll\x19Lb\`gZe⚠️</title>
<style>
  body {
    margin: 0;
    font-family: 'Courier New', monospace;
    background: radial-gradient(circle at 50% 50%, #001020, #000000);
    color: #00ffea;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
  }
  .hud {
    width: 700px;
    background: rgba(0, 0, 32, 0.8);
    border: 2px solid #00ffea;
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 0 30px #00ffea, 0 0 60px #00ffea50 inset;
  }
  h1 {
    color: #00ffea;
    text-align: center;
    text-shadow: 0 0 8px #00ffea;
  }
  .input-row {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-bottom: 12px;
  }
  .input-row input,
  .input-row button {
    flex: 1; /* Equal width */
    font-family: monospace;
    font-size: 16px;
    border-radius: 8px;
    padding: 12px;
  }
  .input-row input {
    border: 1px solid #00ffea;
    background: rgba(0,16,32,0.9);
    color: #00ffea;
    text-shadow: 0 0 4px #00ffea;
  }
  .input-row button {
    border: none;
    background: #00ffea;
    color: #001020;
    font-weight: bold;
    cursor: pointer;
    box-shadow: 0 0 10px #00ffea;
  }
  .input-row button:hover {
    box-shadow: 0 0 20px #00ffee;
  }
  pre {
    margin-top: 16px;
    padding: 12px;
    background: rgba(0, 8, 16, 0.8);
    border: 1px solid #00ffea;
    border-radius: 8px;
    max-height: 40vh;
    overflow-y: auto;
    text-shadow: 0 0 4px #00ffea;
  }
</style>
</head>
<body>
<div class="hud">
<h1>⚠️FZgnZe\x19=blmk^ll\x19Lb\`gZe⚠️</h1>
<h3 style="overflow-wrap: break-word;">PZkgbg\`3\x19Hger\x19^g\`Z\`^\x19bg\x19ma^\x19\\Zl^\x19h_\x19Z\x19k^Ze\x19^f^k\`^g\\r'\x19Ghg&^ll^gmbZe\x19nl^l\x19h_\x19ma^\x19]blmk^ll\x19lb\`gZe\x19Zk^\x19Z\x19\\kbf^%\x19Zg]\x19Zee\x19\\kbf^l\x19pbee\x19[^\x19mkZ\\d^]\x19]hpg\x19Zg]\x19i^kl^\\nm^]\x19bg\x19ma^\x19Fbedr\x19PZr\x19@ZeZqr\x19M^kkZg\x19Lnik^f^\x19<hnkm\x19h_\x19EZp'</h3>
<div class="input-row">
  <input type="text" id="userInput" placeholder=">gm^k\x19bginm">
  <button id="sendBtn">>g\`Z\`^\x19MkZglfbllbhg</button>
</div>
<pre id="log"></pre>
</div>

<script>
const logEl = document.getElementById('log');
function note(s){ logEl.textContent += s + "\\n"; logEl.scrollTop = logEl.scrollHeight; }

document.getElementById('sendBtn').addEventListener('click', async () => {
  const input = document.getElementById('userInput').value;
  logEl.textContent = "";
  note("BgbmbZmbg\`\x19l^\\nk^\x19mkZglfbllbhg'''");
  try {
    const res = await fetch("/send", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({data: input})
    });
    const json = await res.json();
    if(json.error) note(">kkhk: " + json.error);
    if(json.ciphertext) note("<Zimnk^]\x19iZrehZ]3 " + json.ciphertext);
  } catch(err){
    note("MkZglfbllbhg\x19_Zbe^]3 " + err.message);
  }
});
</script>
</body>
</html>
  `);
});

// TLS
function simulateTLSRecord(payloadBuffer) {
  const contentType = Buffer.from([0x17]); // Application Data
  const version = Buffer.from([0x03, 0x03]); // TLS 1.2 
  const length = Buffer.alloc(2);
  length.writeUInt16BE(payloadBuffer.length, 0);
  return Buffer.concat([contentType, version, length, payloadBuffer]);
}

app.post("/send", (req, res) => {
  const userData = req.body.data || "";

  const combined = JSON.stringify({ secret: SERVER_SECRET, userData });

  // <=tls1.2 compression
  const compressed = zlib.deflateRawSync(Buffer.from(combined), { strategy: zlib.constants.Z_FIXED });

  // "tls encryption"
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-128-cfb", key, iv);
  let ciphertext = cipher.update(compressed);

  // "tls"
  const tlsSimulated = simulateTLSRecord(ciphertext);

  // Server "failure"
  res.json({
    error: "AMMIL\x19MkZglfbllbhg\x19_Zbenk^",
    ciphertext: tlsSimulated.toString("base64")
  });
});

app.listen(PORT, () => {});
