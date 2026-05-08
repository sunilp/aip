const FLOW_STEPS = [
  { num: 1, title: "Discover Agent Card",
    detail: "Caller fetches the receiving agent's A2A agent card and reads its <code>aip_identity</code> extension. If absent and the receiver requires AIP, the request MUST be rejected." },
  { num: 2, title: "Resolve Identity Document",
    detail: "Caller fetches the identity document at <code>aip_identity.document_url</code> (for <code>aip:web:</code>) or constructs it from the key (for <code>aip:key:</code>). The document's self-signature MUST verify and the document MUST NOT be expired." },
  { num: 3, title: "Append Delegation Block",
    detail: "Caller appends a delegation block: <code>delegate</code> = receiving agent's id, <code>scopes</code> = subset of caller's current scopes, non-empty <code>context</code>. Block is signed by the caller's private key." },
  { num: 4, title: "Send Task with Token",
    detail: "Caller sends the A2A task with the chained token in <code>metadata.aip_token</code>. The full chain travels with the request." },
  { num: 5, title: "Verify Full Chain",
    detail: "Receiver verifies: (a) Block 0 signature against root identity, (b) every delegation block's signature, scope-attenuation, and non-empty context, (c) chain depth ≤ max_depth, (d) no block expired, (e) declared budget non-negative, (f) final delegation targets the receiver." },
  { num: 6, title: "Further Delegation (optional)",
    detail: "Receiver MAY append another delegation block if depth allows. All scope-attenuation rules apply. If chain depth equals max_depth, further delegation is rejected." },
];

function renderFlow() {
  const root = document.getElementById("flow-diagram");
  if (!root) return;
  FLOW_STEPS.forEach((step) => {
    const el = document.createElement("div");
    el.className = "flow-step";
    el.dataset.step = step.num;
    el.innerHTML = `<span class="step-num">${step.num}</span><span class="step-title">${step.title}</span>`;
    el.addEventListener("click", () => showFlowDetail(step));
    root.appendChild(el);
  });
}

function showFlowDetail(step) {
  document.querySelectorAll(".flow-step").forEach((s) => s.classList.toggle("active", s.dataset.step === String(step.num)));
  const detail = document.getElementById("flow-detail");
  detail.innerHTML = `<strong>Step ${step.num}: ${step.title}</strong><p>${step.detail}</p>`;
  detail.hidden = false;
}

document.addEventListener("DOMContentLoaded", () => {
  renderFlow();
});

async function loadJSON(url) {
  const res = await fetch(url);
  return res.json();
}

async function renderChain() {
  const root = document.getElementById("chain-viewer");
  if (!root) return;
  const data = await loadJSON("/aip/paper/data/chain-demo.json");
  data.blocks.forEach((block) => {
    const wrap = document.createElement("details");
    wrap.className = "chain-block";
    wrap.addEventListener("toggle", () => wrap.classList.toggle("expanded", wrap.open));

    const scopes = block.scopes.join(", ");
    const summary = document.createElement("summary");
    summary.innerHTML = `
      <span>Block ${block.depth} — ${block.type}</span>
      <span>${block.delegate ?? block.issuer}</span>
      <span class="scope-badge">scope: [${scopes}]</span>
    `;
    wrap.appendChild(summary);

    const body = document.createElement("div");
    body.className = "chain-block-body";
    body.innerHTML = `<dl>
      <dt>Issuer</dt><dd>${block.issuer}</dd>
      ${block.delegate ? `<dt>Delegate</dt><dd>${block.delegate}</dd>` : ""}
      <dt>Scopes</dt><dd>[${scopes}]</dd>
      <dt>Budget</dt><dd>${block.budget_cents !== null ? `$${(block.budget_cents/100).toFixed(2)}` : "n/a"}</dd>
      ${block.max_depth !== undefined ? `<dt>Max depth</dt><dd>${block.max_depth}</dd>` : ""}
      ${block.context ? `<dt>Context</dt><dd>${block.context}</dd>` : ""}
      <dt>Expires</dt><dd>${block.expires}</dd>
      <dt>Signature</dt><dd>${block.signature}</dd>
    </dl>`;
    wrap.appendChild(body);
    root.appendChild(wrap);
  });
}

document.addEventListener("DOMContentLoaded", renderChain);
