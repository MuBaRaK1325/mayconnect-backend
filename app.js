/* =================================================
   MAY-CONNECT — FINAL STABLE APP.JS
================================================== */

const backendUrl = "https://mayconnect-backend-1.onrender.com";

/* ================= HELPERS ================= */
const $ = id => document.getElementById(id);
const getToken = () => localStorage.getItem("token");

/* ================= NETWORK ================= */
const net = $("networkStatus");
function showNetwork(type) {
  if (!net) return;
  net.className = `network-status ${type}`;
  net.textContent =
    type === "slow" ? "Slow network detected" : "You are offline";
  net.classList.remove("hidden");
  setTimeout(() => net.classList.add("hidden"), 3000);
}
window.addEventListener("offline", () => showNetwork("offline"));

/* ================= LOADER ================= */
const loader = $("splashLoader");
const loaderState = $("loaderState");
function showLoader() {
  if (!loader) return;
  loaderState.innerHTML = `<div class="splash-ring"></div>`;
  loader.classList.remove("hidden");
}
function showSuccess() {
  loaderState.innerHTML = `<div class="success-check">✓</div>`;
}
function hideLoader() {
  loader?.classList.add("hidden");
}

/* ================= SOUND ================= */
function playSuccessSound() {
  $("successSound")?.play().catch(() => {});
}

/* ================= WALLET ================= */
async function updateWalletBalance() {
  if (!getToken()) return;
  try {
    const res = await fetch(`${backendUrl}/api/wallet`, {
      headers: { Authorization: `Bearer ${getToken()}` }
    });
    const data = await res.json();
    $("walletBalance") && ( $("walletBalance").textContent = `₦${data.balance || 0}` );
  } catch {}
}

/* ================= PIN STATE ================= */
let hasPin = false;

async function checkPinStatus() {
  try {
    const res = await fetch(`${backendUrl}/api/wallet`, {
      headers: { Authorization: `Bearer ${getToken()}` }
    });
    if (res.ok) {
      hasPin = true;
      $("setPinBtn") && ($("setPinBtn").textContent = "Change PIN");
    }
  } catch {}
}

/* ================= DATA PLANS ================= */
let selectedPlan = null;
const DATA_PLANS = [
  {
    id: "mtn5gb",
    provider: "maitama",
    network: "MTN",
    plan_id: 158,
    name: "MTN 5GB SME",
    price: 1500,
    validity: "30 Days"
  },
  {
    id: "subpadi_airtel_3_2gb",
    provider: "subpadi",
    network: "AIRTEL",
    plan_id: 415,
    name: "AIRTEL GIFTING 3.2GB",
    price: 1050,
    validity: "1 Month"
  },
  {
    id: "subpadi_mtn_2_5gb",
    provider: "subpadi",
    network: "MTN",
    plan_id: 414,
    name: "MTN GIFTING 2.5GB",
    price: 600,
    validity: "1 Month"
  },
  {
    id: "cheapdata_airtel_5gb",
    provider: "cheapdatahub",
    network: "AIRTEL",
    plan_id: 52,
    name: "AIRTEL 5GB",
    price: 1650,
    validity: "7 Days"
  },
  {
    id: "glo_sme_9_8gb",
    provider: "glo",
    network: "GLO",
    plan_id: 335,
    name: "GLO SME 9.8GB",
    price: 2450,
    validity: "1 Month"
  }
];

/* ================= DYNAMIC PLAN RENDER ================= */
function renderPlans() {
  const container = $("plansGrid");
  if (!container) return;

  container.innerHTML = "";
  DATA_PLANS.forEach(plan => {
    const div = document.createElement("div");
    div.className = "plan-card";
    div.innerHTML = `
      <small>${plan.network}</small>
      <h4>${plan.name.split(" ")[1]}</h4>
      <small>${plan.validity}</small>
      <div class="price">₦ ${plan.price}</div>
    `;
    div.onclick = () => selectPlan(div, plan);
    container.appendChild(div);
  });
}

/* ================= PLAN SELECTION ================= */
function selectPlan(card, plan) {
  document.querySelectorAll(".plan-card").forEach(p => p.classList.remove("selected"));
  card.classList.add("selected");
  selectedPlan = plan;
  $("confirmOrderBtn")?.classList.remove("hidden");
}

/* ================= CONFIRM ORDER ================= */
function confirmOrder() {
  if (!selectedPlan) return alert("Select a plan first");
  if (!$("phone").value) return alert("Enter phone number");

  if (!hasPin) {
    openSetPin();
    return;
  }
  openPinModal();
}

/* ================= SET PIN ================= */
function openSetPin() {
  $("setPinModal")?.classList.remove("hidden");
  document.querySelectorAll("#setPinModal input").forEach(i => (i.value = ""));
}
function closeSetPin() {
  $("setPinModal")?.classList.add("hidden");
}

async function submitSetPin() {
  const pin = [...document.querySelectorAll("#setPinModal input")]
    .map(i => i.value)
    .join("");
  if (!/^\d{4}$/.test(pin)) return alert("PIN must be 4 digits");

  showLoader();
  try {
    const res = await fetch(`${backendUrl}/api/set-pin`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getToken()}`
      },
      body: JSON.stringify({ pin })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || data.error);

    hasPin = true;
    $("setPinBtn").textContent = "Change PIN";
    showSuccess();
    playSuccessSound();

    setTimeout(() => {
      hideLoader();
      closeSetPin();
      openPinModal(); // continue purchase automatically
    }, 600);
  } catch (err) {
    alert(err.message);
    hideLoader();
  }
}

/* ================= PIN MODAL ================= */
function openPinModal() {
  $("pinModal")?.classList.remove("hidden");
}
function closePinModal() {
  $("pinModal")?.classList.add("hidden");
}

async function submitPin() {
  const pin = [...document.querySelectorAll(".pin-inputs input")]
    .map(i => i.value)
    .join("");
  if (pin.length !== 4) return alert("Enter 4-digit PIN");

  showLoader();
  try {
    const res = await fetch(`${backendUrl}/api/wallet/purchase`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getToken()}`
      },
      body: JSON.stringify({
        type: "data",
        pin,
        details: {
          mobile_number: $("phone").value,
          plan: selectedPlan.plan_id,
          network: selectedPlan.network
        }
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    playSuccessSound();
    showReceipt(data.receipt);
    updateWalletBalance();
    closePinModal();
  } catch (err) {
    alert(err.message || "Purchase failed");
  } finally {
    hideLoader();
  }
}

/* ================= RECEIPT ================= */
function showReceipt(r) {
  $("receiptBody").innerHTML = `
    <div><b>Reference:</b> ${r.reference}</div>
    <div><b>Amount:</b> ₦${r.amount}</div>
    <div style="color:green"><b>Status:</b> SUCCESS</div>
  `;
  $("receiptModal")?.classList.remove("hidden");
}

/* ================= INIT ================= */
document.addEventListener("DOMContentLoaded", () => {
  renderPlans();
  if (getToken()) {
    updateWalletBalance();
    checkPinStatus();
  }
});
