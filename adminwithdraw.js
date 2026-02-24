const token = localStorage.getItem("token")

if (!token) {
  window.location.href = "login.html"
}

document.getElementById("withdrawForm").addEventListener("submit", async (e) => {
  e.preventDefault()

  const amount = document.getElementById("amount").value
  const bank = document.getElementById("bank").value
  const accountNumber = document.getElementById("accountNumber").value
  const accountName = document.getElementById("accountName").value
  const description = document.getElementById("description").value

  const res = await fetch("/api/admin/withdraw", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token
    },
    body: JSON.stringify({
      amount,
      bank,
      accountNumber,
      accountName,
      description
    })
  })

  const data = await res.json()

  document.getElementById("message").innerText = data.message
})