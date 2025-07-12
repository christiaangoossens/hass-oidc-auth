function safeSetTextContent(element, value) {
  if (!element) return
  var textNode = Array.from(element.childNodes).find(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim().length > 0)
  if (!textNode) return
  textNode.textContent = value
}

function addSSOButton() {
  const loginHeader = document.querySelector(".card-content > ha-auth-flow > form > h1")
  safeSetTextContent(loginHeader, "Log in to Home Assistant")
  
  const codeField = document.querySelector(".mdc-text-field__input[name=code]")
  const loginButton = document.querySelector("mwc-button:not(.sso)")

  if (codeField) {
    codeField.placeholder = "One-time code"
    codeField.autofocus = false
    codeField.autocomplete = "off"
    setTimeout(() => {
      codeField.blur()
    }, 0)
  }

  var ssoButton = document.querySelector("mwc-button.sso")
  if (!ssoButton) {
    ssoButton = document.createElement("mwc-button")
    ssoButton.classList.add("sso")
    ssoButton.innerText = "Log in with " + window.sso_name
    ssoButton.setAttribute("raised", "")
    ssoButton.style.marginRight = "1em"
    ssoButton.style.display = "none"
    ssoButton.addEventListener("click", () => {
      location.href = "/auth/oidc/redirect"
    })
    loginButton.parentElement.prepend(ssoButton)
  }

  safeSetTextContent(loginButton, codeField ? "Log in with code" : "Log in")
  ssoButton.style.display = codeField ? "" : "none"
}

const observer = new MutationObserver((mutationsList, observer) => {
  addSSOButton()
})
observer.observe(document.body, { childList: true, subtree: true })