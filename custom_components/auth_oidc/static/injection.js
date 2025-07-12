function safeSetTextContent(element, value) {
  if (!element) return
  var textNode = Array.from(element.childNodes).find(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim().length > 0)
  if (!textNode || textNode.textContent === value) return
  textNode.textContent = value
}

let firstFocus = true

function addSSOButton() {
  const loginHeader = document.querySelector(".card-content > ha-auth-flow > form > h1")
  const codeField = document.querySelector(".mdc-text-field__input[name=code]")
  const loginButton = document.querySelector("mwc-button:not(.sso)")
  const ssoButton = document.querySelector("mwc-button.sso")

  safeSetTextContent(loginHeader, "Log in to Home Assistant")

  if (codeField && codeField.placeholder !== "One-time code") {
    codeField.placeholder = "One-time code"
    codeField.autofocus = false
    codeField.autocomplete = "off"
    if (firstFocus) {
      firstFocus = false
      if (document.activeElement === codeField) {
        setTimeout(() => {
          codeField.blur()
          setTimeout(() => {
            const helperText = document.querySelector("#helper-text")
            const invalidTextField = document.querySelector(".mdc-text-field--invalid")
            const validationMsg = document.querySelector(".mdc-text-field-helper-text--validation-msg")
            if (helperText) safeSetTextContent(helperText, "")
            if (invalidTextField) invalidTextField.classList.remove("mdc-text-field--invalid")
            if (validationMsg) validationMsg.classList.remove("mdc-text-field-helper-text--validation-msg")
          }, 0)
        }, 0)
      }
    }
  }

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
    if (loginButton) loginButton.parentElement.prepend(ssoButton)
  } else {
    ssoButton.style.display = codeField ? "" : "none"
  }

  safeSetTextContent(loginButton, codeField ? "Log in with code" : "Log in")
}

const observer = new MutationObserver((mutationsList, observer) => {
  addSSOButton()
})

observer.observe(document.body, { childList: true, subtree: true })