function safeSetTextContent(element, value) {
  if (!element) return
  var textNode = Array.from(element.childNodes).find(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim().length > 0)
  if (!textNode || textNode.textContent === value) return
  textNode.textContent = value
}

let firstFocus = true
let showCodeOverride = null

function showCode() {
  if (showCodeOverride !== null) return showCodeOverride

  const clientId = new URL(location.href).searchParams.get("client_id")
  return clientId && clientId.startsWith("https://home-assistant.io/iOS") || clientId.startsWith("https://home-assistant.io/android")
}

let ssoButton = null
let codeMessage = null
let codeToggle = null
let codeToggleText = null

function update() {
  const sso_name = window.sso_name || "Single Sign-On"
  const loginHeader = document.querySelector(".card-content > ha-auth-flow > form > h1")
  const authForm = document.querySelector("ha-auth-form")
  const codeField = document.querySelector(".mdc-text-field__input[name=code]")
  const loginButton = document.querySelector("mwc-button:not(.sso)")
  const errorAlert = document.querySelector("ha-auth-form ha-alert[alert-type=error]")
  const loginOptionList = document.querySelector("ha-pick-auth-provider")?.shadowRoot?.querySelector("mwc-list")

  // ====
  // Code input
  if (codeField) {
    if (codeField.placeholder !== "One-time code") {
      codeField.placeholder = "One-time code"
      codeField.autofocus = false
      codeField.autocomplete = "off"

      if (firstFocus) {
        firstFocus = false

        if (document.activeElement === codeField) {
          setTimeout(() => {
            codeField.blur()
            let check = setInterval(() => {
              const helperText = document.querySelector("#helper-text")
              const invalidTextField = document.querySelector(".mdc-text-field--invalid")
              const validationMsg = document.querySelector(".mdc-text-field-helper-text--validation-msg")
              if (helperText && invalidTextField && validationMsg) {
                clearInterval(check)
                safeSetTextContent(helperText, "")
                invalidTextField.classList.remove("mdc-text-field--invalid")
                validationMsg.classList.remove("mdc-text-field-helper-text--validation-msg")
              }
            }, 1)
          }, 0)
        }
      }
    }
  
    if (errorAlert && errorAlert.textContent.trim().length === 0) {
      errorAlert.setAttribute("title", "Invalid Code")
    }
  
    authForm.style.display = showCode() ? "" : "none"
    loginButton.style.display = showCode() ? "" : "none"
  }

  if (authForm && !codeMessage) {
    codeMessage = document.createElement("p")
    codeMessage.innerHTML = `<b>Please login on a different device to continue.</b><br/>You can also use your mobile webbrowser.`
    authForm.parentElement.insertBefore(codeMessage, authForm)
  }

  if (codeMessage) {
    codeMessage.style.display = showCode() ? "" : "none"
  }

  safeSetTextContent(loginButton, codeField ? "Log in with code" : "Log in")

  // ====
  // Toggle button
  if (loginOptionList && !codeToggle) {
    codeToggle = document.createElement("ha-list-item")
    codeToggle.setAttribute("hasmeta", "")
    codeToggleText = document.createTextNode("")
    codeToggle.appendChild(codeToggleText)
    const codeToggleIcon = document.createElement("ha-icon-next")
    codeToggleIcon.setAttribute("slot", "meta")
    codeToggle.appendChild(codeToggleIcon)

    let ranHandler = false;
    codeToggle.addEventListener("click", () => {
      ranHandler = true;
      showCodeOverride = !showCode()
      update()
    })

    loginOptionList.addEventListener("click", (ev) => {
      if (!ranHandler) {
        showCodeOverride = false;
        codeMessage = null;
      }
      ranHandler = false;
    })
  
    loginOptionList.appendChild(codeToggle)
  }

  if (codeToggle) {
    codeToggle.style.display = codeField ? "" : "none"
  }

  if (codeToggleText) {
    codeToggleText.textContent = showCode() ? "Single-Sign On" : "One-time device code"
  }

  // ====
  // SSO Page
  const shouldShowSSOButton = !showCode() && !!codeField
  const isOurScreen = showCode() || shouldShowSSOButton
  
  if (loginButton && !ssoButton) {
    ssoButton = document.createElement("mwc-button")
    ssoButton.id = "sso_button"
    ssoButton.classList.add("sso")
    ssoButton.innerText = "Log in with " + sso_name
    ssoButton.setAttribute("raised", "")
    ssoButton.style.marginRight = "1em"
    ssoButton.addEventListener("click", () => {
      location.href = "/auth/oidc/redirect"
    })
    loginButton.parentElement.prepend(ssoButton)
  }

  if (ssoButton) {
    ssoButton.style.display = (!showCode() && codeField) ? "" : "none"
  }

  // ====
  // Header hidden on our screens
  if (loginHeader) {
    if (isOurScreen) {
      // Hide the header on our screens
      loginHeader.style.display = "none"
    } else {
      // Show the header on the login screen
      loginHeader.style.display = ""
    }
  }
}

// Hide the content until ready
let ready = false
document.querySelector(".content").style.display = "none"

const observer = new MutationObserver((mutationsList, observer) => {
  update()

  if (!ready) {
    ready = Boolean(ssoButton && codeMessage && codeToggle && codeToggleText)
    if (ready) document.querySelector(".content").style.display = ""
  }
})

observer.observe(document.body, { childList: true, subtree: true })

setTimeout(() => {
  if (!ready) {
    console.warn("hass-oidc-auth: Document was not ready after 300ms seconds, force displaying. This may indicate a problem with the UI injection.")
  }

  // Force display the content
  document.querySelector(".content").style.display = "";
  update();
}, 300)