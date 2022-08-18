'use strict'; (async () => {
const CONFIG = window.CONFIG

//--[ OAuth ]--------------------------------------
const STATE_PREFIX = 'oauth'
const STORAGE = localStorage

function sleep(time) {
  return new Promise((resolve) => setTimeout(resolve, time))
}

function never_returns() {
  return new Promise(() => {})
}

function random() {
  const array = new Uint32Array(32)
  window.crypto.getRandomValues(array)
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('')
}

function sha256(plain) {
  const encoder = new TextEncoder()
  const data = encoder.encode(plain)
  return window.crypto.subtle.digest('SHA-256', data)
}

function base64url_encode(str) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function pkce_verifier_to_challenge(v) {
  const hashed = await sha256(v)
  return base64url_encode(hashed)
}

async function redirect_to_oauth_authorization() {
  const state = random()
  const code_verifier = random()

  STORAGE.setItem(`${STATE_PREFIX}:state`, state)
  STORAGE.setItem(`${STATE_PREFIX}:pkce_code_verifier`, code_verifier)

  // Build the authorization URL
  const param = new URLSearchParams()
  param.append('response_type', 'code')
  param.append('client_id', CONFIG.client_id)
  param.append('state', state)
  param.append('scope', CONFIG.requested_scopes)
  param.append('redirect_uri', CONFIG.redirect_uri)
  param.append('code_challenge', await pkce_verifier_to_challenge(code_verifier))
  param.append('code_challenge_method', 'S256')

  // Redirect to the authorization server
  window.location.href = `${CONFIG.authorization_endpoint}?${param}`
  await never_returns()
}

async function handle_oauth_return() {
  const u = new URL(window.location)
  const p = key => u.searchParams.get(key)

  const state = STORAGE.getItem(`${STATE_PREFIX}:state`)
  const code_verifier = STORAGE.getItem(`${STATE_PREFIX}:pkce_code_verifier`)

  // Clean these up since we don't need them anymore
  STORAGE.removeItem(`${STATE_PREFIX}:state`)
  STORAGE.removeItem(`${STATE_PREFIX}:pkce_code_verifier`)

  // If there's no oauth 'state' parameter, there's nothing to do.
  if (!p("state"))
    return null

  if (state != p("state")) {
    // If the state doesn't match the locally saved state,
    // we have to abort the flow. Someone might have started
    // it without our knowledge.
    console.log("Invalid state")
    return null
  } else if (p("error")) {
    // If there's an error response, print it out
    alert(p("error_description"))
    window.location.href = CONFIG.web_root
    await never_returns()
  } else if (p("code")) {
    // Exchange the authorization code for an access token
    const param = new URLSearchParams()
    param.append('grant_type', 'authorization_code')
    param.append('code', p("code"))
    param.append('client_id', CONFIG.client_id)
    param.append('redirect_uri', CONFIG.redirect_uri)
    param.append('code_verifier', code_verifier)
    const resp = await fetch(CONFIG.token_endpoint, {
      method: 'POST',
      body: param,
    })
    let data = await resp.json()
    return data.access_token
  }
}
//----------------------

async function wipe_login_and_goto(target) {
  console.log("removing access token")
  try {
    await fetch(window.CONFIG.api_root + 'session/destroy', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${STORAGE.getItem('access_token')}`,
      }
    })
  } catch (e) {
    console.log('cannot destroy session', e)
  }
  STORAGE.removeItem('access_token')
  window.location.href = target || CONFIG.app_root
  await never_returns()
}

async function logout(force_hosted) {
  const return_to_hosted_on_logout = STORAGE.getItem('return-to-hosted-on-logout') != null
  if (return_to_hosted_on_logout || force_hosted) {
    STORAGE.removeItem('return-to-hosted-on-logout')
    await wipe_login_and_goto(CONFIG.web_root)
  } else {
    await wipe_login_and_goto()
  }
}

async function probe_login_state(force_login) {
  let access_token = await handle_oauth_return()
  if (access_token) {
    STORAGE.setItem('access_token', access_token)

    let next = STORAGE.getItem('next')
    if (next) {
      STORAGE.removeItem('next')
      window.history.replaceState({}, '', CONFIG.app_root + next)
    } else {
      window.history.replaceState({}, '', CONFIG.app_root)
    }
    return access_token
  }

  access_token = STORAGE.getItem('access_token')
  if (access_token) {
    return access_token
  }

  const u = new URL(window.location)
  if (u.searchParams.get("source") == "ib") {
    STORAGE.setItem('return-to-hosted-on-logout', '1')
    return await redirect_to_oauth_authorization()
  }

  if (force_login) {
    return await redirect_to_oauth_authorization()
  }

  return null
}

async function http(method, path, body) {
  let headers = {}
  let bearer = STORAGE.getItem('access_token')
  if (bearer) {
    headers['Authorization'] = `Bearer ${bearer}`
  }
  let params = {
    method: method,
    headers: headers,
  }
  if (body) {
    let formdata = new FormData()
    for (let k in body) {
      formdata.append(k, body[k])
    }
    params.body = formdata
  }
  while (true) {
    let r = await fetch(window.CONFIG.api_root + path, params)
    if (r.status == 429) {
      let delay = parseInt(r.headers.get('Retry-After'))
      if (isNaN(delay))
        delay = 5
      await sleep(delay * 1000)
      continue
    } else if (r.status == 401) {
      await wipe_login_and_goto()
    } else if (r.status == 403) {
      alert(`Access to ${path} denied`)
      return null
    }
    return await r.json()
  }
}

if ('serviceWorker' in navigator) {
   navigator.serviceWorker.register("/sw.js");
}

const app = Vue.createApp({})

app.component('app', {
  template: `
    <div class='app'>
      <template v-if='!standalone'>
        <p>
          Please install this page as a web app on your mobile device.
        </p>
        <ol>
          <li>On iOS: Tap the share button below, then click on <strong>Add to Home Screen</strong>.</li>
          <li>On Android: Open your browser's settings. Scroll down and tap <strong>Add to Home screen</strong>.</li>
        </ol>
      </template>
      <template v-else-if='!logged_in'>
        <button class='main-action' @click='login'>
          Log into your account
        </button>
      </template>
      <template v-else>
        <div class='horizontal'>
          <select v-model='selected_device_id' class='main-action'>
            <option :value='null' disabled>Select online device to control</option>
            <option
              v-for='device in devices'
              :value='device.id'
            >{{device.description}} ({{device.serial}}) - {{device.setup.name}}</option>
          </select>
          <button class='main-action' @click='logout' v-if='false'>
            Logout
          </button>
        </div>
        <div class='intro' v-if='selected_device_id==null'>
          ⌃<br/>
          Select device to control
        </div>
        <div class='control' v-else @touchstart.self.prevent @touchmove.self.prevent @touchend.self.stop>
          <div class='btn'
            @mousedown.prevent='event($event, "up")'
            @touchstart.prevent='event($event, "up")'
          >
            ▲
          </div>
          <div class='horizontal'>
            <div class='btn'
              @mousedown.prevent='event($event, "left")'
              @touchstart.prevent='event($event, "left")'
            >
              ◄
            </div>
            <div class='btn'
              @mousedown.prevent='event($event, "right")'
              @touchstart.prevent='event($event, "right")'
            >
              ►
            </div>
          </div>
          <div class='btn'
            @mousedown.prevent='event($event, "down")'
            @touchstart.prevent='event($event, "down")'
          >
            ▼
          </div>
        </div>
      </template>
    </div>
  `,
  data: () => ({
    devices: [],
    selected_device_id: null,
    logged_in: false,
    standalone: (
      window.matchMedia('(display-mode: standalone)').matches ||
      (
        ("standalone" in window.navigator) && window.navigator.standalone
      )
    ),
  }),
  created() {
    this.init()
  },
  methods: {
    async login() {
      await redirect_to_oauth_authorization()
    },
    async logout() {
      await logout()
    },
    async init() {
      let access_token = await probe_login_state(false)
      this.logged_in = access_token != null
      if (this.logged_in) {
        let r = await http('GET', 'device/list?filter:is_online=true')
        this.devices = r.devices
      }
    },
    async event(e, event) {
      e.target.style.animation="";
      let r = await http('POST', `device/${this.selected_device_id}/node/root/event/keyboard`, {
        data: JSON.stringify({
          key: event,
          action: 'down',
        })
      })
      if (r.ok) {
        e.target.style.animation="success 0.3s linear 1";
      } else {
        e.target.style.animation="error 0.3s linear 1";
      }
    },
  },
})


app.mount('#app')

})()
