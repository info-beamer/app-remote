console.log('yo')

self.addEventListener('install', event => {
  console.log('service worker install')
})

self.addEventListener('fetch', event => 
  event.respondWith(fetch(event.request))
)
