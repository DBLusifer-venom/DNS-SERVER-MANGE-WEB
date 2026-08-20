import { defineStore } from 'pinia'
import { api, setAccessToken, clearAccessToken } from '../api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    accessToken: null,
    user: null,
    ready: false,
  }),
  actions: {
    /** Restore a session on page load: try the HttpOnly refresh cookie. */
    async bootstrap() {
      if (this.accessToken) {
        try {
          this.user = (await api.get('/api/auth/me')).data
        } catch {
          this.user = null
        }
        this.ready = true
        return
      }
      try {
        const res = await api.post('/api/auth/refresh')
        this.applyTokens(res.data)
        this.user = (await api.get('/api/auth/me')).data
      } catch {
        /* no session */
      }
      this.ready = true
    },
    async login(username, password) {
      const res = await api.post('/api/auth/login', { username, password })
      this.applyTokens(res.data)
      this.user = (await api.get('/api/auth/me')).data
    },
    applyTokens(data) {
      this.accessToken = data.access_token
      setAccessToken(data.access_token)
    },
    async logout() {
      try {
        await api.post('/api/auth/logout')
      } catch {
        /* ignore */
      }
      clearAccessToken()
      this.accessToken = null
      this.user = null
    },
  },
})