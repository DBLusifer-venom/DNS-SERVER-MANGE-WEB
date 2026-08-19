import { defineStore } from 'pinia'
import { api, setTokens, clearTokens } from '../api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    accessToken: localStorage.getItem('access_token') || null,
    refreshToken: localStorage.getItem('refresh_token') || null,
    user: JSON.parse(localStorage.getItem('user') || 'null'),
  }),
  actions: {
    async login(username, password) {
      const res = await api.post('/api/auth/login', { username, password })
      this.applyTokens(res.data)
      this.user = res.data.user ? res.data.user : await this.fetchMe()
    },
    async fetchMe() {
      const res = await api.get('/api/auth/me')
      this.user = res.data
      localStorage.setItem('user', JSON.stringify(this.user))
      return this.user
    },
    applyTokens(data) {
      this.accessToken = data.access_token
      this.refreshToken = data.refresh_token
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      setTokens(data.access_token, data.refresh_token)
    },
    async logout() {
      try {
        if (this.refreshToken) await api.post('/api/auth/logout', { refresh_token: this.refreshToken })
      } catch {
        /* ignore */
      }
      clearTokens()
      this.accessToken = null
      this.refreshToken = null
      this.user = null
      localStorage.removeItem('user')
    },
  },
})