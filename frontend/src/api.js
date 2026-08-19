import axios from 'axios'

export const api = axios.create({ baseURL: '/' })

let accessToken = localStorage.getItem('access_token') || null
let refreshToken = localStorage.getItem('refresh_token') || null
let refreshPromise = null

export function setTokens(access, refresh) {
  accessToken = access
  refreshToken = refresh
}

export function clearTokens() {
  accessToken = null
  refreshToken = null
}

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry && refreshToken) {
      original._retry = true
      try {
        if (!refreshPromise) {
          refreshPromise = axios
            .post('/api/auth/refresh', { refresh_token: refreshToken })
            .then((r) => r.data)
            .finally(() => (refreshPromise = null))
        }
        const data = await refreshPromise
        setTokens(data.access_token, data.refresh_token)
        localStorage.setItem('access_token', data.access_token)
        localStorage.setItem('refresh_token', data.refresh_token)
        original.headers.Authorization = `Bearer ${data.access_token}`
        return api(original)
      } catch {
        clearTokens()
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        localStorage.removeItem('user')
        if (window.location.pathname !== '/login') window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)