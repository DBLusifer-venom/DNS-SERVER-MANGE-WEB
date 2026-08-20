import axios from 'axios'

// Access token lives in memory only (never localStorage).
// Refresh token lives in an HttpOnly Secure SameSite cookie set by the backend.
export const api = axios.create({ baseURL: '/', withCredentials: true })

let accessToken = null
let refreshPromise = null

export function setAccessToken(token) {
  accessToken = token
}

export function clearAccessToken() {
  accessToken = null
}

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true
      try {
        if (!refreshPromise) {
          // No token in the body: the HttpOnly cookie is sent automatically.
          refreshPromise = api
            .post('/api/auth/refresh')
            .then((r) => r.data)
            .finally(() => (refreshPromise = null))
        }
        const data = await refreshPromise
        setAccessToken(data.access_token)
        original.headers.Authorization = `Bearer ${data.access_token}`
        return api(original)
      } catch {
        clearAccessToken()
        if (window.location.pathname !== '/login') window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)