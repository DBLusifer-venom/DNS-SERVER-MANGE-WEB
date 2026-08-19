import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { public: true } },
  { path: '/', name: 'dashboard', component: () => import('./views/DashboardView.vue') },
  { path: '/servers', name: 'servers', component: () => import('./views/ServersView.vue'), meta: { roles: ['admin', 'operator'] } },
  { path: '/users', name: 'users', component: () => import('./views/UsersView.vue'), meta: { roles: ['admin'] } },
  { path: '/audit', name: 'audit', component: () => import('./views/AuditView.vue'), meta: { roles: ['admin', 'operator'] } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.accessToken) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (to.meta.roles && !to.meta.roles.includes(auth.user?.role)) {
    return { name: 'dashboard' }
  }
})

export default router