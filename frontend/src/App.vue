<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const isPublic = computed(() => route.meta.public)

async function logout() {
  await auth.logout()
  router.push({ name: 'login' })
}
</script>

<template>
  <div v-if="!isPublic" class="layout">
    <nav>
      <div class="brand">SecureDNS</div>
      <router-link to="/">Dashboard</router-link>
      <router-link v-if="['admin', 'operator'].includes(auth.user?.role)" to="/servers">Servers</router-link>
      <router-link v-if="auth.user?.role === 'admin'" to="/users">Users</router-link>
      <router-link v-if="['admin', 'operator'].includes(auth.user?.role)" to="/audit">Audit Log</router-link>
      <div class="spacer"></div>
      <span class="muted small">{{ auth.user?.username }} ({{ auth.user?.role }})</span>
      <button @click="logout" class="danger">Logout</button>
    </nav>
    <main>
      <router-view />
    </main>
  </div>
  <router-view v-else />
</template>

<style scoped>
.layout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

nav {
  display: flex;
  align-items: center;
  gap: 1.25rem;
  padding: 0.75rem 1.5rem;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
}

.brand {
  font-weight: 700;
  color: var(--accent);
  font-size: 1.05rem;
}

.spacer {
  flex: 1;
}

main {
  padding: 1.5rem;
  max-width: 1100px;
  width: 100%;
  margin: 0 auto;
}
</style>