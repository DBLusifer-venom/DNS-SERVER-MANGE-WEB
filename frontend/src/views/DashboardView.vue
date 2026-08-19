<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const health = ref(null)

onMounted(async () => {
  try {
    const res = await api.get('/api/health')
    health.value = res.data
  } catch {
    health.value = null
  }
})
</script>

<template>
  <div>
    <h1>Dashboard</h1>
    <div class="panel">
      <h3>Backend status</h3>
      <p v-if="health" class="ok">
        {{ health.app }} — {{ health.status }} (v0.1.0)
      </p>
      <p v-else class="error">Backend unreachable</p>
    </div>

    <div class="panel mt">
      <h3>Coming next (Phase 1b)</h3>
      <ul class="muted">
        <li>Zone registry: create zones via rndc addzone (inline-signing)</li>
        <li>Record editor (A, AAAA, MX, CNAME, TXT, …) via RFC 2136 updates</li>
        <li>DNSSEC status + DS export</li>
      </ul>
    </div>
  </div>
</template>