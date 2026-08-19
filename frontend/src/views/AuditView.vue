<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'

const entries = ref([])
const actionFilter = ref('')
const actions = ref([])

async function load() {
  const params = actionFilter.value ? { action: actionFilter.value } : {}
  const res = await api.get('/api/audit', { params })
  entries.value = res.data
  if (!actions.value.length) {
    actions.value = [...new Set(res.data.map((e) => e.action))].sort()
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="row spread">
      <h1>Audit Log</h1>
      <div class="row">
        <label class="small" for="action">Filter:</label>
        <select id="action" v-model="actionFilter" @change="load">
          <option value="">all actions</option>
          <option v-for="a in actions" :key="a" :value="a">{{ a }}</option>
        </select>
      </div>
    </div>

    <div class="panel mt">
      <table>
        <thead>
          <tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>IP</th></tr>
        </thead>
        <tbody>
          <tr v-for="e in entries" :key="e.id">
            <td class="small muted">{{ new Date(e.created_at).toLocaleString() }}</td>
            <td>{{ e.user_id ?? '—' }}</td>
            <td><span class="badge">{{ e.action }}</span></td>
            <td>{{ e.resource_type }}<span v-if="e.resource_id">: {{ e.resource_id }}</span></td>
            <td class="muted">{{ e.ip_address }}</td>
          </tr>
          <tr v-if="!entries.length"><td colspan="5" class="muted">No audit entries</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>