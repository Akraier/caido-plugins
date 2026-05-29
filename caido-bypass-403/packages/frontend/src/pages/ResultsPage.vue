<script setup lang="ts">
import { computed, ref } from "vue";

import Button from "primevue/button";
import Card from "primevue/card";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import InputText from "primevue/inputtext";
import Tag from "primevue/tag";
import ToggleButton from "primevue/togglebutton";

import { resultsStore } from "../stores/results";
import type { FrontendSDK, ResultRow } from "../types";

const props = defineProps<{ sdk: FrontendSDK }>();

const onlyInteresting = ref(true);
const search = ref("");

const filteredRows = computed<ResultRow[]>(() => {
  const term = search.value.trim().toLowerCase();
  return resultsStore.state.rows.filter((row) => {
    if (onlyInteresting.value && !row.interesting) return false;
    if (term.length === 0) return true;
    return (
      row.url.toLowerCase().includes(term) ||
      row.detail.toLowerCase().includes(term) ||
      row.variation.toLowerCase().includes(term) ||
      String(row.statusCode).includes(term)
    );
  });
});

const jobsList = computed(() => {
  return Array.from(resultsStore.state.jobs.values()).sort((a, b) => b.startedAt - a.startedAt);
});

const statusSeverity = (status: number, baseline: number): string => {
  if (status === baseline) return "secondary";
  if (status >= 200 && status < 300) return "success";
  if (status >= 300 && status < 400) return "info";
  if (status === 401 || status === 403) return "warn";
  if (status >= 400 && status < 500) return "warn";
  if (status >= 500) return "danger";
  return "secondary";
};

const sendToReplay = async (row: ResultRow): Promise<void> => {
  if (row.requestId === undefined) {
    props.sdk.window.showToast("No saved request id for this probe", { variant: "warning" });
    return;
  }
  await props.sdk.replay.createSession({ type: "ID", id: row.requestId });
  props.sdk.window.showToast("Sent to Replay", { variant: "success" });
};

const clearAll = (): void => {
  resultsStore.clear();
};

const openSettings = (): void => {
  props.sdk.navigation.goTo("/bypass-403/settings");
};
</script>

<template>
  <div class="h-full p-4 flex flex-col gap-3 bg-surface-800 text-surface-0">
    <Card
      class="shrink-0"
      :pt="{ body: { class: 'p-3' }, content: { class: 'flex flex-col gap-2' } }"
    >
      <template #content>
        <div class="flex items-center gap-3 flex-wrap">
          <div class="flex items-center gap-2">
            <i class="fas fa-unlock text-primary-400"></i>
            <span class="font-semibold">Bypass 403/401</span>
          </div>
          <div class="flex-1"></div>
          <ToggleButton
            v-model="onlyInteresting"
            onLabel="Interesting only"
            offLabel="All probes"
            onIcon="fas fa-filter"
            offIcon="fas fa-list"
          />
          <InputText
            v-model="search"
            placeholder="Filter: url, header, ip, status"
            class="w-80"
          />
          <Button label="Settings" icon="fas fa-cog" severity="secondary" @click="openSettings" />
          <Button label="Clear" icon="fas fa-trash" severity="secondary" @click="clearAll" />
        </div>
        <div v-if="jobsList.length > 0" class="text-xs text-surface-300 flex flex-wrap gap-3">
          <span v-for="job in jobsList.slice(0, 3)" :key="job.jobId" class="flex items-center gap-1">
            <i class="fas fa-circle text-[6px]" :class="job.doneAt !== undefined ? 'text-green-400' : 'text-amber-400'"></i>
            <span class="font-mono">{{ job.targetUrl }}</span>
            <span>baseline {{ job.baselineStatus }} ({{ job.baselineLength }}B)</span>
            <span v-if="job.doneAt !== undefined">→ {{ job.interestingCount }}/{{ job.total }} interesting</span>
            <span v-else>→ running</span>
          </span>
        </div>
      </template>
    </Card>

    <Card
      class="flex-1 min-h-0"
      :pt="{ body: { class: 'h-full p-0' }, content: { class: 'h-full flex flex-col p-0' } }"
    >
      <template #content>
        <DataTable
          :value="filteredRows"
          stripedRows
          scrollable
          scrollHeight="flex"
          :rowHover="true"
          dataKey="receivedAt"
          sortField="receivedAt"
          :sortOrder="-1"
          class="h-full"
        >
          <template #empty>
            <div class="flex flex-col items-center justify-center py-10 text-surface-400">
              <i class="fas fa-radar text-3xl mb-2"></i>
              <div>No bypass probes yet.</div>
              <div class="text-xs">
                Right-click a 401/403 request → "Run 403/401 bypass on this request"
              </div>
            </div>
          </template>

          <Column field="statusCode" header="Status" sortable style="width: 90px">
            <template #body="{ data }">
              <Tag
                :value="data.statusCode === 0 ? 'ERR' : data.statusCode"
                :severity="statusSeverity(data.statusCode, data.baselineStatus)"
              />
            </template>
          </Column>
          <Column field="contentLength" header="Len" sortable style="width: 90px">
            <template #body="{ data }">
              <span class="font-mono text-xs">{{ data.contentLength }}</span>
            </template>
          </Column>
          <Column field="variation" header="Vector" sortable style="width: 180px">
            <template #body="{ data }">
              <span class="font-mono text-xs">{{ data.variation }}</span>
            </template>
          </Column>
          <Column field="detail" header="Value" sortable style="width: 220px">
            <template #body="{ data }">
              <span class="font-mono text-xs">{{ data.detail }}</span>
            </template>
          </Column>
          <Column field="method" header="M" style="width: 60px">
            <template #body="{ data }">
              <span class="font-mono text-xs">{{ data.method }}</span>
            </template>
          </Column>
          <Column field="url" header="URL">
            <template #body="{ data }">
              <span class="font-mono text-xs break-all">{{ data.url }}</span>
            </template>
          </Column>
          <Column header="" style="width: 90px">
            <template #body="{ data }">
              <Button
                v-if="data.requestId !== undefined"
                icon="fas fa-paper-plane"
                text
                rounded
                size="small"
                aria-label="Send to Replay"
                @click="sendToReplay(data)"
              />
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>
  </div>
</template>
