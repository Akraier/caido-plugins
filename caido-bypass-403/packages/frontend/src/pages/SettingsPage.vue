<script setup lang="ts">
import { computed, reactive, watch } from "vue";

import Button from "primevue/button";
import Card from "primevue/card";
import Checkbox from "primevue/checkbox";
import InputNumber from "primevue/inputnumber";
import ToggleSwitch from "primevue/toggleswitch";

import EditableList from "../components/EditableList.vue";
import { settingsStore, type Settings } from "../stores/settings";
import type { FrontendSDK } from "../types";

const props = defineProps<{ sdk: FrontendSDK }>();

const draft = reactive<Settings>({
  headers: [],
  ips: [],
  pathMutationIds: [],
  autoMode: false,
  scopeGated: true,
  concurrency: 8,
});

const syncFromStore = (): void => {
  const s = settingsStore.state.settings;
  draft.headers = [...s.headers];
  draft.ips = [...s.ips];
  draft.pathMutationIds = [...s.pathMutationIds];
  draft.autoMode = s.autoMode;
  draft.scopeGated = s.scopeGated;
  draft.concurrency = s.concurrency;
};

watch(
  () => settingsStore.state.loaded,
  (loaded) => {
    if (loaded) syncFromStore();
  },
  { immediate: true },
);

const pathMutations = computed(() => settingsStore.state.defaults.pathMutations);

const totalProbes = computed(() => {
  return draft.headers.length * draft.ips.length + draft.pathMutationIds.length;
});

const toggleMutation = (id: string, checked: boolean): void => {
  if (checked) {
    if (!draft.pathMutationIds.includes(id)) draft.pathMutationIds.push(id);
  } else {
    draft.pathMutationIds = draft.pathMutationIds.filter((x) => x !== id);
  }
};

const save = async (): Promise<void> => {
  await settingsStore.save(props.sdk, { ...draft });
};

const resetDefaults = async (): Promise<void> => {
  const fresh = settingsStore.resetToDefaults();
  await settingsStore.save(props.sdk, fresh);
  syncFromStore();
};

const backToResults = (): void => {
  props.sdk.navigation.goTo("/bypass-403");
};
</script>

<template>
  <div class="h-full p-4 flex flex-col gap-3 bg-surface-800 text-surface-0 overflow-auto">
    <Card :pt="{ body: { class: 'p-3' }, content: { class: 'flex items-center gap-3' } }">
      <template #content>
        <Button label="Back to results" icon="fas fa-arrow-left" severity="secondary" @click="backToResults" />
        <div class="flex-1"></div>
        <span class="text-xs text-surface-300">~{{ totalProbes }} probes per run</span>
        <Button label="Reset to defaults" icon="fas fa-rotate-left" severity="secondary" @click="resetDefaults" />
        <Button label="Save" icon="fas fa-save" @click="save" />
      </template>
    </Card>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
      <Card :pt="{ body: { class: 'p-3' } }">
        <template #title>Headers</template>
        <template #subtitle>
          <span class="text-xs">Header names tested for IP-spoof / host-override bypass. One per line.</span>
        </template>
        <template #content>
          <EditableList
            v-model="draft.headers"
            label="Bypass headers"
            placeholder="X-Forwarded-For&#10;X-Real-IP&#10;X-Original-URL"
          />
        </template>
      </Card>

      <Card :pt="{ body: { class: 'p-3' } }">
        <template #title>IPs / Hostnames</template>
        <template #subtitle>
          <span class="text-xs">Each header is paired with every value here. One per line.</span>
        </template>
        <template #content>
          <EditableList
            v-model="draft.ips"
            label="Header values"
            placeholder="127.0.0.1&#10;localhost&#10;169.254.169.254"
          />
        </template>
      </Card>

      <Card :pt="{ body: { class: 'p-3' } }">
        <template #title>Path mutations</template>
        <template #subtitle>
          <span class="text-xs">URL-level bypass tricks applied to the request path.</span>
        </template>
        <template #content>
          <div class="flex flex-col gap-2">
            <div
              v-for="mut in pathMutations"
              :key="mut.id"
              class="flex items-center gap-2"
            >
              <Checkbox
                :modelValue="draft.pathMutationIds.includes(mut.id)"
                :inputId="`mut-${mut.id}`"
                binary
                @update:modelValue="(v) => toggleMutation(mut.id, v as boolean)"
              />
              <label :for="`mut-${mut.id}`" class="font-mono text-xs cursor-pointer">{{ mut.label }}</label>
            </div>
          </div>
        </template>
      </Card>

      <Card :pt="{ body: { class: 'p-3' } }">
        <template #title>Engine</template>
        <template #subtitle>
          <span class="text-xs">Auto-mode + scope + concurrency.</span>
        </template>
        <template #content>
          <div class="flex flex-col gap-4">
            <div class="flex items-center gap-3">
              <ToggleSwitch v-model="draft.autoMode" inputId="auto" />
              <label for="auto" class="text-sm">
                Auto-trigger on intercepted 401/403 responses
              </label>
            </div>
            <div class="flex items-center gap-3">
              <ToggleSwitch v-model="draft.scopeGated" inputId="scope" />
              <label for="scope" class="text-sm">
                Auto-mode only fires on in-scope hosts
              </label>
            </div>
            <div class="flex items-center gap-3">
              <label for="conc" class="text-sm w-40">Concurrency</label>
              <InputNumber
                v-model="draft.concurrency"
                inputId="conc"
                :min="1"
                :max="32"
                showButtons
                buttonLayout="horizontal"
              />
            </div>
            <div class="text-xs text-surface-400">
              Marker header <span class="font-mono">X-Bypass-403-Probe</span> is added to every probe so auto-mode never recurses on its own traffic.
            </div>
          </div>
        </template>
      </Card>
    </div>
  </div>
</template>
