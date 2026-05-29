<script setup lang="ts">
import { computed, ref, watch } from "vue";

import Button from "primevue/button";
import Textarea from "primevue/textarea";

const props = defineProps<{
  modelValue: string[];
  label: string;
  placeholder?: string;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: string[]];
}>();

const buffer = ref(props.modelValue.join("\n"));

watch(
  () => props.modelValue,
  (next) => {
    const incoming = next.join("\n");
    if (incoming !== buffer.value) buffer.value = incoming;
  },
);

const commit = (): void => {
  const lines = buffer.value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  emit("update:modelValue", lines);
};

const count = computed(() => {
  return buffer.value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0).length;
});
</script>

<template>
  <div class="flex flex-col gap-1">
    <div class="flex items-center justify-between">
      <label class="text-sm font-medium">{{ label }}</label>
      <span class="text-xs text-surface-400">{{ count }} entries</span>
    </div>
    <Textarea
      v-model="buffer"
      :placeholder="placeholder"
      rows="10"
      autoResize
      class="font-mono text-xs"
      @blur="commit"
    />
    <div class="flex justify-end">
      <Button label="Apply" size="small" severity="secondary" @click="commit" />
    </div>
  </div>
</template>
