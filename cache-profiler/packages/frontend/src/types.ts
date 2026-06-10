import type { Caido } from "@caido/sdk-frontend";

import type { API, BackendEvents } from "@cache-profiler/backend";

export type FrontendSDK = Caido<API, BackendEvents>;
