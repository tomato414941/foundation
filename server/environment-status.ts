export interface EnvironmentHeartbeat {
  heartbeat_at: Date | null;
  stopped_at: Date | null;
}

export function environmentConnected(environment: EnvironmentHeartbeat | undefined, now = Date.now()) {
  return Boolean(environment?.heartbeat_at && !environment.stopped_at &&
    now - environment.heartbeat_at.getTime() <= 90_000);
}
