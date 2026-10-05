import type { Context } from './context.js';

export class Worker {
  private stopped = true;
  private timers = new Set<NodeJS.Timeout>();
  private tasks = new Set<Promise<void>>();
  constructor(
    readonly context: Context,
    readonly reportError: (error: unknown) => void,
  ) {}
  private schedule(work: () => Promise<unknown>, milliseconds: number) {
    const run = () => {
      if (this.stopped) return;
      const task = Promise.resolve()
        .then(work)
        .then(
          () => {},
          (error) => this.reportError(error),
        )
        .finally(() => {
          this.tasks.delete(task);
          if (!this.stopped) {
            const timer = setTimeout(() => {
              this.timers.delete(timer);
              run();
            }, milliseconds);
            timer.unref();
            this.timers.add(timer);
          }
        });
      this.tasks.add(task);
    };
    run();
  }
  start() {
    if (!this.stopped) return;
    this.stopped = false;
    for (let index = 0; index < 4; index++) this.schedule(() => this.context.runs.tick(), 500);
    for (let index = 0; index < 2; index++) this.schedule(() => this.context.environments.tick(), 1000);
    this.schedule(() => this.context.runs.recover(), 15_000);
    this.schedule(() => this.context.integrations.deliver(), 2000);
    this.schedule(async () => {
      await this.context.environments.enforcePayment();
      await this.context.billing.measureStorage();
      await this.context.billing.report();
      await this.context.objects.collect();
    }, 60_000);
    this.schedule(async () => {
      await this.context.db.pool.query('DELETE FROM challenges WHERE expires_at<now()');
      await this.context.db.pool.query('DELETE FROM sessions WHERE expires_at<now()');
      await this.context.db.pool.query('DELETE FROM request_links WHERE expires_at<now()');
      await this.context.db.pool.query(
        "UPDATE approval_requests SET state='expired',private_input=NULL,continue_url=NULL WHERE state IN ('pending','running') AND expires_at<now()",
      );
    }, 60_000);
  }
  async stop() {
    this.stopped = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    await this.context.runs.shutdown();
    await Promise.allSettled([...this.tasks]);
  }
}
