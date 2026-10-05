import { configuration } from './config.js';
import { createContext } from './context.js';
import { buildApp } from './app.js';
import { Worker } from './worker.js';
import { failure } from './errors.js';

const config=await configuration(),context=await createContext(config),app=await buildApp(context);
const worker=new Worker(context,error=>app.log.error({code:failure(error).code},'Background operation failed'));
await app.listen({host:config.FOUNDATION_HOST,port:config.FOUNDATION_PORT});worker.start();
let closing=false;
const close=async()=>{if(closing)return;closing=true;const timer=setTimeout(()=>process.exit(1),85_000);timer.unref();await worker.stop();await app.close();await context.db.close();clearTimeout(timer);};
process.once('SIGTERM',()=>{void close();});process.once('SIGINT',()=>{void close();});
