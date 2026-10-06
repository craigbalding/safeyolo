// Retained Pi SDK protocol fixture; native process responses are synthetic.
// This invokes no model and does not claim provider authentication.
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
const root=fileURLToPath(new URL("../../",import.meta.url));
const packagePath=process.argv[2];assert.ok(packagePath,"Pass the installed pinned Pi package directory");
const requirePi=createRequire(resolve(packagePath,"package.json"));
const {createJiti}=requirePi("jiti");
const jiti=createJiti(import.meta.url,{alias:{"@earendil-works/pi-coding-agent":resolve(packagePath,"dist/core/extensions/types.js"),"@earendil-works/pi-ai":resolve(packagePath,"node_modules/@earendil-works/pi-ai/dist/compat.js")}});
await test("Pi tools preserve native canonical results",async()=>{
  const original=childProcess.spawn;const calls=[];let result={};let status=0;let errorText="";
  childProcess.spawn=(binary,args,options)=>{
    const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();let input="";
    child.stdin.on("data",chunk=>{input+=chunk;});
    child.stdin.on("finish",()=>{calls.push({binary,args,options,input:JSON.parse(input)});queueMicrotask(()=>{child.stdout.write(JSON.stringify(result));child.stderr.write(errorText);child.emit("close",status);});});return child;
  };
  syncBuiltinESMExports();
  try {
    const register=await jiti.import(resolve(root,"contrib/pi-coord-extension.ts"),{default:true});const tools=new Map();register({registerTool(tool){tools.set(tool.name,tool);}});
    assert.deepEqual([...tools.keys()].sort(),["read_room","send"]);
    const page={messages:[{sequence:42,sender_kind:"agent",sender_agent_name:"lens",body:"CHANGES_REQUIRED target=https://example.test/review/old\nThe specific prior finding"}],next_cursor:42,has_more:true,history_truncated:false};
    result=page;
    const read=await tools.get("read_room").execute("read-1",{room_name:"backlog",since_sequence:41,limit:1});
    assert.deepEqual(JSON.parse(read.content[0].text),page);assert.deepEqual(read.details,page);
    assert.deepEqual(calls.at(-1).args,["call","read_room"]);assert.deepEqual(calls.at(-1).input,{room_name:"backlog",since_sequence:41,limit:1});
    const sent={envelope:{body:"DONE",sender_agent_name:"forge",msg_id:"msg-fixture"},sequence:43,attention_status:"ready"};result=sent;
    const send=await tools.get("send").execute("send-1",{room_name:"backlog",body:"DONE",notify:["relay"]});
    assert.deepEqual(send.details,sent);assert.equal(calls.at(-1).binary,"/home/agent/.safeyolo/safeyolo-coord");assert.deepEqual(calls.at(-1).args,["call","send"]);
    status=1;errorText="API 403: room access denied";await assert.rejects(tools.get("read_room").execute("read-2",{room_name:"private"}),/403/);
    status=1;errorText="API 503: Coord unavailable; send outcome unknown";await assert.rejects(tools.get("send").execute("send-2",{room_name:"backlog",body:"uncertain"}),/unknown/);
    const abort=new AbortController();abort.abort();await assert.rejects(tools.get("read_room").execute("read-3",{room_name:"backlog"},abort.signal),{name:"AbortError"});
  }finally{childProcess.spawn=original;syncBuiltinESMExports();}
});
