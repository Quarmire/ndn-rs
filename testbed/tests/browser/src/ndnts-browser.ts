// NDNts browser bundle entry point.
// Exports are accessible in tests as window.NDNts.{WsTransport, consume, produce, ...}
//
// Keep this list minimal — only what ws-transport.spec.ts needs.
// esbuild bundles this into fixture-page/ndnts.bundle.js as an IIFE.

import { WsTransport } from "@ndn/ws-transport";
import { consume, produce } from "@ndn/endpoint";
import { Data, Interest, Name, Component } from "@ndn/packet";
import { Encoder } from "@ndn/tlv";

export { WsTransport, consume, produce, Data, Interest, Name, Component, Encoder };

/**
 * Send a rib/register Interest to ndn-fwd so that Interests matching `prefix`
 * are forwarded to this face.
 *
 * NDNts's WsTransport.createFace() sets advertiseFrom:false on the transport
 * face, so produce() never emits a rib/register automatically.  We must send
 * one explicitly before calling produce().
 *
 * Wire format per the NFD management protocol:
 *   Interest name: /localhost/nfd/rib/register/<ControlParams>
 *   ControlParams: full TLV block (type=0x68) containing a Name TLV (0x07).
 *   The ControlParams block is the VALUE of a GenericNameComponent (0x08).
 */
export async function ribRegister(prefix: string): Promise<void> {
  const prefixName = Name.from(prefix);

  // Encode the Name TLV (0x07 + length + components).
  const nameBytes: Uint8Array = Encoder.encode(prefixName);

  // Build ControlParameters TLV: 0x68 + length + nameBytes.
  const cpLen = nameBytes.length;
  let cpBytes: Uint8Array;
  if (cpLen < 0xfd) {
    cpBytes = new Uint8Array(2 + cpLen);
    cpBytes[0] = 0x68;
    cpBytes[1] = cpLen;
    cpBytes.set(nameBytes, 2);
  } else {
    cpBytes = new Uint8Array(4 + cpLen);
    cpBytes[0] = 0x68;
    cpBytes[1] = 0xfd;
    cpBytes[2] = (cpLen >> 8) & 0xff;
    cpBytes[3] = cpLen & 0xff;
    cpBytes.set(nameBytes, 4);
  }

  // /localhost/nfd/rib/register/<ControlParams-as-GenericNameComponent>
  const regName = Name.from("/localhost/nfd/rib/register").append(
    new Component(0x08, cpBytes),
  );

  const interest = new Interest(regName);
  interest.lifetime = 4000;
  await consume(interest);
}
