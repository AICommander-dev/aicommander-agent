import os from "os";
import { MAX_LOCAL_IPS } from "@aicommander/protocol";

/**
 * The machine's own IP addresses, for TELLING MACHINES APART.
 *
 * The relay publishes what this returns in `list_machines` / `session_status`
 * beside the hostname, and that is the whole job: an account with eleven boxes
 * called aic-wfs-pc, aic-wfs-pc2, aic-wfs-pc3 cannot tell from a list which
 * physical machine is which, and an address on the user's own LAN is the thing
 * they recognize. It is DESCRIPTIVE metadata, never a capability and never a
 * route: nothing may try to reach a machine at one of these (they are private
 * addresses on the machine's side of a NAT, and the relay is the only path in).
 *
 * Same three properties the GPU probe has, for the same reason — it runs on the
 * registration path:
 *  - it must NEVER throw (a platform that reports an interface shape we did not
 *    expect must cost us a field, not a registration);
 *  - it must NEVER block (os.networkInterfaces() is a synchronous syscall, which
 *    is why registration can afford to call it on every register frame and always
 *    advertise CURRENT addresses rather than ones cached at process start);
 *  - it must NEVER log an address.
 */

/**
 * Interfaces whose addresses describe a virtual network on this machine rather
 * than the machine's place on a real one: container bridges (docker0, br-…,
 * veth…, virbr…), hypervisor host adapters (vmnet…, vboxnet…, Windows'
 * "vEthernet (WSL)" / "vEthernet (Default Switch)"), tunnels (tun/tap/utun) and
 * Apple's peer-to-peer radios (awdl0, llw0).
 *
 * Deprioritized, NOT banned: this is a heuristic over adapter names, and a
 * machine whose only address lives behind one of these names (a container host,
 * a box reachable solely over a VPN) must still report SOMETHING — an empty list
 * reads as "not reported" and helps nobody. So these sort last and are used when
 * nothing better exists.
 */
const VIRTUAL_INTERFACE =
  /^(docker|br-|veth|virbr|vmnet|vboxnet|vnic|tun\d|tap\d|utun|awdl|llw|zt|vEthernet)/i;

/** IPv4 auto-configuration (169.254.0.0/16): an address that means "no DHCP answered". */
const IPV4_LINK_LOCAL = /^169\.254\./;
/** IPv6 link-local (fe80::/10) — per-link, identical-looking on every machine. */
const IPV6_LINK_LOCAL = /^fe[89ab]/i;

interface Candidate {
  address: string;
  /** Virtual adapters sort last (see VIRTUAL_INTERFACE). */
  virtual: boolean;
}

/** Node reports `family` as "IPv4"/"IPv6" (and, on older shapes, 4/6). */
function isIPv4(family: string | number): boolean {
  return family === "IPv4" || family === 4;
}

/**
 * Non-loopback, non-link-local addresses of this machine, best first, capped at
 * MAX_LOCAL_IPS. Returns `[]` when there is nothing we are confident about —
 * callers must then OMIT the field rather than send an empty array, because
 * absent means "not reported" on the wire and `[]` would claim the machine has
 * no addresses (see AgentRegisterMsg.localIps).
 *
 * Two rules, applied in this order:
 *
 *  1. PHYSICAL BEFORE VIRTUAL, whatever the family. A physical adapter's address
 *     is the one that tells this box from the next one; docker0's 172.17.0.1 is
 *     the same on every machine that runs Docker. Choosing the family first would
 *     make an IPv6-only host with a container bridge report only the bridge and
 *     throw away the single address that identifies it.
 *  2. Within a tier, IPv4 wins outright: it is what a user recognizes as "the
 *     address of that box on my network", and a typical host also carries several
 *     IPv6 addresses (global, temporary/privacy, ULA) that would bury it. IPv6 is
 *     reported only when that tier has no IPv4 at all, so a v6-only host still
 *     identifies itself.
 *
 * The virtual tier is still appended after the physical one (deprioritized, not
 * banned — see VIRTUAL_INTERFACE), so a container host with nothing else keeps
 * reporting something.
 *
 * The interface table is a parameter for the tests; when it is omitted the
 * enumeration happens INSIDE the protected region below, because
 * os.networkInterfaces() is itself a syscall that may fail and this runs on the
 * registration path — it must cost a field, never the registration. (A default
 * parameter value would be evaluated before the body, outside the `try`.)
 */
export function collectLocalIps(interfaces?: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string[] {
  try {
    const table = interfaces === undefined ? os.networkInterfaces() : interfaces;
    const v4: Candidate[] = [];
    const v6: Candidate[] = [];
    for (const [name, entries] of Object.entries(table)) {
      if (!entries) continue;
      const virtual = VIRTUAL_INTERFACE.test(name);
      for (const entry of entries) {
        // `internal` is loopback (127.0.0.1, ::1) — every machine has it and it
        // identifies none of them.
        if (!entry || entry.internal || typeof entry.address !== "string") continue;
        const address = entry.address;
        if (isIPv4(entry.family)) {
          if (IPV4_LINK_LOCAL.test(address)) continue;
          v4.push({ address, virtual });
        } else {
          if (IPV6_LINK_LOCAL.test(address)) continue;
          v6.push({ address, virtual });
        }
      }
    }
    // Family is decided per tier, so a physical address never loses to a virtual
    // one of a different family.
    const tier = (virtual: boolean): string[] => {
      const fours = v4.filter((c) => c.virtual === virtual);
      const sixes = v6.filter((c) => c.virtual === virtual);
      return (fours.length > 0 ? fours : sixes).map((c) => c.address);
    };
    // De-duplicate: the same address can be enumerated twice (aliases, a bridge
    // sharing a subnet).
    return [...new Set([...tier(false), ...tier(true)])].slice(0, MAX_LOCAL_IPS);
  } catch {
    return [];
  }
}

/**
 * The `localIps` key for an agent:register frame, or nothing — spread into the
 * message. Keeps the "never send `[]`" rule in ONE place, next to the collector
 * it belongs to, instead of at every call site that builds a register frame.
 */
export function localIpsField(): { localIps?: string[] } {
  const localIps = collectLocalIps();
  return localIps.length > 0 ? { localIps } : {};
}
