import { describe, it, expect } from "vitest";
import os from "os";
import { MAX_LOCAL_IPS } from "@aicommander/protocol";
import { collectLocalIps, localIpsField } from "../local-addresses.js";

// What this machine says its addresses are — the half of "which box is this?"
// that the hostname alone does not answer on a fleet of aic-wfs-pc, aic-wfs-pc2,
// aic-wfs-pc3.
//
// The interface table is passed in rather than read from the OS: the addresses a
// CI runner (or a laptop on a VPN) happens to have are not a test fixture, and
// every rule here is about which of them are worth reporting.

type Iface = os.NetworkInterfaceInfo;

function v4(address: string, internal = false): Iface {
  return {
    address,
    netmask: "255.255.255.0",
    family: "IPv4",
    mac: "00:00:00:00:00:00",
    internal,
    cidr: `${address}/24`,
  };
}

function v6(address: string, internal = false): Iface {
  return {
    address,
    netmask: "ffff:ffff:ffff:ffff::",
    family: "IPv6",
    mac: "00:00:00:00:00:00",
    internal,
    cidr: `${address}/64`,
    scopeid: 0,
  };
}

describe("collectLocalIps", () => {
  it("reports the machine's routable IPv4 addresses", () => {
    expect(collectLocalIps({ en0: [v4("192.168.1.34")], en1: [v4("10.8.0.2")] })).toEqual([
      "192.168.1.34",
      "10.8.0.2",
    ]);
  });

  it("drops loopback — every machine has it and it identifies none of them", () => {
    expect(
      collectLocalIps({ lo0: [v4("127.0.0.1", true), v6("::1", true)], en0: [v4("192.168.1.34")] }),
    ).toEqual(["192.168.1.34"]);
  });

  it("drops link-local addresses, which say only that no DHCP answered", () => {
    expect(
      collectLocalIps({
        en0: [v4("169.254.10.2"), v6("fe80::1"), v6("FE80::2")],
        en1: [v4("192.168.1.34")],
      }),
    ).toEqual(["192.168.1.34"]);
  });

  it("prefers IPv4 — it is the address a user recognizes as 'that box'", () => {
    // A typical host carries several IPv6 addresses (global, temporary, ULA); all
    // of them alongside one IPv4 would bury the only line anyone reads.
    expect(collectLocalIps({ en0: [v4("192.168.1.34"), v6("fd00::1"), v6("2001:db8::7")] })).toEqual(
      ["192.168.1.34"],
    );
  });

  it("still identifies a v6-only host", () => {
    expect(collectLocalIps({ en0: [v6("2001:db8::7")] })).toEqual(["2001:db8::7"]);
  });

  it("sorts container/VM/tunnel adapters after the real ones", () => {
    expect(
      collectLocalIps({
        docker0: [v4("172.17.0.1")],
        "vEthernet (WSL)": [v4("172.30.5.1")],
        eth0: [v4("192.168.1.34")],
      })[0],
    ).toBe("192.168.1.34");
  });

  it("keeps a physical IPv6 ahead of a container bridge's IPv4", () => {
    // Family used to be decided before the physical/virtual split, so an IPv6-only
    // host that happened to run Docker reported 172.17.0.1 — the one address that
    // is identical on every Docker host — and threw away the address that actually
    // says which box this is.
    expect(
      collectLocalIps({ docker0: [v4("172.17.0.1")], eth0: [v6("2001:db8::7")] }),
    ).toEqual(["2001:db8::7", "172.17.0.1"]);
  });

  it("still reports a virtual adapter's address when it is all the machine has", () => {
    // A container host or a box reachable only over a VPN must not come back
    // empty: an empty list is sent as NOTHING, and "not reported" helps nobody
    // tell that machine from the next one.
    expect(collectLocalIps({ docker0: [v4("172.17.0.1")] })).toEqual(["172.17.0.1"]);
  });

  it("de-duplicates and caps the list", () => {
    const many: Record<string, Iface[]> = { en0: [v4("192.168.1.34"), v4("192.168.1.34")] };
    for (let i = 0; i < MAX_LOCAL_IPS + 4; i++) many[`en${i + 1}`] = [v4(`10.0.0.${i + 1}`)];
    const ips = collectLocalIps(many);
    expect(ips).toHaveLength(MAX_LOCAL_IPS);
    expect(new Set(ips).size).toBe(ips.length);
  });

  it("returns an empty list rather than throwing on a shape it did not expect", () => {
    // It runs on the registration path: a platform reporting something odd must
    // cost the register frame one optional field, never the registration.
    expect(collectLocalIps({ en0: undefined })).toEqual([]);
    expect(collectLocalIps(null as never)).toEqual([]);
  });

  it("survives os.networkInterfaces() itself throwing", () => {
    // The path the injected-argument cases above cannot reach. It used to be a
    // DEFAULT PARAMETER, evaluated before the body — so its throw escaped the
    // try/catch entirely and took down the ws "open" handler that builds the
    // register frame: an os-level failure cost the whole connection instead of one
    // optional field.
    const real = os.networkInterfaces;
    (os as { networkInterfaces: unknown }).networkInterfaces = () => {
      throw new Error("EPERM");
    };
    try {
      expect(collectLocalIps()).toEqual([]);
      expect(localIpsField()).toEqual({});
    } finally {
      (os as { networkInterfaces: unknown }).networkInterfaces = real;
    }
  });
});
