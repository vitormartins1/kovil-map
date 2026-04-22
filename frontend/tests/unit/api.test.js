const { API } = require("../../src/modules/api.js");

function makeResponse(payload, ok = true, status = ok ? 200 : 500) {
  return {
    ok,
    status,
    json: jest.fn().mockResolvedValue(payload),
  };
}

describe("API._unwrap", () => {
  test("returns .data when status is success", async () => {
    const result = await API._unwrap(makeResponse({ status: "success", data: { a: 1 } }));
    expect(result).toEqual({ a: 1 });
  });

  test("returns raw payload when status is not success wrapper", async () => {
    const payload = { hello: "world" };
    const result = await API._unwrap(makeResponse(payload));
    expect(result).toEqual(payload);
  });

  test("throws meaningful error from response payload", async () => {
    await expect(API._unwrap(makeResponse({ error: { message: "boom" } }, false))).rejects.toThrow("boom");
    await expect(API._unwrap(makeResponse({ detail: "bad" }, false))).rejects.toThrow("bad");
    await expect(API._unwrap(makeResponse({}, false, 418))).rejects.toThrow("HTTP 418");
  });
});

describe("API methods", () => {
  beforeEach(() => {
    fetch.mockResolvedValue(makeResponse({ status: "success", data: { ok: true } }));
  });

  test("delegates authenticated transport to desktop bridge when available", async () => {
    const bridgeResponse = {
      ok: true,
      status: 200,
      statusText: "OK",
      headers: {
        "content-type": "application/json",
      },
      bodyText: JSON.stringify({ status: "success", data: { ok: true } }),
    };
    window.desktop = {
      fetchApi: jest.fn().mockResolvedValue(bridgeResponse),
    };

    await API.getStatus();
    expect(window.desktop.fetchApi).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/health",
      undefined,
    );

    await API.sync(true, {
      pwnagotchiHandshakesProcessId: "pwn-hs-1",
      m5HandshakesProcessId: "m5-hs-1",
      m5WardriveProcessId: "m5-wd-1",
      bruceHandshakesProcessId: "bruce-hs-1",
      bruceRawsnifferProcessId: "bruce-raw-1",
      bruceWardriveProcessId: "bruce-wd-1",
    }, {
      pwnagotchi: true,
      m5evil: false,
      bruce: true,
    });
    expect(window.desktop.fetchApi).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          force: true,
          pwn_handshakes_process_id: "pwn-hs-1",
          m5_handshakes_process_id: "m5-hs-1",
          m5_wardrive_process_id: "m5-wd-1",
          bruce_handshakes_process_id: "bruce-hs-1",
          bruce_rawsniffer_process_id: "bruce-raw-1",
          bruce_wardrive_process_id: "bruce-wd-1",
          pwn_force_sync: true,
          m5_force_sync: false,
          bruce_force_sync: true,
        }),
      })
    );

    await API.trustHostKey("10.0.0.2", 22, true, "m5evil");
    expect(window.desktop.fetchApi).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync/trust-host-key",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      })
    );

    delete window.desktop;
  });

  test("trustHostKey omits host and port when not provided", async () => {
    await API.trustHostKey(null, null, false);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync/trust-host-key",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ replace: false }),
      })
    );
  });

  test("GET-like endpoints call expected URLs", async () => {
    await API.getStatus();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/health");

    await API.getMapData();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/map/data");

    await API.getVendor("aa:bb");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/vendors/aa:bb");

    await API.getVendorAlt("aa:bb");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/vendors/aa:bb?source=manuf");

    await API.getConfig();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/config");

    await API.getHandshakeFiles("aa:bb");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/handshakes/aa:bb/files");

    await API.getHandshakeSet("aa:bb");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/handshakes/aa:bb/set");

    await API.getHandshakeRawContext("aa:bb");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/handshakes/aa:bb/raw-context");

    await API.getFileContent("space name.pcap");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/files/space%20name.pcap");

    await API.getCustomWordlists();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/wordlists/custom");

    await API.getHashcatRules();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/hashcat/rules");

    await API.getHashcatMasks();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/hashcat/masks");

    await API.getHashcatDevices();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/hashcat/devices");

    await API.listMultiFiles();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/batches");

    await API.getMultiFileContent("batch 1.22000");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/batches/batch%201.22000");

    await API.getBatchFiles("batch 1.22000");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/batches/batch%201.22000/files");

    await API.getJobStatus("job-1");
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/jobs/job-1");

    await API.listJobs();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/jobs");

    await API.getFingerprintDetails({ filename: "My Net.details" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/details?filename=My+Net.details"
    );

    await API.getFingerprintDetails({ mac: "AA:BB:CC:DD:EE:FF" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/details?mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF"
    );

    await API.getFingerprintDetails({ filename: "net.details", mac: "aa:bb" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/details?filename=net.details&mac=aa%3Abb"
    );

    await API.getFingerprintDetails({});
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/details?"
    );

    await API.listRawSnifferFiles();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/rawsniffer/files");

    await API.getRawSnifferHashes();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/rawsniffer/hashes");

    await API.getRawSnifferMetadata("raw_1.pcap");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/rawsniffer/metadata?filename=raw_1.pcap"
    );

    await API.getRawSnifferAnalysis("raw::pcap::abc123");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/rawsniffer/analysis/raw%3A%3Apcap%3A%3Aabc123"
    );

    await API.getDataHealthSummary();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/data-health/summary");

    await API.getAttackScore({ mac: "AA:BB:CC:DD:EE:FF" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/score?mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF"
    );

    await API.getAttackRecommendation({ filename: "capture.22000" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/attack-recommendation?filename=capture.22000"
    );

    await API.getHandshakeReadiness({ mac: "AA:BB:CC:DD:EE:FF" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/handshake-readiness?mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF"
    );

    await API.getQualityGate("capture.22000", "rules");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/quality-gate?filename=capture.22000&attack_mode=rules"
    );

    await API.getAnalyticsHeatmap({ metric: "opportunity", source: "raw", channel: 6, cell_size_m: 120 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/heatmap?metric=opportunity&time_window=all&source=raw&security=all&device_type=all&cell_size_m=120&channel=6"
    );

    await API.getAnalyticsChannelSummary({ metric: "eapol", security: "locked" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/channel-summary?metric=eapol&time_window=all&source=all&security=locked&device_type=all"
    );

    await API.getAnalyticsHotspots({ metric: "probe", time_window: "24h", limit: 5 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/hotspots?metric=probe&time_window=24h&source=all&security=all&device_type=all&cell_size_m=120&limit=5"
    );

    await API.getWardriveHierarchy({ time_window: "24h", source: "ward", session_ids: ["session-a", "session-b"] });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/wardrive/hierarchy?time_window=24h&source=ward&session_ids=session-a%2Csession-b"
    );

    await API.getWardriveInventory();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/wardrive/inventory");

    await API.getWardriveSessions({ time_window: "24h" });
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/wardrive/sessions?time_window=24h");

    await API.setWardriveSessionTag("session-a", "car");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/wardrive/sessions/tag",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ session_id: "session-a", transport_mode: "car" }),
      })
    );

    await API.getWardriveSessionTracks(["session-a", "session-b"]);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/wardrive/sessions/tracks",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ session_ids: ["session-a", "session-b"] }),
      })
    );

    await API.mergeWardriveSessions(["session-a", "session-b"]);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/wardrive/sessions/merge",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ session_ids: ["session-a", "session-b"] }),
      })
    );

    await API.refreshWardriveRuntime({ reload_data: true, reload_maps: false });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/wardrive/refresh",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ reload_data: true, reload_maps: false }),
      })
    );
  });

  test("RawSniffer extract and analytics channel params are included when provided", async () => {
    await API.extractRawSniffer();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/rawsniffer/extract",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({}),
      })
    );

    await API.getAnalyticsChannelSummary({ channel: 6 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/channel-summary?metric=opportunity&time_window=all&source=all&security=all&device_type=all&channel=6"
    );

    await API.getAnalyticsHotspots({ channel: 6 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/hotspots?metric=opportunity&time_window=all&source=all&security=all&device_type=all&cell_size_m=120&limit=12&channel=6"
    );
  });

  test("metadata refresh, insight queries and cracking payloads cover optional params", async () => {
    await API.getRawSnifferMetadata("raw_1.pcap", true);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/rawsniffer/metadata?filename=raw_1.pcap&refresh=true"
    );

    await API.getRawSnifferMetadata(null, false, "raw::pcap::abc123");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/rawsniffer/metadata?raw_item_id=raw%3A%3Apcap%3A%3Aabc123"
    );

    await API.analyzeRawSniffer("raw::pcap::abc123", true);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/rawsniffer/analyze",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ raw_item_id: "raw::pcap::abc123", force: true }),
      })
    );

    await API.getAttackScore();
    expect(fetch).toHaveBeenLastCalledWith("http://127.0.0.1:8000/api/insights/score");

    await API.getAttackRecommendation({});
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/attack-recommendation"
    );

    await API.previewAssociationCandidates("capture.22000", "association_hint_first", "hint", ["h1", "h2"]);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/hashcat/association/preview",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          filename: "capture.22000",
          capture_id: null,
          combined_build_id: null,
          mac: null,
          mode: "association_hint_first",
          association_hint: "hint",
          association_hints: ["h1", "h2"],
        }),
      })
    );

    await API.buildCombinedCapture("AA:BB:CC:DD:EE:FF", ["cap-a", "cap-b"]);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/handshakes/AA:BB:CC:DD:EE:FF/combine-captures",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ capture_ids: ["cap-a", "cap-b"] }),
      })
    );

    await API.startCracking(
      "capture.22000",
      "rules",
      "3",
      "wl.txt",
      "best64.rule",
      "?a?a",
      true,
      false,
      "1",
      true,
      "wl2.txt",
      true,
      1,
      4,
      "mask.hcmask",
      "assoc",
      ["hint1"],
      true
    );
    const lastCall = fetch.mock.calls[fetch.mock.calls.length - 1];
    expect(lastCall[0]).toBe("http://127.0.0.1:8000/api/hashcat/jobs");
    const payload = JSON.parse(lastCall[1].body);
    expect(payload).toEqual(
      expect.objectContaining({
        filename: "capture.22000",
        mask_file: "mask.hcmask",
        association_hint: "assoc",
        association_hints: ["hint1"],
        skip_quality_gate: true,
      })
    );
  });

  test("insights endpoints handle mac/filename combos and omit channel when set to all", async () => {
    await API.getAttackScore({ filename: "capture.22000" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/score?filename=capture.22000"
    );

    await API.getAttackRecommendation({ mac: "AA:BB:CC:DD:EE:FF" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/attack-recommendation?mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF"
    );

    await API.getHandshakeReadiness();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/handshake-readiness"
    );

    await API.getQualityGate("capture.22000");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/insights/quality-gate?filename=capture.22000"
    );

    await API.getAnalyticsHeatmap({ channel: "all" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/heatmap?metric=opportunity&time_window=all&source=all&security=all&device_type=all&cell_size_m=120"
    );

    await API.getAnalyticsChannelSummary({ channel: "all" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/channel-summary?metric=opportunity&time_window=all&source=all&security=all&device_type=all"
    );

    await API.getAnalyticsHotspots({ channel: "all" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/analytics/hotspots?metric=opportunity&time_window=all&source=all&security=all&device_type=all&cell_size_m=120&limit=12"
    );
  });

  test("POST/PUT/PATCH/DELETE endpoints send expected payload", async () => {
    await API.sync(true);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force: true }),
      })
    );

    await API.sync();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force: false }),
      })
    );

    await API.trustHostKey("10.0.0.2", 22, true, "m5evil");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync/trust-host-key",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ replace: true, host: "10.0.0.2", port: 22, target: "m5evil" }),
      })
    );

    await API.trustHostKey();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync/trust-host-key",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ replace: false }),
      })
    );

    await API.probePwnagotchiSync({
      pwn_host: "10.0.0.2",
      pwn_port: 22,
      pwn_user: "pi",
      pwn_pass: "raspberry",
      remote_path: "/home/pi/handshakes",
    });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync/pwnagotchi/probe",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pwn_host: "10.0.0.2",
          pwn_port: 22,
          pwn_user: "pi",
          pwn_pass: "raspberry",
          remote_path: "/home/pi/handshakes",
        }),
      })
    );

    await API.probeM5EvilSync({
      m5_host: "192.168.0.6",
      m5_port: 80,
      m5_web_user: "evil",
      m5_web_password: "test",
    });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/sync/m5evil/probe",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );

    await API.getZones({ maxDistance: 100 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/zones",
      expect.objectContaining({ method: "POST" })
    );

    await API.getToConquerZones({ maxDistance: 100 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/zones/to-conquer",
      expect.objectContaining({ method: "POST" })
    );

    await API.getWardriveZones({ region_id: "city:3304557", eps_m: 200, min_samples: 3 });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/wardrive/zones",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ region_id: "city:3304557", eps_m: 200, min_samples: 3 }),
      })
    );

    await API.saveConfig({ ui_theme: "cyan" });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/config",
      expect.objectContaining({ method: "PUT" })
    );

    await API.convertPcap("file.pcap");
    expect(fetch).toHaveBeenLastCalledWith(
        "http://127.0.0.1:8000/api/convert/hcx",
        expect.objectContaining({
            method: "POST",
            body: JSON.stringify({ filename: "file.pcap", capture_id: null, raw_item_id: null }),
        })
    );

    await API.prepareHandshakeRaw("aa:bb", { source_file: "raw_1.pcap", force: true });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/handshakes/aa:bb/raw-prepare",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ source_file: "raw_1.pcap", raw_item_id: null, force: true }),
      })
    );

    await API.prepareHandshakeRawAll("aa:bb", { force: true });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/handshakes/aa:bb/raw-prepare-all",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ force: true }),
      })
    );

    await API.convertMultiPcaps(["a.pcap", "b.pcap"]);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/convert/hcx/batch",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ filenames: ["a.pcap", "b.pcap"], capture_ids: null }),
      })
    );

    await API.startCracking(
      "x.22000",
      0,
      2,
      "wordlist.txt",
      "rule.rule",
      "?d?d?d?d",
      true,
      false,
      "1",
      true,
      "wordlist2.txt",
      false,
      1,
      4,
      "my-profile.hcmask",
      "my_hint",
      "hint1\nhint2"
    );
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/hashcat/jobs",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );
    const startCrackingPayload = JSON.parse(fetch.mock.calls.at(-1)[1].body);
    expect(startCrackingPayload.mask_file).toBe("my-profile.hcmask");
    expect(startCrackingPayload.association_hint).toBe("my_hint");
    expect(startCrackingPayload.association_hints).toBe("hint1\nhint2");
    expect(startCrackingPayload.skip_quality_gate).toBe(false);

    await API.startCracking(
      "x.22000",
      0,
      2,
      "wordlist.txt",
      "rule.rule",
      "?d?d?d?d",
      true,
      false,
      "1",
      true,
      "wordlist2.txt",
      false,
      1,
      4,
      "my-profile.hcmask",
      "my_hint",
      "hint1\nhint2",
      true
    );
    const forceStartPayload = JSON.parse(fetch.mock.calls.at(-1)[1].body);
    expect(forceStartPayload.skip_quality_gate).toBe(true);

    await API.previewAssociationCandidates(
      "capture.22000",
      "association_hint_first",
      "fallback_hint",
      "hint-a\nhint-b"
    );
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/hashcat/association/preview",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );
    const previewPayload = JSON.parse(fetch.mock.calls.at(-1)[1].body);
    expect(previewPayload).toEqual({
      filename: "capture.22000",
      capture_id: null,
      combined_build_id: null,
      mac: null,
      mode: "association_hint_first",
      association_hint: "fallback_hint",
      association_hints: "hint-a\nhint-b",
    });

    await API.startAircrack("file.pcap", "aa:bb:cc", "wl.txt");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/aircrack/jobs",
      expect.objectContaining({ method: "POST" })
    );
    expect(JSON.parse(fetch.mock.calls.at(-1)[1].body)).toEqual({
      filename: "file.pcap",
      capture_id: null,
      raw_item_id: null,
      bssid: "aa:bb:cc",
      wordlist: "wl.txt",
    });

    await API.deleteMultiFile("batch 2.22000");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/batches/batch%202.22000",
      expect.objectContaining({ method: "DELETE" })
    );

    await API.cancelJob("job-2");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/jobs/job-2",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ status: "canceled" }),
      })
    );

    await API.clearHistory();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/history",
      expect.objectContaining({ method: "DELETE" })
    );

    await API.clearDetailsFiles();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/maintenance/details",
      expect.objectContaining({ method: "DELETE" })
    );

    await API.clearCache();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/maintenance/cache",
      expect.objectContaining({ method: "DELETE" })
    );

    await API.getDemoDataStatus();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/maintenance/demo"
    );

    await API.installDemoData({ profile_id: "showcase-core-v5", frontend_state: { lists: { targets: [] } } });
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/maintenance/demo/install",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile_id: "showcase-core-v5", frontend_state: { lists: { targets: [] } } }),
      })
    );

    await API.removeDemoData();
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/maintenance/demo",
      expect.objectContaining({ method: "DELETE" })
    );

    await API.extractFingerprint("capture.pcap", true);
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/extract",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: "capture.pcap", capture_id: null, raw_item_id: null, bssid: null, force: true }),
      })
    );

    await API.extractFingerprint("capture.pcap");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/extract",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: "capture.pcap", capture_id: null, raw_item_id: null, bssid: null, force: false }),
      })
    );

    await API.extractFingerprint("capture.pcap", false, null, "raw::pcap::abc123", "AA:BB:CC:DD:EE:FF");
    expect(fetch).toHaveBeenLastCalledWith(
      "http://127.0.0.1:8000/api/fingerprint/extract",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: "capture.pcap",
          capture_id: null,
          raw_item_id: "raw::pcap::abc123",
          bssid: "AA:BB:CC:DD:EE:FF",
          force: false,
        }),
      })
    );
  });
});
