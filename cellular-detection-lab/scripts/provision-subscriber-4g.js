// Synthetic 4G/LTE test subscriber on the same 3GPP-reserved test PLMN
// (999/70) the 5G tier already uses - NOT a real SIM, not a real
// carrier's key material. Given its own IMSI, distinct from the 5G
// tier's 999700000000001, purely so 4G and 5G subscriber identities are
// visibly distinguishable in a shared capture/allowlist - Open5GS's HSS
// (open5gs-hssd) reads the exact same `slice[].session[]` document shape
// the 5G tier's UDR already writes (schema unified since Open5GS 2.2.0 -
// see docs/4G-TIER.md), so no new schema was invented here.
db = db.getSiblingDB('open5gs');

db.subscribers.deleteMany({ imsi: "999700000000099" });

db.subscribers.insertOne({
  imsi: "999700000000099",
  msisdn: [],
  imeisv: "4370816125816151",
  mme_host: [],
  mm_realm: [],
  purge_flag: [],
  slice: [
    {
      sst: 1,
      default_indicator: true,
      session: [
        {
          name: "internet",
          type: 3,
          pcc_rule: [],
          ambr: {
            uplink: { value: 1, unit: 3 },
            downlink: { value: 1, unit: 3 }
          },
          qos: {
            index: 9,
            arp: {
              priority_level: 8,
              pre_emption_vulnerability: 1,
              pre_emption_capability: 1
            }
          }
        }
      ]
    }
  ],
  ambr: {
    uplink: { value: 1, unit: 3 },
    downlink: { value: 1, unit: 3 }
  },
  security: {
    k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
    amf: "8000",
    op: null,
    opc: "E8ED289DEBA952E4283B54E88E6183CA"
  },
  schema_version: 1,
  __v: 0
});

print("4G subscriber count: " + db.subscribers.countDocuments({imsi: "999700000000099"}));
db.subscribers.find({imsi: "999700000000099"}).forEach(printjson);
