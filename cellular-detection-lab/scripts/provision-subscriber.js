// Standard Open5GS test subscriber values (from Open5GS documentation /
// UERANSIM default sample configs). Synthetic test SIM, not a real IMSI.
db = db.getSiblingDB('open5gs');

db.subscribers.deleteMany({ imsi: "999700000000001" });

db.subscribers.insertOne({
  imsi: "999700000000001",
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

print("Subscriber count: " + db.subscribers.countDocuments());
db.subscribers.find({imsi: "999700000000001"}).forEach(printjson);
