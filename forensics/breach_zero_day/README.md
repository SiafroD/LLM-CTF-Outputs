# Breach : Zero Day

## Description

**Category :** Forensics

**Description :** Triage of FNW-WKS047 (Fenwick Analytics, Toulouse) from a pcap, a Windows event log export and a memory string dump. Flag format: `csaw{C2INDICATOR_SERVICENAME_BACKDOORNAME}`.

## LLM

**Model :** Claude Sonnet 5.5

## Execution

**Found flag :** `csaw{RELAYSHELL_WinDefend_FORESTTIGER}`

**Prompt :** The original challenge prompt and briefs, plus your corrections: RELAYSHELL is not the backdoor name, TIGER and FOREST may combine into something, and the service is the one hit by the driver.

**Execution trace :**

1. **Service name (your correction).** You're right. The Afd driver (`Afd4Eop12`, 01:14:15) is the attack tool, not the target. The very next event, five seconds later at 01:14:20, is the stop of **`WinDefend`**, the Defender service. That makes SERVICENAME `WinDefend`. By the same logic the backup chain's `BkupAgent64` driver hit `SecurityHealthService`, which is the decoy chain.
2. **TIGER and FOREST.** I dismissed them too quickly, and they do combine. In the memory dump, `TSEROF` (FOREST) sits at line 2272 and `REGIT` (TIGER) at line 896. Read together they spell **ForestTiger**. A search confirms that the Lazarus AFD.sys zero-day campaign ends with the ForestTiger backdoor, a well-documented malware family widely attributed to the Lazarus threat group, delivered once the AFD.sys exploit gives SYSTEM privileges and FudModule runs.
3. **Re-sorting the reversed strings.** I had misread what the four planted strings are:
   - **FUDMODULE** is Lazarus's rootkit, loaded by the AFD.sys exploit. It matches the `Afd4Eop12` driver but is not the backdoor.
   - **COPPERHEDGE** is a different Lazarus tool that does not appear in the campaign reporting I found. It is likely a decoy, and my earlier choice of it was wrong.
   - **TIGER + FOREST** gives **ForestTiger**, which the reporting names as the backdoor delivered after the rootkit. That fits BACKDOORNAME.
4. **C2 indicator.** The same reporting says Lazarus kept its command traffic off dedicated servers, using hijacked WordPress and Roundcube sites. They deployed RelayShell, a PHP webshell that turns the compromised server into a relay node. That explains why the beacon ID `RELAYSHELL` appears in the traffic to the lookalike domain.

## More

**Additional explanation :**

- The attribution is now sourced: this is the Lazarus Operation Dream Job pattern from Check Point's reporting. It uses a Windows AFD.sys zero-day (CVE-2026-68820) to deploy FudModule, which is where the challenge title "Zero Day" comes from.
- The attack also matches your brief: the target is a defense/aerospace-style firm, and the intruders stay quiet during off hours.
- Case may matter. I used `FORESTTIGER` in the main answer because the other planted strings and `RELAYSHELL` are uppercase. If the checker rejects it, try `csaw{RELAYSHELL_WinDefend_ForestTiger}`.