from pathlib import Path
import yara

path = Path(__file__).resolve().parents[2] / "data" / "yara-signatures" / "yara"

# these are for THOR/LOKI, doesn't work for normal YARA
# yes, I hand-picked them (by running again and again ofc)
EXCLUDED = {
    "configured_vulns_ext_vars",
    "gen_webshells_ext_vars",
    "generic_anomalies",
    "general_cloaking",
    "thor_inverse_matches",
    "yara_mixed_ext_vars",
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519",
    "expl_connectwise_screenconnect_vuln_feb24",
    "gen_fake_amsi_dll",
    "gen_mal_3cx_compromise_mar23",
    "gen_susp_obfuscation",
    "gen_vcruntime140_dll_sideloading",
    "yara-rules_vuln_drivers_strict_renamed"
}


def _compile_rules() -> yara.Rules:

    print("[zense] Finding YARA rules...")
    rule_files = {}

    for f in path.rglob("*.yar"):
        if f.stem in EXCLUDED:
            continue
        rule_files[f.stem] = str(f)

    print(f"[zense] YARA rules found! {len(rule_files)} included, {len(EXCLUDED)} excluded")

    try:
        rules = yara.compile(filepaths=rule_files)
        print("[zense] All YARA rules compiled successfully")
        return rules
    except yara.SyntaxError as e:
        # we crash weeeeeeeeeeeee
        print(f"[zense] Error compiling YARA rules. Crashing...")
        raise e