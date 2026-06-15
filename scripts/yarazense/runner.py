from yarazense.compile import compile_rules

# COMPILATION
RULES = compile_rules()

# HELPERS

def _match(yara_bin: bytes):
    return RULES.match(data=yara_bin)

def _export_as_dict(matches):
    return [
        {
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": m.tags,
            "meta": m.meta,
        }
        for m in matches
    ]


# RUNNERS
def run(yara_bin: bytes) -> list[dict]:
    print(f"\t[*] Matching against found rules...")
    matches = _match(yara_bin)
    print(f"\t[*] Analytics via YARA received.")
    return _export_as_dict(matches)