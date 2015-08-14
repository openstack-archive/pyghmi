from pyghmi.ipmi.oem.lenovo.inventory import EntryField, \
    parse_inventory_category_entry

cpu_fields = (
    EntryField("index", "B"),
    EntryField("Cores", "B"),
    EntryField("Threads", "B"),
    EntryField("Manufacturer", "13s"),
    EntryField("Family", "30s"),
    EntryField("Model", "30s"),
    EntryField("Stepping", "3s"),
    EntryField("Maximum Frequency", "<I",
        valuefunc=lambda v: str(v) + " MHz"),
    EntryField("Reserved", "h", include=False))

def parse_cpu_info(raw):
    return parse_inventory_category_entry(raw, cpu_fields)

def get_categories():
    return {"cpu": {
        "idstr": "CPU {0}",
        "parser": parse_cpu_info,
        "command": {
            "netfn": 0x06,
            "command": 0x59,
            "data": (0x00, 0xc1, 0x01, 0x00)
        }
    }}
