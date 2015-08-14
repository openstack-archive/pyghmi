from pyghmi.ipmi.oem.lenovo.inventory import EntryField, \
    parse_inventory_category_entry

pci_fields = (
    EntryField("index", "B"),
    EntryField("PCIType", "B", mapper={
        0x0: "On board slot",
        0x1: "Riser Type 1",
        0x2: "Riser Type 2",
        0x3: "Riser Type 3",
        0x4: "Riser Type 4",
        0x5: "Riser Type 5",
        0x6: "Riser Type 6a",
        0x7: "Riser Type 6b",
        0x8: "ROC",
        0x9: "Mezz"
    }),
    EntryField("BusNumber", "B"),
    EntryField("DeviceFunction", "B"),
    EntryField("VendorID", "<H"),
    EntryField("DeviceID", "<H"),
    EntryField("SubSystemVendorID", "<H"),
    EntryField("SubSystemID", "<H"),
    EntryField("InterfaceType", "B"),
    EntryField("SubClassCode", "B"),
    EntryField("BaseClassCode", "B"),
    EntryField("LinkSpeed", "B"),
    EntryField("LinkWidth", "B"),
    EntryField("Reserved", "h")
)

def parse_pci_info(raw):
    return parse_inventory_category_entry(raw, pci_fields)

def get_categories():
    return {"pci": {
        "idstr": "PCI {0}",
        "parser": parse_pci_info,
        "command": {
            "netfn": 0x06,
            "command": 0x59,
            "data": (0x00, 0xc1, 0x03, 0x00)
        }
    }}
