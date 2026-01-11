from mac_vendor_lookup import MacLookup
import sys

def test_lookup():
    print("Initializing MacLookup...")
    try:
        mac = MacLookup()
    except Exception as e:
        print(f"Failed to initialize MacLookup: {e}")
        return

    print("Checking if vendor DB needs update...")
    try:
        # flexible check
        mac.lookup("00:00:00:00:00:00")
    except Exception:
        print("Updating vendor DB...")
        try:
            mac.update_vendors()
        except Exception as e:
            print(f"Failed to update vendors: {e}")
            return

    test_macs = [
        ("00:50:56:C0:00:08", "VMware"),  # Example VMware
        ("AC:BC:32:AE:B1:C3", "Apple"),  # Example Apple (randomly generated prefix, might need real one if strict)
        ("00:00:00:00:00:00", "Xerox"),  # 00:00:00 is Xerox
        ("FF:FF:FF:FF:FF:FF", "Unknown") # Broadcast
    ]

    print("\nTesting Lookups:")
    for m, expected in test_macs:
        try:
            vendor = mac.lookup(m)
            print(f"MAC: {m} -> Vendor: {vendor}")
        except Exception as e:
            print(f"MAC: {m} -> Error/Unknown: {e}")

if __name__ == "__main__":
    test_lookup()
