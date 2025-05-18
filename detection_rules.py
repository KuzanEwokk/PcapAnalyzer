def detect_large_flow(flow):
    """
    Wykrywa podejrzanie duży ruch sieciowy wysyłany do konkretnego portu.
    """
    if flow.bidirectional_bytes > 5_000:
        return True, f"Suspicious large flow from: {flow.src_ip}"
    return False, None

#add all rules to this list to be initialised.    
detection_rules = [detect_large_flow]

def get_list():
    return detection_rules
#flow.destination_port == 443 and