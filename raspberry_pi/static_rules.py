def check_static_rules(features):
    flow_duration         = features[0]
    flow_iat_std          = features[2]
    packet_length_var     = features[3]
    packet_length_max     = features[4]
    init_bwd_win_bytes    = features[6]
    fwd_packets_s         = features[7]
    bwd_packet_length_mean = features[8]

    if fwd_packets_s > 1000 and bwd_packet_length_mean < 10 and flow_iat_std < 5:
        return "DoS/DDoS"

    if init_bwd_win_bytes == 0 and flow_duration < 2 and fwd_packets_s > 100:
        return "SYN Scan"

    if fwd_packets_s > 100 and packet_length_max < 100 and init_bwd_win_bytes == 0:
        return "Port Scan"

    if flow_iat_std < 0.5 and packet_length_var < 50 and flow_duration > 5:
        return "Brute Force"

    return None