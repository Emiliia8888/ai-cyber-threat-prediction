import pandas as pd


def add_unsw_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add domain-specific network traffic features
    to UNSW-NB15 data.
    """

    result = df.copy()

    # Avoid division by zero.
    eps = 1e-9

    # ---------------------------------------------------------
    # Packet and byte ratios
    # ---------------------------------------------------------

    result["src_bytes_per_packet"] = (
        result["sbytes"] / (result["spkts"] + eps)
    )

    result["dst_bytes_per_packet"] = (
        result["dbytes"] / (result["dpkts"] + eps)
    )

    result["src_dst_bytes_ratio"] = (
        result["sbytes"] / (result["dbytes"] + eps)
    )

    result["src_dst_packets_ratio"] = (
        result["spkts"] / (result["dpkts"] + eps)
    )

    # ---------------------------------------------------------
    # Traffic rates
    # ---------------------------------------------------------

    result["packets_per_second"] = (
        (result["spkts"] + result["dpkts"])
        / (result["dur"] + eps)
    )

    result["bytes_per_second"] = (
        (result["sbytes"] + result["dbytes"])
        / (result["dur"] + eps)
    )

    # ---------------------------------------------------------
    # Total traffic
    # ---------------------------------------------------------

    result["total_bytes"] = (
        result["sbytes"] + result["dbytes"]
    )

    result["total_packets"] = (
        result["spkts"] + result["dpkts"]
    )

    # ---------------------------------------------------------
    # Traffic direction
    # ---------------------------------------------------------

    result["source_byte_ratio"] = (
        result["sbytes"]
        / (result["total_bytes"] + eps)
    )

    result["source_packet_ratio"] = (
        result["spkts"]
        / (result["total_packets"] + eps)
    )

    # ---------------------------------------------------------
    # TCP timing
    # ---------------------------------------------------------

    result["tcp_handshake_time"] = (
        result["tcprtt"]
        + result["synack"]
        + result["ackdat"]
    )

    result["tcp_response_ratio"] = (
        result["tcprtt"]
        / (result["dur"] + eps)
    )

    # ---------------------------------------------------------
    # Connection behaviour
    # ---------------------------------------------------------

    result["connection_activity"] = (
        result["ct_src_dport_ltm"]
        + result["ct_dst_sport_ltm"]
    )

    result["connection_activity_ratio"] = (
        result["ct_src_dport_ltm"]
        / (
            result["ct_dst_sport_ltm"]
            + eps
        )
    )

    # ---------------------------------------------------------
    # Packet timing
    # ---------------------------------------------------------

    result["packet_interval_ratio"] = (
        result["sinpkt"]
        / (result["dinpkt"] + eps)
    )

    result["jitter_ratio"] = (
        result["sjit"]
        / (result["djit"] + eps)
    )

    return result
