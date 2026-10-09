import numpy as np
import pandas as pd


def add_cic_features(
    df: pd.DataFrame,
) -> pd.DataFrame:
    result = df.copy()

    eps = 1e-9

    # --------------------------------------------------
    # Packet and byte totals
    # --------------------------------------------------

    result["Total Packets"] = (
        result["Total Fwd Packets"]
        + result["Total Backward Packets"]
    )

    result["Total Bytes"] = (
        result["Fwd Packets Length Total"]
        + result["Bwd Packets Length Total"]
    )

    result["Packets per Second"] = (
        result["Total Packets"]
        / (result["Flow Duration"] + eps)
    )

    result["Bytes per Second"] = (
        result["Total Bytes"]
        / (result["Flow Duration"] + eps)
    )

    # --------------------------------------------------
    # Forward / backward packet ratios
    # --------------------------------------------------

    result["Fwd Packet Ratio"] = (
        result["Total Fwd Packets"]
        / (result["Total Packets"] + eps)
    )

    result["Bwd Packet Ratio"] = (
        result["Total Backward Packets"]
        / (result["Total Packets"] + eps)
    )

    result["Fwd Byte Ratio"] = (
        result["Fwd Packets Length Total"]
        / (result["Total Bytes"] + eps)
    )

    result["Bwd Byte Ratio"] = (
        result["Bwd Packets Length Total"]
        / (result["Total Bytes"] + eps)
    )

    # --------------------------------------------------
    # Average bytes per packet
    # --------------------------------------------------

    result["Fwd Bytes per Packet"] = (
        result["Fwd Packets Length Total"]
        / (result["Total Fwd Packets"] + eps)
    )

    result["Bwd Bytes per Packet"] = (
        result["Bwd Packets Length Total"]
        / (result["Total Backward Packets"] + eps)
    )

    result["Packet Size Ratio"] = (
        result["Fwd Packet Length Mean"]
        / (result["Bwd Packet Length Mean"] + eps)
    )

    # --------------------------------------------------
    # Inter-arrival time features
    # --------------------------------------------------

    result["IAT Range"] = (
        result["Flow IAT Max"]
        - result["Flow IAT Min"]
    )

    result["Fwd IAT Range"] = (
        result["Fwd IAT Max"]
        - result["Fwd IAT Min"]
    )

    result["Bwd IAT Range"] = (
        result["Bwd IAT Max"]
        - result["Bwd IAT Min"]
    )

    result["IAT Mean Ratio"] = (
        result["Fwd IAT Mean"]
        / (result["Bwd IAT Mean"] + eps)
    )

    # --------------------------------------------------
    # Header features
    # --------------------------------------------------

    result["Total Header Length"] = (
        result["Fwd Header Length"]
        + result["Bwd Header Length"]
    )

    result["Fwd Header Ratio"] = (
        result["Fwd Header Length"]
        / (result["Total Header Length"] + eps)
    )

    result["Bwd Header Ratio"] = (
        result["Bwd Header Length"]
        / (result["Total Header Length"] + eps)
    )

    # --------------------------------------------------
    # TCP flags
    # --------------------------------------------------

    result["Total TCP Flags"] = (
        result["SYN Flag Count"]
        + result["ACK Flag Count"]
        + result["FIN Flag Count"]
        + result["RST Flag Count"]
        + result["PSH Flag Count"]
        + result["URG Flag Count"]
        + result["ECE Flag Count"]
        + result["CWE Flag Count"]
    )

    result["SYN ACK Ratio"] = (
        result["SYN Flag Count"]
        / (result["ACK Flag Count"] + eps)
    )

    result["RST SYN Ratio"] = (
        result["RST Flag Count"]
        / (result["SYN Flag Count"] + eps)
    )

    # --------------------------------------------------
    # Active / idle behaviour
    # --------------------------------------------------

    result["Active Mean Ratio"] = (
        result["Active Mean"]
        / (result["Flow Duration"] + eps)
    )

    result["Idle Mean Ratio"] = (
        result["Idle Mean"]
        / (result["Flow Duration"] + eps)
    )

    # --------------------------------------------------
    # Directional packet rates
    # --------------------------------------------------

    result["Fwd Packet Rate Ratio"] = (
        result["Fwd Packets/s"]
        / (result["Flow Packets/s"] + eps)
    )

    result["Bwd Packet Rate Ratio"] = (
        result["Bwd Packets/s"]
        / (result["Flow Packets/s"] + eps)
    )

    # --------------------------------------------------
    # Down / up relationship
    # --------------------------------------------------

    result["Down Up Ratio Safe"] = (
        result["Down/Up Ratio"]
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
    )

    # --------------------------------------------------
    # Clean invalid numerical values
    # --------------------------------------------------

    numeric_columns = result.select_dtypes(
        include=np.number
    ).columns

    result[numeric_columns] = (
        result[numeric_columns]
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
    )

    return result
