import pandas as pd
from clean import clean_data

AUTH_PORTS = {21, 22}
MAX_FWD_PACKES = 8
ATTEMPT_PER_MIN = 20

HTTP_PORT = 80

def load_threshold(path="threshold.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "threshold.csv".

    Returns:
        _type_: _description_
    """
    tdf = pd.read_csv(path).dropna(subset=["Metric"])
    tdf["value"] = pd.to_numeric(tdf["value"])
    return tdf.set_index(["Metric", "Port"])["Value"].to_dict()