import pandas as pd
import matplotlib as plt
import numpy as np

RULES_LIST = [
    "brute_force_rate",
    "dos_flood",
    "dos_low_and_slow"
]

RULES_TARGETS = {
    "brute_force_rate": ["FTP-Patator", "SSH-Patator"],
    "dos_flood": ["DoS Hulk", "DoS GoldenEye"],
    "dos_low_and_slow": ["DoS slowloris", "DoS Slowhttptest"],
}

def load_alert(path="alerts.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "alerts.csv".

    Returns:
        _type_: _description_
    """
    alerts_df = pd.read_csv(path)
    
    return alerts_df

def load_results(results_path="results.csv", attacks_results_path="results_per_attack.csv"):
    """_summary_

    Args:
        results_path (str, optional): _description_. Defaults to "results.csv".
        attacks_results_path (str, optional): _description_. Defaults to "results_per_attack.csv".

    Returns:
        _type_: _description_
    """
    
    results_df = pd.read_csv(results_path)
    results_per_attack_df = pd.read_csv(attacks_results_path)
    
    return results_df, results_per_attack_df

def load_thresh(path="threshold.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "threshold.csv".

    Returns:
        _type_: _description_
    """
    thresh_df = pd.read_csv(path)
    
    return thresh_df
    
    
def alert_vol_per_rule(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_
    """
    number_of_alerts = {}
    
    for rule in RULES_LIST:
        number_of_alerts[rule + "_volume"] = int(alerts_df['rule'].str.contains(rule, na=False).sum())
    
    print(number_of_alerts)
        
def rank_rules_by_noise(results_df):
    rules_sorted_by_FP = results_df.sort_values(by=["FP"], ascending=False)
    # print(rules_sorted_by_FP)
    
    return rules_sorted_by_FP
       
def alert_vol_over_time(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    alerts_df['Timestamp'] = pd.to_datetime(alerts_df['Timestamp'])
    alerts_df_sorted = alerts_df.sort_values(by=['Timestamp', 'rule'])
    
    hourly_alerts_count = (
        alerts_df_sorted.set_index('Timestamp')
        .groupby(['rule'])
        .resample('h')
        .size()
        .reset_index(name='count')
        .sort_values(by=['rule', 'Timestamp', 'count'], ascending=[True, True, False])
    )
    
    # print(hourly_alerts_count)
    
    return hourly_alerts_count

def mark_false_positive(alerts_df):
    targets_per_row = alerts_df["rule"].map(RULES_TARGETS)
    alerts_df["is_fp"] = [lbl not in tgts for lbl, tgts in zip(alerts_df["Label"], targets_per_row)]

def noisiest_sources(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    fps = alerts_df[alerts_df["is_fp"]]
    
    top_talkers = fps.groupby("Source IP").size().sort_values(ascending=False).head(10)
    noisiest_raw_FP_count = fps.groupby("rule").size().sort_values(ascending=False)
    benign_tripping_rule = fps.groupby(["rule", "Label"]).size().sort_values(ascending=False)
    
    
    return top_talkers, noisiest_raw_FP_count, benign_tripping_rule



def calculate_magnitude(alerts_df, thresh_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_
        thresh_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    flood_thresh = thresh_df.loc[thresh_df['Metric'] == 'Flow Packets/s', 'Value'].iloc[0]
    flow_thresh = thresh_df.loc[thresh_df['Metric'] == 'Flow Duration', 'Value'].iloc[0]
    RATE_THRESHOLD = 20
    
    dos_flood_mask = alerts_df["rule"] == "dos_flood"
    dos_slow_mask = alerts_df["rule"] == "dos_low_and_slow"
    brute_force_mask = alerts_df["rule"] == "brute_force_rate"
    
    alerts_df.loc[dos_flood_mask, "raw_ratio"] = alerts_df.loc[dos_flood_mask, "Flow Packets/s"] / flood_thresh
    alerts_df.loc[dos_slow_mask, 'raw_ratio'] = alerts_df.loc[dos_slow_mask, "Flow Duration"] / flow_thresh
    alerts_df.loc[brute_force_mask, 'raw_ratio'] = alerts_df.loc[brute_force_mask, "attempts"] / RATE_THRESHOLD
    
    alerts_df["magnitude"] = np.log1p(alerts_df['raw_ratio'])
    
    # # sanity checks
    # print(alerts_df[alerts_df["magnitude"] == alerts_df["magnitude"].min()][["rule", "Flow Packets/s", "Flow Duration", "attempts", "magnitude"]])
    # print(alerts_df["magnitude"].describe())
    # print(alerts_df["magnitude"].isna().sum()) # should be 0
    # print((alerts_df["magnitude"] < 0.69).sum()) # should be ~0
    
    return alerts_df

def alerts_per_source_IP(alerts_df):
    
    
    
    
    
    pass

def assign_priority_score():
    pass



def main():
    alerts_df = load_alert()
    alert_vol_per_rule(alerts_df)
    results_df, _ = load_results()
    thresh_df = load_thresh()
    rank_rules_by_noise(results_df)
    alert_vol_over_time(alerts_df)
    mark_false_positive(alerts_df)
    noisiest_sources(alerts_df)
    # calculate_magnitude(alerts_df, thresh_df)
    
    

if __name__ == '__main__':
    main()