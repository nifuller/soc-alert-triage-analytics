import pandas as pd
import matplotlib as plt

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

def is_false_positive(row):
    targets = RULES_TARGETS.get(row["rule"], [])
    return row["Label"] not in targets

def noisiest_sources(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    alerts_df["is_fp"] = alerts_df.apply(is_false_positive, axis=1)
    
    fps = alerts_df[alerts_df["is_fp"]]
    
    top_talkers = fps.groupby("Source IP").size().sort_values(ascending=False).head(10)
    
    noisiest_raw_FP_count = fps.groupby("rule").size().sort_values(ascending=False)
    
    benign_tripping_rule = fps.groupby(["rule", "Label"]).size().sort_values(ascending=False)
    
    # print(top_talkers)
    # print(noisiest_raw_FP_count)
    # print(benign_tripping_rule)
    
    return top_talkers, noisiest_raw_FP_count, benign_tripping_rule

def assign_priority_score():
    pass



def main():
    alerts_df = load_alert()
    alert_vol_per_rule(alerts_df)
    results_df, _ = load_results()
    rank_rules_by_noise(results_df)
    alert_vol_over_time(alerts_df)
    noisiest_sources(alerts_df)
    
    

if __name__ == '__main__':
    main()