import pandas as pd
import matplotlib as plt

RULES_LIST = [
    "brute_force_rate",
    "dos_flood",
    "dos_low_and_slow"
]

def load_alert(path="alerts.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "alerts.csv".

    Returns:
        _type_: _description_
    """
    alerts_df = pd.read_csv(path)
    
    return alerts_df

def alert_vol_per_rule(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_
    """
    number_of_alerts = {}
    
    for rule in RULES_LIST:
        number_of_alerts[rule + "_volume"] = int(alerts_df['rule'].str.contains(rule, na=False).sum())
    
    print(number_of_alerts)
        
    
    



def main():
    alerts_df = load_alert()
    alert_vol_per_rule(alerts_df)

if __name__ == '__main__':
    main()