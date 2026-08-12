import pandas as pd
from clean import clean_data

RULES_TARGETS = {
    "brutef_force_rate": ["FTP-Patator", "SSH-Patator"],
    "dos_flood": ["DoS Hulk", "DoS GoldenEye"],
    "dos_low_andslow": ["DoS slowloris", "Dos Slowhttptest"],
}

def get_orig_labels():
    """Gets the orignal labels from the clean dataset 

    Returns:
        Dataframe: Returns 3 dataframes: monday_df, tuesday_df, & wednesday_df
    """
    monday_df, tuesday_df, wednesday_df = clean_data()
    
    # #sanity check
    # print('Label' in wednesday_df.columns)
    # print(wednesday_df['Label'].value_counts())
    
    return monday_df, tuesday_df, wednesday_df

def read_csv(path="alerts.csv"):
    """Obtains the alerts.csv file and stores it as a pandas
    data frame

    Args:
        path (str, optional):The name of the csv file. Defaults to "alerts.csv".

    Returns:
        Dataframe: Returns a pandas dataframe containing all the 
        alerts.
    """
    alerts_df = pd.read_csv(path)
    
    # #sanity check to ensure it pulls alerts.csv correctly
    # print(alerts_df["Label"].value_counts())
    
    return alerts_df


def main():
    # get_orig_labels()
    # read_csv()

if __name__ == "__main__":
    main()