import rules
import pandas as pd
from clean import clean_data

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

def main():
    get_orig_labels()

if __name__ == "__main__":
    main()