import sys
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
DATA_FILE = ROOT_DIR / "data" / "traffic_features.csv"

sys.path.insert(0, str(SRC_DIR))

# Import the actual Rule Engine functions
from rule_engine import analyze_flow, apply_rules


# ---------------------------------------------------------
# Helper function
# ---------------------------------------------------------

def load_test_data():
    """
    Load the same feature data used by the Rule Engine.
    """

    assert DATA_FILE.exists(), (
        f"Feature data file was not found: {DATA_FILE}\n"
        "Run the traffic generation and feature engineering steps first."
    )

    dataframe = pd.read_csv(DATA_FILE)

    assert not dataframe.empty, "Feature data file is empty."

    return dataframe


# ---------------------------------------------------------
# Test 1: Feature data can be loaded
# ---------------------------------------------------------

def test_feature_data_loads():
    """
    Verify that the traffic feature dataset exists and
    contains records.
    """

    dataframe = load_test_data()

    assert isinstance(dataframe, pd.DataFrame)
    assert len(dataframe) > 0


# ---------------------------------------------------------
# Test 2: Required Rule Engine fields exist
# ---------------------------------------------------------

def test_required_rule_fields_exist():
    """
    Verify that the feature dataset contains the fields
    required by the Rule Engine.
    """

    dataframe = load_test_data()

    required_columns = [
        "packets_per_second",
    ]

    for column in required_columns:
        assert column in dataframe.columns, (
            f"Required column '{column}' is missing."
        )


# ---------------------------------------------------------
# Test 3: analyze_flow() works with a real feature row
# ---------------------------------------------------------

def test_analyze_flow_returns_result():
    """
    Verify that analyze_flow() can process a real traffic
    feature row from the project dataset.
    """

    dataframe = load_test_data()

    row = dataframe.iloc[0]

    result = analyze_flow(row)

    assert result is not None


# ---------------------------------------------------------
# Test 4: analyze_flow() returns a usable structure
# ---------------------------------------------------------

def test_analyze_flow_result_type():
    """
    Verify that analyze_flow() returns a dictionary or
    pandas Series containing the analysis result.
    """

    dataframe = load_test_data()

    row = dataframe.iloc[0]

    result = analyze_flow(row)

    assert isinstance(result, (dict, pd.Series))


# ---------------------------------------------------------
# Test 5: apply_rules() works with a DataFrame
# ---------------------------------------------------------

def test_apply_rules_returns_dataframe():
    """
    Verify that apply_rules() accepts a DataFrame and
    returns processed rule-detection results.
    """

    dataframe = load_test_data()

    # Use a small sample for the unit test
    test_dataframe = dataframe.head(10).copy()

    result = apply_rules(test_dataframe)

    assert isinstance(result, pd.DataFrame)
    assert len(result) == len(test_dataframe)


# ---------------------------------------------------------
# Test 6: Rule results contain expected detection data
# ---------------------------------------------------------

def test_rule_results_contain_detection_columns():
    """
    Verify that the Rule Engine produces classification
    and risk-score information.
    """

    dataframe = load_test_data()

    test_dataframe = dataframe.head(10).copy()

    result = apply_rules(test_dataframe)

    assert isinstance(result, pd.DataFrame)

    assert "rule_classification" in result.columns
    assert "rule_risk_score" in result.columns


# ---------------------------------------------------------
# Test 7: Risk scores are valid
# ---------------------------------------------------------

def test_rule_risk_scores_are_valid():
    """
    Verify that Rule Engine risk scores remain within
    the expected 0-100 range.
    """

    dataframe = load_test_data()

    test_dataframe = dataframe.head(10).copy()

    result = apply_rules(test_dataframe)

    assert result["rule_risk_score"].min() >= 0
    assert result["rule_risk_score"].max() <= 100


# ---------------------------------------------------------
# Manual execution
# ---------------------------------------------------------

if __name__ == "__main__":

    print("========================================")
    print("       RULE ENGINE TESTS")
    print("========================================")

    test_feature_data_loads()
    print("[PASS] Feature data loading")

    test_required_rule_fields_exist()
    print("[PASS] Required Rule Engine fields")

    test_analyze_flow_returns_result()
    print("[PASS] analyze_flow() execution")

    test_analyze_flow_result_type()
    print("[PASS] analyze_flow() result type")

    test_apply_rules_returns_dataframe()
    print("[PASS] apply_rules() execution")

    test_rule_results_contain_detection_columns()
    print("[PASS] Rule detection columns")

    test_rule_risk_scores_are_valid()
    print("[PASS] Rule risk score validation")

    print()
    print("All Rule Engine tests passed successfully.")