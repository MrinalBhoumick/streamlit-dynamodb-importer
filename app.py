import streamlit as st
import pandas as pd
import boto3
import io

# Constants
ROLE_ARNS = {
    "CWM Q": "arn:aws:iam::207567766326:role/Workmates-SSO-L2SupportRole",
    "Cert-In": "arn:aws:iam::412381762776:role/Workmates-SSO-L2SupportRole"
}
REGION = "ap-south-1"

TABLE_SCHEMAS = {
    "CWM-Account-Details-Table": {
        "AccountId": str,
        "AccountName": str,
        "CustomerEmailIds": str,
        "TeamEmailIds": str,
        "TeamId": str,
        "TeamName": str
    },
    "CWM-Team-Details-Table": {
        "TeamName": str,
        "TeamsURL": str
    }
} 

PRIMARY_KEYS = {
    "CWM-Account-Details-Table": "AccountId",
    "CWM-Team-Details-Table": "TeamName"
}


@st.cache_resource
def assume_role_session(role_arn):
    """Assume a role and return a boto3 session."""
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="StreamlitUploaderSession"
    )
    credentials = response['Credentials']
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=REGION
    )


def validate_and_prepare_data(df, schema, table_name):
    """Validate DataFrame against schema and transform data."""
    errors = []
    cleaned_items = []

    for i, row in df.iterrows():
        item = {}
        for col, expected_type in schema.items():
            if col not in row or pd.isna(row[col]):
                errors.append(f"Row {i+2}: Missing value for required column '{col}'")
                continue

            value = row[col]

            if expected_type == str and not isinstance(value, str):
                value = str(value)

            if expected_type == str and col == "TeamEmailIds":
                value = [email.strip() for email in str(value).split(",") if email.strip()]
                if not all(isinstance(email, str) for email in value):
                    errors.append(f"Row {i+2}: Invalid emails in 'TeamEmailIds'")

            item[col] = value

        if len(item) == len(schema):
            cleaned_items.append(item)

    return cleaned_items, errors


def get_existing_keys(session, table_name, key_name):
    """Fetch all existing primary key values from the table."""
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table(table_name)

    existing_keys = set()
    scan_kwargs = {
        "ProjectionExpression": key_name
    }

    done = False
    start_key = None
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])
        for item in items:
            existing_keys.add(item[key_name])
        start_key = response.get('LastEvaluatedKey', None)
        done = start_key is None

    return existing_keys


def upload_to_dynamodb(session, table_name, items):
    """Upload new (non-duplicate) items to DynamoDB."""
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table(table_name)
    for item in items:
        table.put_item(Item=item)


def main():
    st.title("📊 Excel to DynamoDB Uploader with Validation & Duplicate Detection")
    
    st.markdown("""
    This application allows you to securely upload and insert Excel data into a DynamoDB table.

    **Key Features:**

    - 🔍 **Dynamic Table Selection**: Choose from supported DynamoDB tables configured with specific schema requirements.
    - ✅ **Schema Validation**: Ensures your uploaded Excel file contains all required columns and matches expected data types.
    - 🚫 **Duplicate Prevention**: Checks for existing records based on table's primary key(s) and prevents re-uploading the same items.
    - 📄 **Detailed Feedback**: Displays validation issues and already existing entries before performing the upload.
    - 🔐 **Secure Uploads**: Uses role-based access with AWS STS to ensure secure and scoped access to DynamoDB.

    Simply upload your Excel file, validate the data, and upload clean entries to DynamoDB with confidence.
    """)
    # Account selection
    account_choice = st.selectbox("Choose AWS Account", list(ROLE_ARNS.keys()))
    role_arn = ROLE_ARNS[account_choice]
    
    table_choice = st.selectbox("Choose DynamoDB Table", list(TABLE_SCHEMAS.keys()))
    schema = TABLE_SCHEMAS[table_choice]
    primary_key = PRIMARY_KEYS[table_choice]
    st.markdown(f"**Required Columns:** `{list(schema.keys())}`")

    uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])
    if uploaded_file:
        try:
            df = pd.read_excel(uploaded_file)
            st.success("Excel file uploaded successfully!")
            st.dataframe(df)

            if st.button("Validate and Upload"):
                with st.spinner("Validating..."):
                    items, validation_errors = validate_and_prepare_data(df, schema, table_choice)

                if validation_errors:
                    st.error("❌ Validation Failed!")
                    for err in validation_errors:
                        st.warning(err)
                    return

                with st.spinner("Checking for duplicates in DynamoDB..."):
                    session = assume_role_session(role_arn)
                    existing_keys = get_existing_keys(session, table_choice, primary_key)

                    new_items = []
                    duplicates = []

                    for item in items:
                        key = item[primary_key]
                        if key in existing_keys:
                            duplicates.append(item)
                        else:
                            new_items.append(item)

                if duplicates:
                    st.warning(f"⚠️ {len(duplicates)} item(s) already exist in `{table_choice}`:")
                    st.dataframe(pd.DataFrame(duplicates))

                if new_items:
                    with st.spinner("Uploading new items to DynamoDB..."):
                        upload_to_dynamodb(session, table_choice, new_items)
                    st.success(f"✅ Successfully uploaded {len(new_items)} new item(s) to `{table_choice}`.")
                else:
                    st.info("ℹ️ No new items to upload.")

        except Exception as e:
            st.error(f"❌ Error reading or uploading file: {e}")


if __name__ == "__main__":
    main()
