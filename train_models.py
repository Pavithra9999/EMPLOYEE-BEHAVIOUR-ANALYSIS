import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder
import joblib

# Set random seed for reproducibility
np.random.seed(42)

# Generate synthetic network traffic data
def generate_data(num_records, num_anomalies):
    data = pd.DataFrame({
        'employee_id': np.random.randint(1, 100, size=num_records),
        'src_ip': np.random.choice(['192.168.1.1', '192.168.1.2', '192.168.1.3'], size=num_records),
        'dest_ip': np.random.choice(['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'], size=num_records),
        'src_port': np.random.randint(1024, 65535, size=num_records),
        'dest_port': np.random.randint(80, 443, size=num_records),
        'timestamp': pd.date_range(start='2023-01-01', periods=num_records, freq='T'),
        'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], size=num_records),
        'packet_length': np.random.randint(50, 1500, size=num_records)
    })

    # Insert anomalies by altering some of the normal records
    anomalies = data.sample(n=num_anomalies)
    anomalies['dest_ip'] = '255.255.255.255'  # Unusual IP address as an anomaly
    anomalies['packet_length'] = 5000  # Unusually large packet size

    # Combine normal data with anomalies
    data = pd.concat([data, anomalies])

    return data

# Generate the dataset
num_records = 5000
num_anomalies = 50
data = generate_data(num_records, num_anomalies)

# Split the data into training and testing datasets
train_data, test_data = train_test_split(data, test_size=0.3, random_state=42)

# Preprocessing
features = ['employee_id', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'packet_length']
encoder = OneHotEncoder(handle_unknown='ignore')

# Fit encoder and transform data
X_train = encoder.fit_transform(train_data[features])
X_test = encoder.transform(test_data[features])

# Train Isolation Forest model
model = IsolationForest(contamination=float(num_anomalies) / num_records, random_state=42)
model.fit(X_train)

# Save the model and encoder
joblib.dump(model, 'isolation_forest_model.pkl')
joblib.dump(encoder, 'onehot_encoder.pkl')

print(f"Training data: {train_data.shape[0]} records")
print(f"Testing data: {test_data.shape[0]} records")
